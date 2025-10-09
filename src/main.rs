// TODO read path from stdin?? (echo "C:/Directory/" | sg "todo|fixme" -i)
//
// TODO only list the file extensions in the given directory and count the number of files
// TODO     e.g. 'sg . . --only-extensions' would only count what file extensions are in
// TODO     the current directory and count how many files with what extension
use std::{
    ffi::OsStr,
    fs,
    io::{self, BufWriter, Stdout, Write},
    os::windows::fs::MetadataExt,
    path::{self, Path, PathBuf},
    process,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::Instant,
};

use clap::{Arg, ArgAction, ArgMatches, Command};
use colored::Colorize;
use flexi_logger::{detailed_format, Duplicate, FileSpec, Logger};
use log::{error, info, warn};
use rayon::prelude::*;
use regex::{Match, Regex, RegexBuilder, RegexSet};
use walkdir::{DirEntry, WalkDir};

// TODO reduce buffer size for quicker user feedback of found files??
const BUFFER_CAPACITY: usize = 64 * (1 << 10); // 64 KB

// TODO add other useful pre-filters
const COMMON_PRE_FILTERS: &[&str] = &[
    r"\.js$",         // javascript file
    r"\.js.map$",     // javascript source map
    r"index\..*\.js", // javascript index file
];

fn main() {
    // INFO don`t lock stdout, otherwise unable to handle ctrl-c
    let handle = Arc::new(Mutex::new(BufWriter::with_capacity(
        BUFFER_CAPACITY,
        io::stdout(),
    )));

    // handle Ctrl+C
    ctrlc::set_handler(move || {
        println!("{}", "Received Ctrl-C!".italic());
        process::exit(0)
    })
    .expect("Error setting Ctrl-C handler");

    // initialize the logger
    let config_dir = check_create_config_dir().unwrap_or_else(|err| {
        error!("Unable to find or create a config directory: {err}");
        process::exit(1);
    });
    init_logger(&config_dir);

    // handle arguments
    let matches = sg().get_matches();
    let case_insensitive_flag = matches.get_flag("case-insensitive");
    let common_flag = matches.get_flag("common");
    let count_flag = matches.get_flag("count");
    let dir_flag = matches.get_flag("dir");
    let file_flag = matches.get_flag("file");
    let link_flag = matches.get_flag("link");
    let only_filepaths_flag = matches.get_flag("only-filepaths");
    let hidden_flag = matches.get_flag("hidden");
    let raw_flag = matches.get_flag("raw");
    let show_errors_flag = matches.get_flag("show-errors");
    let stats_flag = matches.get_flag("stats");
    let unicode_flag = matches.get_flag("no_unicode");

    let depth_flag = set_search_depth(&matches);

    if let Some(args) = matches
        .get_many::<String>("args")
        .map(|a| a.collect::<Vec<_>>())
    {
        // don't accept emtpy strings like "" (or in powershell `"`")
        if args[0].is_empty() {
            let err = sg().error(
                clap::error::ErrorKind::MissingRequiredArgument,
                "value required for '[REGEX]', none provided",
            );
            warn!("{}", err);
            process::exit(0);
        }

        // get search pattern from arguments -> build regex
        let reg = build_regex(args[0].as_str(), case_insensitive_flag, unicode_flag);

        // get search path from arguments
        let mut path = Path::new(&args[1]).to_path_buf();

        if !path.is_absolute() {
            path = path::absolute(path).unwrap_or_else(|err| {
                error!(
                    "{}",
                    format!("Unable to convert {} to absolute path: {}", &args[1], err)
                );
                process::exit(0);
            })
        }

        // get possible file extensions for filtering
        let extensions: Vec<String> = matches
            .get_many::<String>("extensions")
            .map(|a| a.cloned().collect::<Vec<_>>())
            .unwrap_or_default();

        // get exclude patterns
        let exclude_patterns: Vec<String> = matches
            .get_many::<String>("exclude")
            .map(|a| a.cloned().collect::<Vec<_>>())
            .unwrap_or_default();

        // store exclude patterns in regex set
        let excludes = build_excludes_regex(exclude_patterns, common_flag).unwrap_or_else(|err| {
            error!("Unable to get regex pattern: {err}");
            process::exit(1);
        });

        // handle grep flag
        let greps: String = matches
            .get_one::<String>("grep")
            .unwrap_or(&String::new())
            .to_string();

        let grep_reg = build_regex(&greps, case_insensitive_flag, unicode_flag);

        let start = Instant::now();
        let entry_count = Arc::new(AtomicUsize::new(0));
        let error_count = Arc::new(AtomicUsize::new(0));
        let search_hits = Arc::new(AtomicUsize::new(0));
        let grep_files = Arc::new(AtomicUsize::new(0));
        let grep_patterns = Arc::new(AtomicUsize::new(0));

        let entries = collect_entries(path, depth_flag, hidden_flag);

        entries
            .filter_map(|entry| match entry {
                Ok(entry) => Some(entry),
                Err(err) => {
                    error_count.fetch_add(1, Ordering::Relaxed);

                    if show_errors_flag {
                        show_walk_errors(&err);
                    }

                    None
                }
            })
            .filter(|entry| extension_filter(entry, &extensions))
            .filter(|entry| {
                let name = entry.file_name();
                !excludes.is_match(&name.to_string_lossy())
            })
            .filter(|entry| filetype_filter(entry, &grep_reg, file_flag, dir_flag))
            // INFO filter first to reduce memory overhead when using rayon
            .par_bridge()
            .for_each(|entry| {
                // all pre-filters (set via flags) are checked -> start counting entries
                entry_count.fetch_add(1, Ordering::Relaxed);

                let mut fileobject = FileObject::new(&entry);

                // search for a pattern match (regex) in the remaining entries
                let name = fileobject.name();
                let captures: Vec<_> = reg.find_iter(&name).collect();
                if !captures.is_empty() {
                    search_hits.fetch_add(1, Ordering::Relaxed);

                    // if grep_flag is set -> search for pattern matches (regex) in files
                    if !grep_reg.as_str().is_empty() {
                        // TODO handle non-UTF8 data???
                        let content = match fs::read_to_string(&fileobject.path) {
                            Ok(s) => s,
                            Err(err) => {
                                error_count.fetch_add(1, Ordering::Relaxed);

                                if show_errors_flag {
                                    show_content_errors(&entry, &err);
                                }

                                return;
                            }
                        };

                        if grep_reg.is_match(&content) {
                            grep_files.fetch_add(1, Ordering::Relaxed);

                            if !only_filepaths_flag {
                                let mut linenumber = 0;
                                for line in content.lines() {
                                    linenumber += 1;
                                    // remove leading & trailing whitespace (including newlines)
                                    let line = line.trim();
                                    let grep_captures: Vec<_> = grep_reg.find_iter(&line).collect();

                                    if !grep_captures.is_empty() {
                                        grep_patterns
                                            .fetch_add(grep_captures.len(), Ordering::Relaxed);

                                        if raw_flag {
                                            let line_match =
                                                LineMatch::new(linenumber, line.to_string());
                                            fileobject.add_matching_line(line_match);
                                        } else {
                                            let highlighted_line =
                                                highlight_capture(&line, &grep_captures, true);

                                            let line_match =
                                                LineMatch::new(linenumber, highlighted_line);
                                            fileobject.add_matching_line(line_match);
                                        }
                                    }
                                }
                            }

                            if !count_flag {
                                fileobject.show(
                                    &handle,
                                    &captures,
                                    link_flag,
                                    only_filepaths_flag,
                                    raw_flag,
                                );
                            }
                        }
                    } else {
                        if !count_flag {
                            fileobject.show(
                                &handle,
                                &captures,
                                link_flag,
                                only_filepaths_flag,
                                raw_flag,
                            );
                        }
                    }
                }
            });

        // empty bufwriter
        handle.lock().unwrap().flush().unwrap_or_else(|err| {
            error!("Error flushing stdout buffer: {err}");
            process::exit(1)
        });

        let counters = unpack_search_counters(
            grep_reg,
            grep_files,
            grep_patterns,
            only_filepaths_flag,
            search_hits,
        );

        if count_flag && !stats_flag {
            println!("{}", counters);
        } else if stats_flag {
            let colorized_hits = colorize_hits(counters);

            println!(
                "[{}  {} {} {}]",
                format!("{:?}", start.elapsed()).truecolor(95, 134, 217),
                entry_count.load(Ordering::Relaxed).to_string().dimmed(),
                error_count
                    .load(Ordering::Relaxed)
                    .to_string()
                    .truecolor(217, 83, 96),
                colorized_hits
            );
        }
    } else if matches.get_flag("list-common") {
        for filter in COMMON_PRE_FILTERS {
            println!("{filter}");
        }
    } else if let Some(_) = matches.subcommand_matches("log") {
        show_logs(&config_dir);
    } else if let Some(_) = matches.subcommand_matches("examples") {
        examples();
    } else if let Some(_) = matches.subcommand_matches("syntax") {
        show_regex_syntax();
    } else {
        sg().print_help().unwrap();
        process::exit(0);
    }
}

#[derive(Clone)]
struct LineMatch {
    linenumber: u32,
    oneliner: String,
}

struct FileObject {
    // I needed a name, don`t sue me
    // reference: https://en.wikipedia.org/wiki/Qwirkle
    name: String,
    parent: String,
    path: String,
    matching_lines: Option<Vec<LineMatch>>,
}

impl LineMatch {
    fn new(linenumber: u32, oneliner: String) -> Self {
        Self {
            linenumber,
            oneliner,
        }
    }

    fn merge(&self, raw_flag: bool) -> String {
        if raw_flag {
            format!(" {}: {}", self.linenumber, self.oneliner)
        } else {
            format!(
                " {}: {}",
                self.linenumber.to_string().truecolor(217, 83, 96),
                self.oneliner
            )
        }
    }
}

impl FileObject {
    fn new(entry: &DirEntry) -> Self {
        let name = entry.file_name().to_string_lossy().to_string();
        let parent = get_parent_path(entry.clone());
        let path = format!("{}/{}", parent, name);
        let matching_lines = None;

        Self {
            name,
            parent,
            path,
            matching_lines,
        }
    }

    fn name(&self) -> String {
        self.name.clone()
    }

    fn add_matching_line(&mut self, line_match: LineMatch) {
        self.matching_lines
            .get_or_insert_with(Vec::new)
            .push(line_match);
    }

    fn show(
        self,
        handle: &Arc<Mutex<BufWriter<Stdout>>>,
        captures: &Vec<Match>,
        link_flag: bool,
        only_filepaths_flag: bool,
        raw_flag: bool,
    ) {
        let mut matches: Vec<String> = Vec::new();

        if raw_flag {
            matches.push(self.path);
        } else {
            let name = highlight_capture(&self.name, captures, false);
            // make file clickable on windows by adding 'file://'
            // TODO checkout 'url' crate (https://github.com/servo/rust-url) to replace 'file://'
            // TODO check if terminal accepts clickable paths
            let path = if link_flag {
                format!("file://{}/{}", self.parent, &name)
            } else {
                format!("{}/{}", self.parent, &name)
            };
            matches.push(path);
        }

        if let Some(lines) = self.matching_lines {
            if !only_filepaths_flag {
                let mut lines: Vec<String> = lines
                    .iter()
                    .map(|line| {
                        // INFO order of elements will not change when using map()
                        line.merge(raw_flag)
                    })
                    .collect();

                matches.append(&mut lines);
                matches.push("".to_string());
            }
        }

        write_stdout(handle, matches);
    }
}

fn set_search_depth(matches: &ArgMatches) -> u32 {
    if let Some(d) = matches.get_one::<String>("depth") {
        match d.parse() {
            Ok(depth) => return depth,
            Err(err) => {
                warn!("Expected an integer for the search depth: {err}");
                process::exit(0);
            }
        }
    } else {
        // default search depth is 1000000
        return 1000000;
    }
}

fn build_excludes_regex(
    exclude_patterns: Vec<String>,
    common_flag: bool,
) -> Result<RegexSet, regex::Error> {
    let all_excludes: Vec<String> = if common_flag {
        COMMON_PRE_FILTERS
            .iter()
            .map(|&s| s.to_string())
            .chain(exclude_patterns.into_iter())
            .collect()
    } else {
        exclude_patterns
    };

    RegexSet::new(all_excludes)
}

fn build_regex(patterns: &str, case_insensitive_flag: bool, unicode_flag: bool) -> Regex {
    let reg = RegexBuilder::new(patterns)
        .case_insensitive(case_insensitive_flag)
        .unicode(unicode_flag)
        .build()
        .unwrap_or_else(|err| {
            error!("Unable to get regex pattern: {err}");
            process::exit(1);
        });

    reg
}

fn collect_entries(
    path: PathBuf,
    depth_flag: u32,
    hidden_flag: bool,
) -> impl Iterator<Item = Result<DirEntry, walkdir::Error>> {
    WalkDir::new(path)
        .max_depth(depth_flag as usize) // set maximum search depth
        .into_iter()
        // filter hidden entries by default
        .filter_entry(move |entry| filter_hidden(entry, hidden_flag))
}

fn get_parent_path(entry: DirEntry) -> String {
    assert!(entry.path().is_absolute());

    entry
        .path()
        .parent()
        .unwrap_or_else(|| Path::new(""))
        .to_string_lossy()
        .to_string()
        .replace("\\", "/")
}

fn write_stdout(handle: &Arc<Mutex<BufWriter<Stdout>>>, content: Vec<String>) {
    let mut handle_lock = handle.lock().unwrap_or_else(|err| {
        // if the Mutex is poisoned, something severely wrong happened with a previous thread
        error!("Mutex poisoned while locking stdout handle: {err}");
        process::exit(0);
    });

    for line in content {
        if let Err(err) = handle_lock.write_all(line.as_bytes()) {
            error!("Error writing to stdout: {err}");
            process::exit(0);
        }

        if let Err(err) = handle_lock.write_all(b"\n") {
            error!("Error writing newline to stdout: {err}");
            process::exit(0);
        }
    }

    // TODO this would slow down the performance significantly when processing a lot to stdout,
    // TODO but would provide quicker feedback to user
    // if let Err(err) = handle_lock.flush() {
    //     error!("Error flushing stdout buffer: {err}");
    //     // we do not exit here, as the content might have been mostly written
    // }
}

fn highlight_capture(content: &str, captures: &Vec<Match>, grep: bool) -> String {
    assert!(!captures.is_empty());

    // pre-allocate enough memory for original content + estimated additional space
    // for ANSI codes (est. each color adds ~20 bytes)
    // this reduces the number of times the string's buffer needs to be reallocated as elements are added
    let mut new = String::with_capacity(content.len() + captures.len() * 20);

    let mut last_match = 0;
    for cap in captures {
        new.push_str(&content[last_match..cap.start()]);

        let pattern = if grep {
            cap.as_str().truecolor(240, 215, 117).to_string()
        } else {
            cap.as_str().truecolor(59, 179, 140).to_string()
        };
        new.push_str(&pattern);

        last_match = cap.end();
    }
    new.push_str(&content[last_match..]);

    new
}

// check entries if hidden and compare to hidden flag
fn filter_hidden(entry: &DirEntry, hidden_flag: bool) -> bool {
    if !hidden_flag && is_hidden(&entry).unwrap_or(false) {
        return false;
    }

    true
}

fn is_hidden(entry: &DirEntry) -> std::io::Result<bool> {
    // INFO also count everything that starts with "." on windows as hidden -> this is intentional
    Ok((entry.metadata()?.file_attributes() & 0x2) > 0
        || entry.file_name().to_string_lossy().starts_with('.'))
}

fn filetype_filter(entry: &DirEntry, grep_reg: &Regex, file_flag: bool, dir_flag: bool) -> bool {
    if file_flag && !entry.file_type().is_file() {
        return false;
    }

    if dir_flag && !entry.file_type().is_dir() {
        return false;
    }

    // skip entry if grep flag is set and entry not file
    if !grep_reg.as_str().is_empty() && !entry.file_type().is_file() {
        return false;
    }

    true
}

fn extension_filter(entry: &DirEntry, extensions: &Vec<String>) -> bool {
    if !extensions.is_empty()
        && !extensions.iter().any(|ex| {
            entry
                .path()
                .extension()
                .unwrap_or(&OsStr::new(""))
                .to_string_lossy()
                .to_string()
                == *ex
        })
    {
        return false;
    }

    true
}

// FIXME slows down performance -> no bufwriter (extra bufwriter just for errors??)
fn show_walk_errors(err: &walkdir::Error) {
    let path = err.path().unwrap_or(Path::new("")).display();
    if let Some(inner) = err.io_error() {
        match inner.kind() {
            io::ErrorKind::InvalidData => {
                info!("Entry \'{}\' contains invalid data: {}", path, inner)
            }
            io::ErrorKind::NotFound => {
                info!("Entry \'{}\' not found: {}", path, inner);
            }
            io::ErrorKind::PermissionDenied => {
                warn!("Missing permission to read entry \'{}\': {}", path, inner)
            }
            _ => {
                error!(
                    "Failed to access entry: \'{}\'\nUnexpected error occurred: {}",
                    path, inner
                )
            }
        }
    }
}

// FIXME slows down performance -> no bufwriter (extra bufwriter just for errors??)
fn show_content_errors(path: &DirEntry, err: &io::Error) {
    let path = path.path().display();
    match err.kind() {
        io::ErrorKind::InvalidData => {
            info!("Entry \'{}\' contains invalid data: {}", path, err)
        }
        io::ErrorKind::NotFound => {
            info!("Entry \'{}\' not found: {}", path, err);
        }
        io::ErrorKind::PermissionDenied => {
            warn!("Missing permission to read entry \'{}\': {}", path, err)
        }
        _ => {
            error!(
                "Failed to access entry: \'{}\'\nUnexpected error occurred: {}",
                path, err
            )
        }
    }
}

fn unpack_search_counters(
    grep_reg: Regex,
    grep_files: Arc<AtomicUsize>,
    grep_patterns: Arc<AtomicUsize>,
    only_filepaths_flag: bool,
    search_hits: Arc<AtomicUsize>,
) -> String {
    // format found search hits based on whether grep flag was set or not
    // if grep flag was set, it shows:
    //     - for found files containing matches inside the file
    //         (shows only this number when only_filepaths_flag was set)
    //     - for number of found matches (inside of files) overall
    // if the grep flag was not set it shows one number: the number of found files
    // containing a match inside the filename
    let counters = if !grep_reg.as_str().is_empty() {
        if only_filepaths_flag {
            grep_files.load(Ordering::Relaxed).to_string()
        } else {
            format!(
                "{} {}",
                grep_files.load(Ordering::Relaxed).to_string(),
                grep_patterns.load(Ordering::Relaxed).to_string(),
            )
        }
    } else {
        search_hits.load(Ordering::Relaxed).to_string()
    };

    counters
}

fn colorize_hits(hits: String) -> String {
    // check if hits contain one or two numbers and colourize accordingly
    let hits: Vec<_> = hits.split_whitespace().collect();
    let colorized_hits = if hits.len() <= 1 {
        format!("{}", hits[0].truecolor(59, 179, 140))
    } else {
        format!(
            "{} {}",
            hits[0].truecolor(59, 179, 140),
            hits[1].truecolor(240, 215, 117)
        )
    };

    colorized_hits
}

fn check_create_config_dir() -> io::Result<PathBuf> {
    let mut new_dir = PathBuf::new();
    match dirs::config_dir() {
        Some(config_dir) => {
            new_dir.push(config_dir);
            new_dir.push("sg");
            if !new_dir.as_path().exists() {
                fs::create_dir(&new_dir)?;
            }
        }
        None => {
            error!("Unable to find config directory");
        }
    }

    Ok(new_dir)
}

fn init_logger(config_dir: &PathBuf) {
    let _logger = Logger::try_with_str("info") // log info, warn and error
        .unwrap()
        .format_for_files(detailed_format) // use timestamp for every log
        .log_to_file(
            FileSpec::default()
                .directory(&config_dir)
                .suppress_timestamp(),
        ) // change directory for logs, no timestamps in the filename
        .append() // use only one logfile
        .duplicate_to_stderr(Duplicate::Info) // print infos, warnings and errors also to the console
        .start()
        .unwrap();
}

fn show_log_file(config_dir: &PathBuf) -> io::Result<String> {
    let log_path = Path::new(&config_dir).join("sg.log");
    match log_path.try_exists()? {
        true => {
            return Ok(format!(
                "{} {}\n{}",
                "Log location:".italic().dimmed(),
                &log_path.display(),
                fs::read_to_string(&log_path)?
            ));
        }
        false => {
            return Ok(format!(
                "{} {}",
                "No log file found:"
                    .truecolor(217, 83, 96)
                    .bold()
                    .to_string(),
                log_path.display()
            ))
        }
    }
}

fn show_logs(config_dir: &PathBuf) {
    if let Ok(logs) = show_log_file(&config_dir) {
        println!("{}", "Available logs:".bold().yellow());
        println!("{}", logs);
    } else {
        error!("Unable to read logs");
        process::exit(1);
    }
}

// TODO add more examples
fn examples() {
    println!("\n{}\n----------", "Example 1".bold());
    println!(
        r###"
- list everything in the current directory 

$ sg . . 
    "###
    );

    println!("\n{}\n----------", "Example 2".bold());
    println!(
        r###"
- find all python or rust files in the 'src' directory that contain the word 'main' or 'init' in their filename 

$ sg "main|init" .\src\ -e rs py 
    "###
    );

    println!("\n{}\n----------", "Example 3".bold());
    println!(
        r###"
- find all files in the current directory that contain the words 'fixme' or 'todo'
- search case insensitively 

$ sg . . -g "todo|fixme" -i 
    "###
    );

    println!("\n{}\n----------", "Example 4".bold());
    println!(
        r###"
- count all txt-files in the 'document' directory

$ sg . .\Documents -e txt -c
    "###
    );

    println!("\n{}\n----------", "Example 5".bold());
    println!(
        r###"
- search e-mails (e.g.: leann.phydon@gmail.com) in files

$ sg . . -g "[\w\d]*\.*[\w\d]+@[\w]+\.[\w]+"
    "###
    );
}

fn show_regex_syntax() {
    println!("{}", "Regex Syntax".bold().blue());
    println!(
        "More information on '{}'",
        "https://docs.rs/regex/latest/regex/#syntax".italic()
    );
    println!("\n{}", "Matching one character:".bold());
    println!(
        r###"
.             any character except new line (includes new line with s flag)
[0-9]         any ASCII digit
\d            digit (\p{{Nd}})
\D            not digit
\pX           Unicode character class identified by a one-letter name
\p{{Greek}}     Unicode character class (general category or script)
\PX           Negated Unicode character class identified by a one-letter name
\P{{Greek}}     negated Unicode character class (general category or script)
        "###
    );
    println!("\n{}", "Character classes:".bold());
    println!(
        r###"
[xyz]         A character class matching either x, y or z (union).
[^xyz]        A character class matching any character except x, y and z.
[a-z]         A character class matching any character in range a-z.
[[:alpha:]]   ASCII character class ([A-Za-z])
[[:^alpha:]]  Negated ASCII character class ([^A-Za-z])
[x[^xyz]]     Nested/grouping character class (matching any character except y and z)
[a-y&&xyz]    Intersection (matching x or y)
[0-9&&[^4]]   Subtraction using intersection and negation (matching 0-9 except 4)
[0-9--4]      Direct subtraction (matching 0-9 except 4)
[a-g~~b-h]    Symmetric difference (matching `a` and `h` only)
[\[\]]        Escaping in character classes (matching [ or ])
[a&&b]        An empty character class matching nothing        
        "###
    );
    println!("\n{}", "Composites:".bold());
    println!(
        r###"
xy    concatenation (x followed by y)
x|y   alternation (x or y, prefer x)
        "###
    );
    println!("\n{}", "Repetitions:".bold());
    println!(
        r###"
x*        zero or more of x (greedy)
x+        one or more of x (greedy)
x?        zero or one of x (greedy)
x*?       zero or more of x (ungreedy/lazy)
x+?       one or more of x (ungreedy/lazy)
x??       zero or one of x (ungreedy/lazy)
x{{n,m}}    at least n x and at most m x (greedy)
x{{n,}}     at least n x (greedy)
x{{n}}      exactly n x
x{{n,m}}?   at least n x and at most m x (ungreedy/lazy)
x{{n,}}?    at least n x (ungreedy/lazy)
x{{n}}?     exactly n x        
        "###
    );
    println!("\n{}", "Empty matches:".bold());
    println!(
        r###"
^               the beginning of a haystack (or start-of-line with multi-line mode)
$               the end of a haystack (or end-of-line with multi-line mode)
\A              only the beginning of a haystack (even with multi-line mode enabled)
\z              only the end of a haystack (even with multi-line mode enabled)
\b              a Unicode word boundary (\w on one side and \W, \A, or \z on other)
\B              not a Unicode word boundary
\b{{start}}, \<   a Unicode start-of-word boundary (\W|\A on the left, \w on the right)
\b{{end}}, \>     a Unicode end-of-word boundary (\w on the left, \W|\z on the right))
\b{{start-half}}  half of a Unicode start-of-word boundary (\W|\A on the left)
\b{{end-half}}    half of a Unicode end-of-word boundary (\W|\z on the right)        
        "###
    );
    println!("\n{}", "Grouping:".bold());
    println!(
        r###"
(exp)          numbered capture group (indexed by opening parenthesis)
(?P<name>exp)  named (also numbered) capture group (names must be alpha-numeric)
(?<name>exp)   named (also numbered) capture group (names must be alpha-numeric)
(?:exp)        non-capturing group
(?flags)       set flags within current group
(?flags:exp)   set flags for exp (non-capturing)        
        "###
    );
    println!("\n{}", "Flags:".bold());
    println!(
        r###"
i     case-insensitive: letters match both upper and lower case
m     multi-line mode: ^ and $ match begin/end of line
s     allow . to match \n
R     enables CRLF mode: when multi-line mode is enabled, \r\n is used
U     swap the meaning of x* and x*?
u     Unicode support (enabled by default)
x     verbose mode, ignores whitespace and allow line comments (starting with `#`)        
        "###
    );
    println!("\n{}", "Escape sequences:".bold());
    println!(
        r###"
\*              literal *, applies to all ASCII except [0-9A-Za-z<>]
\a              bell (\x07)
\f              form feed (\x0C)
\t              horizontal tab
\n              new line
\r              carriage return
\v              vertical tab (\x0B)
\A              matches at the beginning of a haystack
\z              matches at the end of a haystack
\b              word boundary assertion
\B              negated word boundary assertion
\b{{start}}, \<   start-of-word boundary assertion
\b{{end}}, \>     end-of-word boundary assertion
\b{{start-half}}  half of a start-of-word boundary assertion
\b{{end-half}}    half of a end-of-word boundary assertion
\123            octal character code, up to three digits (when enabled)
\x7F            hex character code (exactly two digits)
\x{{10FFFF}}      any hex character code corresponding to a Unicode code point
\u007F          hex character code (exactly four digits)
\u{{7F}}          any hex character code corresponding to a Unicode code point
\U0000007F      hex character code (exactly eight digits)
\U{{7F}}          any hex character code corresponding to a Unicode code point
\p{{Letter}}      Unicode character class
\P{{Letter}}      negated Unicode character class
\d, \s, \w      Perl character class
\D, \S, \W      negated Perl character class        
        "###
    );
    println!("\n{}", "Perl character classes (unicode friendly):".bold());
    println!(
        r###"
\d     digit (\p{{Nd}})
\D     not digit
\s     whitespace (\p{{White_Space}})
\S     not whitespace
\w     word character (\p{{Alphabetic}} + \p{{M}} + \d + \p{{Pc}} + \p{{Join_Control}})
\W     not word character        
        "###
    );
    println!("\n{}", "ASCII character classes:".bold());
    println!(
        r###"
[[:alnum:]]    alphanumeric ([0-9A-Za-z])
[[:alpha:]]    alphabetic ([A-Za-z])
[[:ascii:]]    ASCII ([\x00-\x7F])
[[:blank:]]    blank ([\t ])
[[:cntrl:]]    control ([\x00-\x1F\x7F])
[[:digit:]]    digits ([0-9])
[[:graph:]]    graphical ([!-~])
[[:lower:]]    lower case ([a-z])
[[:print:]]    printable ([ -~])
[[:punct:]]    punctuation ([!-/:-@\[-`{{}}-~])
[[:space:]]    whitespace ([\t\n\v\f\r ])
[[:upper:]]    upper case ([A-Z])
[[:word:]]     word characters ([0-9A-Za-z_])
[[:xdigit:]]   hex digit ([0-9A-Fa-f])        
        "###
    );
}

// build cli
fn sg() -> Command {
    Command::new("sg")
        .bin_name("sg")
        .before_help(format!(
            "{}\n{}",
            "SIMPLE GREP".bold().truecolor(217, 83, 96),
            "Leann Phydon <leann.phydon@gmail.com>".italic().dimmed()
        ))
        .about("Simple file and pattern search")
        .before_long_help(format!(
            "{}\n{}",
            "SIMPLE GREP".bold().truecolor(217, 83, 96),
            "Leann Phydon <leann.phydon@gmail.com>".italic().dimmed()
        ))
        .long_about(format!("{}\n{}\n", "Simple recursive file and pattern search via regex patterns", "Combine 'find' with 'grep'"))
        // TODO update version
        .version("1.2.3")
        .author("Leann Phydon <leann.phydon@gmail.com>")
        // INFO format for USAGE specified here: https://docs.rs/clap/latest/clap/struct.Command.html#method.override_usage
        .override_usage("sg [REGEX] [PATH] [OPTIONS]\n       \
            sg [COMMAND]")
        .arg_required_else_help(true)
        .arg(
            Arg::new("args")
                .help("Add a search regex and a path for the file search")
                .action(ArgAction::Set)
                .num_args(2)
                .value_names(["REGEX", "PATH"]),
        )
        .arg(
            Arg::new("case-insensitive")
                .short('i')
                .long("case-insensitive")
                .help("Search case insensitively")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("common")
                .short('C')
                .long("common")
                .help("Set common pre-filters")
                .long_help(format!(
                    "{}\n{}\n{}\n{}",
                    "Set common pre-filters",
                    "Exclude some files from the search, that usually pollute the output with hugh amounts of data",
                    "Common examples are source maps, stored in *.js.map files",
                    "They take thousands of lines of pretty code and turn it into only a few lines of ugly code",
                ))
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("count")
                .short('c')
                .long("count")
                .help("Only print the number of search results")
                .long_help(format!(
                    "{}\n{}\n{}\n{}",
                    "Only print the number of search results",
                    "Can be combined with the --stats flag to only show stats",
                    "When used with the --grep flag the first output is the number of files containing at least one match",
                    "The second number is the overall number of matches",
                ))
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("depth")
                .short('D')
                .long("depth")
                .help("Set max search depth")
                .default_value("1000000")
                .action(ArgAction::Set)
                .num_args(1)
                .value_name("NUMBER"),
        )
        .arg(
            Arg::new("dir")
                .short('d')
                .long("dir")
                .visible_aliases(["directory", "directories"])
                .help("Search only in directory names for the given regex")
                .action(ArgAction::SetTrue)
                .conflicts_with("file"),
        )
        .arg(
            Arg::new("extensions")
                .short('e')
                .long("extensions")
                .visible_aliases(["extensions", "ext"])
                .help("Only search in files with the given extensions")
                .long_help(format!(
                    "{}\n{}",
                    "Only search in files with the given extensions",
                    "Must be provided after the regex and the search path"
                ))
                .action(ArgAction::Set)
                .conflicts_with("dir")
                .num_args(1..)
                .value_name("EXTENSIONS"),
        )
        .arg(
            Arg::new("exclude")
                .short('E')
                .long("exclude")
                .help("Exclude regex patterns from the search")
                .long_help(format!(
                    "{}\n{}",
                    "Exclude regex patterns from the search",
                    "Must be provided after the regex and the search path"
                ))
                .action(ArgAction::Set)
                .num_args(1..)
                .value_name("REGEX"),
        )
        .arg(
            Arg::new("file")
                .short('f')
                .long("file")
                .visible_alias("files")
                .help("Search only in filenames for the regex")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("grep")
                .short('g')
                .long("grep")
                .help("Search for specific regex pattern in files")
                .action(ArgAction::Set)
                .num_args(1)
                .conflicts_with("dir")
                .value_name("REGEX"),
        )
        .arg(
            Arg::new("link")
                .short('l')
                .long("link")
                .visible_alias("hyperlink")
                .help("Make filepaths clickable")
                .long_help(format!(
                    "{}\n{}\n{}",
                    "Make filepaths clickable, so that it opens the file or directory with the default tool or program",
                    "Terminal has to accept clickable filepaths",
                    "(Tested with Windows Terminal)",
                ))
                .conflicts_with("raw")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("list-common")
                .long("list-common")
                .help("List all common pre-filters")
                .exclusive(true)
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("hidden")
                .short('H')
                .long("hidden")
                .help("Include hidden files and directories in search")
                .long_help(format!(
                    "{}\n{}\n{}\n{}",
                    "Include hidden files and directories in search",
                    "If a directory is hidden, all its content counts as hidden as well",
                    "Everything starting with '.' counts as hidden as well",
                    "Hidden files and directories are excluded by default",
                ))
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("only-filepaths")
                .short('o')
                .long("only-filepaths")
                .visible_alias("only")
                .help("Only show the files that contain the grep regex pattern, without printing the actual matching lines")
                .long_help(format!(
                    "{}\n{}",
                    "Only show the files that contain the grep regex pattern, without printing the actual matching lines",
                    "Can only be used together with the 'grep' flag",
                ))
                .requires("grep")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("raw")
                .short('r')
                .long("raw")
                .help("Don`t colourize the search output and speed up the output printing")
                .long_help(format!(
                    "{}\n{}\n{}",
                    "Focus on performance",
                    "Don`t colourize the search output",
                    "Print raw filepaths",
                ))
                .action(ArgAction::SetTrue)
        )
        .arg(
            Arg::new("show-errors")
                .long("show-errors")
                .visible_alias("show-error")
                .help("Show possible filesystem warnings and errors")
                .long_help(format!(
                    "{}\n{}",
                    "Show possible filesystem warnings and errors",
                    "For example in case of insufficient permissions or unreadable non-UTF-8 data",
                ))
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("stats")
                .short('s')
                .long("stats")
                .visible_aliases(["statistic", "statistics"])
                .help("Show short search statistics at the end")
                .long_help(format!(
                    "{}\n{}\n{}",
                    "Show short search statistics at the end",
                    "Can be combined with the --count flag to only show stats",
                    "Output: ['elapsed time'  'searched number of files' 'errors' 'file search hits' 'grep hits']",
                ))
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("no_unicode")
                .short('u')
                .long("no-unicode")
                .help("Exclude unicode in search")
                .long_help(format!(
                    "{}\n{}\n{}\n{}",
                    "Disables unicode mode [Default: Enabled]",
                    "With Unicode character classes like \\p{Letter} and \\p{Greek} are available",
                    "Note that if Unicode mode is disabled, then the regex will fail to compile if it could match invalid UTF-8",
                    "More information: https://docs.rs/regex/latest/regex/struct.RegexBuilder.html#method.unicode",
                ))
                .action(ArgAction::SetFalse),
        )
        .subcommand(
            Command::new("examples")
                .short_flag('X')
                .long_flag("examples")
                .visible_aliases(["example", "--example"])
                .about("Show examples"),
        )
        .subcommand(
            Command::new("log")
                .short_flag('L')
                .long_flag("log")
                .about("Show content of the log file"),
        )
        .subcommand(
            Command::new("syntax")
                .short_flag('S')
                .long_flag("syntax")
                .about("Show regex syntax information"),
        )
}
