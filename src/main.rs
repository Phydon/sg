// TODO refactor
// TODO read path from stdin??
use std::{
    env,
    ffi::OsStr,
    fs,
    io::{self, BufWriter, Stdout, Write},
    os::windows::fs::MetadataExt,
    path::{Path, PathBuf},
    process,
    time::Instant,
};

use clap::{Arg, ArgAction, ArgMatches, Command};
use colored::Colorize;
use flexi_logger::{detailed_format, Duplicate, FileSpec, Logger};
use log::{error, warn};
use regex::{Match, Regex, RegexBuilder, RegexSet};
use walkdir::{DirEntry, WalkDir};

const BUFFER_CAPACITY: usize = 64 * (1 << 10); // 64 KB

fn main() {
    // don`t lock stdout, otherwise unable to handle ctrl-c
    let mut handle = BufWriter::with_capacity(BUFFER_CAPACITY, io::stdout());

    // handle Ctrl+C
    ctrlc::set_handler(move || {
        println!("{}", "Received Ctrl-C!".italic());
        process::exit(0)
    })
    .expect("Error setting Ctrl-C handler");

    // get config dir
    let config_dir = check_create_config_dir().unwrap_or_else(|err| {
        error!("Unable to find or create a config directory: {err}");
        process::exit(1);
    });

    // initialize the logger
    let _logger = Logger::try_with_str("info") // log warn and error
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

    // handle arguments
    let matches = sg().get_matches();
    let case_insensitive_flag = matches.get_flag("case-insensitive");
    let count_flag = matches.get_flag("count");
    let dir_flag = matches.get_flag("dir");
    let file_flag = matches.get_flag("file");
    let matching_files_flag = matches.get_flag("matching-files");
    let no_hidden_flag = matches.get_flag("no-hidden");
    let raw_flag = matches.get_flag("raw");
    let show_errors_flag = matches.get_flag("show-errors");
    let stats_flag = matches.get_flag("stats");

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
        let reg = build_regex(args[0].as_str(), case_insensitive_flag);

        // get search path from arguments
        let mut path = Path::new(&args[1]).to_path_buf();

        // accept "." as current directory
        if path.as_path().to_string_lossy().to_string() == "." {
            let current_dir = env::current_dir().unwrap_or_else(|err| {
                error!("Unable to get current directory: {err}");
                process::exit(1);
            });
            path.push(current_dir);
        }

        // get possible file extensions for filtering
        let mut extensions = Vec::new();
        if let Some(mut ext) = matches
            .get_many::<String>("extensions")
            .map(|a| a.collect::<Vec<_>>())
        {
            extensions.append(&mut ext);
        }

        // get exclude patterns
        let mut exclude_patterns = Vec::new();
        if let Some(mut excludes) = matches
            .get_many::<String>("exclude")
            .map(|a| a.collect::<Vec<_>>())
        {
            exclude_patterns.append(&mut excludes);
        }

        // store exclude patterns in regex set
        let excludes = RegexSet::new(exclude_patterns).unwrap_or_else(|err| {
            error!("Unable to get regex pattern: {err}");
            process::exit(1);
        });

        // handle grep flag
        let mut greps = String::new();
        if let Some(grep_pattern) = matches.get_one::<String>("grep") {
            greps.push_str(&grep_pattern);
        }

        let grep_reg = build_regex(&greps, case_insensitive_flag);

        let start = Instant::now();
        let mut entry_count = 0;
        let mut error_count = 0;
        let mut search_hits = 0;
        let mut grep_files = 0;
        let mut grep_patterns = 0;

        for entry in WalkDir::new(path)
            .max_depth(depth_flag as usize) // set maximum search depth
            .into_iter()
            // TODO bottleneck if it has to filter out hidden files
            .filter_entry(|entry| filter_hidden(entry, no_hidden_flag))
        // handle hidden flag
        {
            match entry {
                Ok(entry) => {
                    // handle filetype flags and grep flag
                    // must be outside of function file_check()
                    // else no file will be searched with WalkDir...filter_entry()
                    if !filetype_filter(&entry, &grep_reg, file_flag, dir_flag) {
                        continue;
                    }

                    // handle extensions -> skip entry if entry extension doesn't match any given extension via '--extensions' flag
                    if !extension_filter(&entry, &mut extensions) {
                        continue;
                    }

                    // handle excluded patterns
                    let name = get_filename(&entry);
                    if excludes.is_match(&name) {
                        continue;
                    }

                    // all pre-filters (set via flags) are checked -> start counting entries
                    entry_count += 1;

                    let parent = get_parent_path(entry);
                    let fullpath = format!("{}/{}", parent, name);

                    // search for a pattern match (regex) in the remaining entries
                    let captures: Vec<_> = reg.find_iter(&name).collect();
                    if !captures.is_empty() {
                        search_hits += 1;

                        // if grep_flag is set -> search for pattern matches (regex) in files
                        if !grep_reg.as_str().is_empty() {
                            // TODO show an error here when content unreadable??
                            let content =
                                fs::read_to_string(&fullpath).unwrap_or_else(|_| String::new());

                            if grep_reg.is_match(&content) {
                                grep_files += 1;

                                if !count_flag {
                                    if raw_flag {
                                        // don't use "file://" to make the path clickable in Windows Terminal -> otherwise output can't be piped easily to another program
                                        write_stdout(&mut handle, fullpath);
                                    } else {
                                        let highlighted_name =
                                            highlight_capture(&name, &captures, false);
                                        let highlighted_path = parent + "/" + &highlighted_name;
                                        // TODO check if terminal accepts clickable paths
                                        println!("file://{}", highlighted_path);
                                    }

                                    if !matching_files_flag {
                                        let mut linenumber = 0;
                                        for line in content.lines() {
                                            linenumber += 1;
                                            let line = line.trim(); // remove leading & trailing whitespace (including newlines)
                                            let grep_captures: Vec<_> =
                                                grep_reg.find_iter(&line).collect();

                                            if !grep_captures.is_empty() {
                                                grep_patterns += grep_captures.len();

                                                if raw_flag {
                                                    let line =
                                                        format!("  {}: {}", linenumber, &line);
                                                    write_stdout(&mut handle, line);
                                                } else {
                                                    let highlighted_line = highlight_capture(
                                                        &line,
                                                        &grep_captures,
                                                        true,
                                                    );

                                                    println!(
                                                        "  {}: {}",
                                                        linenumber
                                                            .to_string()
                                                            .truecolor(250, 0, 104),
                                                        &highlighted_line
                                                    );
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        } else {
                            if !count_flag {
                                if raw_flag {
                                    // don't use "file://" to make the path clickable in Windows Terminal -> otherwise output can't be piped easily to another program
                                    write_stdout(&mut handle, fullpath);
                                } else {
                                    let highlighted_name =
                                        highlight_capture(&name, &captures, false);

                                    let highlighted_path = parent + "/" + &highlighted_name;
                                    // TODO check if terminal accepts clickable paths
                                    println!("file://{}", highlighted_path);
                                }
                            }
                        }
                    }
                }
                Err(err) => {
                    error_count += 1;

                    if show_errors_flag {
                        let path = err.path().unwrap_or(Path::new("")).display();
                        if let Some(inner) = err.io_error() {
                            match inner.kind() {
                                io::ErrorKind::InvalidData => {
                                    warn!("Entry \'{}\' contains invalid data: {}", path, inner)
                                }
                                io::ErrorKind::NotFound => {
                                    warn!("Entry \'{}\' not found: {}", path, inner);
                                }
                                io::ErrorKind::PermissionDenied => {
                                    warn!(
                                        "Missing permission to read entry \'{}\': {}",
                                        path, inner
                                    )
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
                }
            }
        }

        // empty bufwriter
        handle.flush().unwrap_or_else(|err| {
            error!("Error flushing writer: {err}");
            process::exit(1)
        });

        // format found search hits based on whether grep flag was set or not
        // if grep flag was set, it shows two numbers:
        //     - for found files containing matches
        //     - for number of found matches overall
        // if not it shows one number: the number of found files containing a match in the filename
        let hits = if !grep_reg.as_str().is_empty() {
            format!("{} {}", grep_files.to_string(), grep_patterns.to_string(),)
        } else {
            search_hits.to_string()
        };

        if count_flag && !stats_flag {
            println!("{}", hits);
        } else if stats_flag {
            // check if hits contain one or two numbers and colourize accordingly
            let hits: Vec<_> = hits.split_whitespace().collect();
            let hits_formated = if hits.len() <= 1 {
                format!("{}", hits[0].truecolor(59, 179, 140))
            } else {
                format!(
                    "{} {}",
                    hits[0].truecolor(59, 179, 140),
                    hits[1].bright_yellow()
                )
            };

            println!(
                "[{}  {} {} {}]",
                format!("{:?}", start.elapsed()).bright_blue(),
                entry_count.to_string().dimmed(),
                error_count.to_string().bright_red(),
                hits_formated
            );
        }
    } else if let Some(_) = matches.subcommand_matches("log") {
        if let Ok(logs) = show_log_file(&config_dir) {
            println!("{}", "Available logs:".bold().yellow());
            println!("{}", logs);
        } else {
            error!("Unable to read logs");
            process::exit(1);
        }
    } else if let Some(_) = matches.subcommand_matches("examples") {
        examples();
    } else if let Some(_) = matches.subcommand_matches("syntax") {
        show_regex_syntax();
    } else {
        unreachable!();
        // sg().print_help();
        // process::exit(0)
    }
}

// build cli
fn sg() -> Command {
    Command::new("sg")
        .bin_name("sg")
        .before_help(format!(
            "{}\n{}",
            "SIMPLE GREP".bold().truecolor(250, 0, 104),
            "Leann Phydon <leann.phydon@gmail.com>".italic().dimmed()
        ))
        .about("Simple file and pattern search")
        .before_long_help(format!(
            "{}\n{}",
            "SIMPLE GREP".bold().truecolor(250, 0, 104),
            "Leann Phydon <leann.phydon@gmail.com>".italic().dimmed()
        ))
        .long_about(format!("{}\n{}\n", "Simple recursive file and pattern search via regex patterns", "Combine 'find' with 'grep'"))
        // TODO update version
        .version("1.0.6")
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
            Arg::new("matching-files")
                .short('m')
                .long("matching-files")
                .visible_alias("matches")
                .help("Only show the relevant files that contain the grep regex pattern, without printing the actual matching lines")
                .long_help(format!(
                    "{}\n{}",
                    "Only show the relevant files that contain the grep regex pattern, without printing the actual matching lines",
                    "Can only be used together with the 'grep' flag",
                ))
                .requires("grep")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("no-hidden")
                .short('H')
                .long("no-hidden")
                .help("Exclude hidden files and directories from search")
                .long_help(format!(
                    "{}\n{}",
                    "Exclude hidden files and directories from search",
                    "If a directory is hidden, all its content will be skiped as well",
                ))
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("raw")
                .short('r')
                .long("raw")
                .help("Don`t colourize the search output and speed up the output printing")
                .long_help(format!(
                    "{}\n{}\n{}\n{}",
                    "Focus on performance",
                    "Don`t colourize the search output",
                    "Write the output via BufWriter",
                    "Print raw filepaths",
                ))
                .action(ArgAction::SetTrue)
        )
        .arg(
            Arg::new("show-errors")
                .long("show-errors")
                .visible_alias("show-error")
                .help("Show possible filesystem errors")
                .long_help(format!(
                    "{}\n{}",
                    "Show possible filesystem errors",
                    "For example for situations such as insufficient permissions",
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
        .subcommand(
            Command::new("examples")
                .long_flag("examples")
                .alias("example")
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

fn build_regex(patterns: &str, case_insensitive_flag: bool) -> Regex {
    let reg = RegexBuilder::new(patterns)
        .case_insensitive(case_insensitive_flag)
        // TODO check if needed
        // .unicode(false)
        .build()
        .unwrap_or_else(|err| {
            error!("Unable to get regex pattern: {err}");
            process::exit(1);
        });

    reg
}

fn get_filename(entry: &DirEntry) -> String {
    entry.file_name().to_string_lossy().to_string()
}

fn get_parent_path(entry: DirEntry) -> String {
    entry
        .path()
        .parent()
        .unwrap_or_else(|| Path::new(""))
        .to_string_lossy()
        .to_string()
        .replace("\\", "/")
}

fn write_stdout(handle: &mut BufWriter<Stdout>, content: String) {
    writeln!(handle, "{}", content).unwrap_or_else(|err| {
        error!("Error writing to stdout: {err}");
        process::exit(1);
    });
}

fn highlight_capture(content: &str, captures: &Vec<Match>, grep: bool) -> String {
    assert!(!captures.is_empty());

    let mut new = String::with_capacity(content.len());
    let mut last_match = 0;
    for cap in captures {
        new.push_str(&content[last_match..cap.start()]);

        // TODO change to fixed colors (don't use standard terminal colours)
        let pattern = if grep {
            cap.as_str().bright_yellow().to_string()
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
fn filter_hidden(entry: &DirEntry, no_hidden_flag: bool) -> bool {
    if no_hidden_flag && is_hidden(&entry.path().to_path_buf()).unwrap_or(false) {
        return false;
    }

    true
}

// TODO bottleneck
fn is_hidden(file_path: &PathBuf) -> std::io::Result<bool> {
    let metadata = fs::metadata(file_path)?;
    let attributes = metadata.file_attributes();

    if (attributes & 0x2) > 0 {
        Ok(true)
    } else {
        Ok(false)
    }
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

fn extension_filter(entry: &DirEntry, extensions: &mut Vec<&String>) -> bool {
    if !extensions.is_empty()
        && !extensions.iter().any(|ex| {
            &entry
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
    println!("\n{}", "Grouping and flags:".bold());
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
    println!("\n{}", "Perl character classes:".bold());
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
                    .truecolor(250, 0, 104)
                    .bold()
                    .to_string(),
                log_path.display()
            ))
        }
    }
}
