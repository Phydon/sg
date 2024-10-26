// TODO implement 'mg' features
use std::{
    env, fs,
    io::{self, Write},
    os::windows::fs::MetadataExt,
    path::{Path, PathBuf},
    process,
    time::Instant,
};

use clap::{Arg, ArgAction, ArgMatches, Command};
use colored::Colorize;
use flexi_logger::{detailed_format, Duplicate, FileSpec, Logger};
use log::{error, warn};
use regex::{Match, RegexBuilder, RegexSet};
use walkdir::{DirEntry, WalkDir};

const BUFFER_CAPACITY: usize = 64 * (1 << 10); // 64 KB

fn main() {
    // don`t lock stdout, otherwise unable to handle ctrl-c
    let mut handle = io::BufWriter::with_capacity(BUFFER_CAPACITY, io::stdout());

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
    let no_hidden_flag = matches.get_flag("no-hidden");
    let raw_flag = matches.get_flag("raw");
    let show_errors_flag = matches.get_flag("show-errors");
    let stats_flag = matches.get_flag("stats");

    let depth_flag = set_search_depth(&matches);

    if let Some(args) = matches
        .get_many::<String>("args")
        .map(|a| a.collect::<Vec<_>>())
    {
        // get search pattern from arguments -> build regex
        let reg = RegexBuilder::new(args[0].as_str())
            .case_insensitive(case_insensitive_flag)
            // TODO check if needed
            // .unicode(false)
            .build()
            .unwrap_or_else(|err| {
                error!("Unable to get regex pattern: {err}");
                process::exit(1);
            });

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
            .get_many::<String>("extension")
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

        let grep_reg = RegexBuilder::new(&greps)
            .case_insensitive(case_insensitive_flag)
            // TODO check if needed
            // .unicode(false)
            .build()
            .unwrap_or_else(|err| {
                error!("Unable to get regex grep pattern: {err}");
                process::exit(1);
            });

        let start = Instant::now();
        let mut entry_count = 0;
        let mut error_count = 0;
        let mut search_hits = 0;
        let mut grep_hits = 0;

        for entry in WalkDir::new(path)
            .max_depth(depth_flag as usize) // set maximum search depth
            .into_iter()
            // TODO bottleneck if it has to filter out hidden files
            .filter_entry(|entry| file_check(entry, no_hidden_flag))
        // handle hidden flag
        {
            match entry {
                Ok(entry) => {
                    // handle file flag
                    // must be outside of function file_check()
                    // else no file will be searched with WalkDir...filter_entry()
                    if file_flag && !entry.file_type().is_file() {
                        continue;
                    }

                    // handle dir flag
                    // must be outside of function file_check()
                    // else search stops if dir is found via WalkDir...filter_entry()
                    if dir_flag && !entry.file_type().is_dir() {
                        continue;
                    }

                    // handle extensions
                    if !extensions.is_empty() {
                        if let Some(extension) = entry.path().extension() {
                            // skip entry if entry extension doesn't matche any given extension via '--extensions' flag
                            if !extensions
                                .iter()
                                .any(|ex| &extension.to_string_lossy().to_string() == *ex)
                            {
                                continue;
                            }
                        }
                    }

                    entry_count += 1;

                    let name = get_filename(&entry);

                    if excludes.is_match(&name) {
                        continue;
                    }

                    let parent = get_parent_path(entry);
                    let fullpath = format!("{}/{}", parent, name);

                    let captures: Vec<_> = reg.find_iter(&name).collect();
                    if !captures.is_empty() {
                        search_hits += 1;

                        if !grep_reg.as_str().is_empty() {
                            let content =
                                fs::read_to_string(&fullpath).unwrap_or_else(|_| String::new());
                            let grep_captures: Vec<_> = grep_reg.find_iter(&content).collect();

                            if !grep_captures.is_empty() {
                                grep_hits += 1;

                                if !count_flag {
                                    let mut linenumber = 0;

                                    if raw_flag {
                                        // don't use "file://" to make the path clickable in Windows Terminal -> otherwise output can't be piped easily to another program
                                        writeln!(handle, "{}", fullpath).unwrap_or_else(|err| {
                                            error!("Error writing to stdout: {err}");
                                        });

                                        for line in content.lines() {
                                            linenumber += 1;
                                            if grep_reg.is_match(&line) {
                                                writeln!(
                                                    handle,
                                                    "{}",
                                                    format!(" {}: {}", linenumber, &line)
                                                )
                                                .unwrap_or_else(|err| {
                                                    error!("Error writing to stdout: {err}");
                                                });
                                            }
                                        }
                                    } else {
                                        // highlight search pattern in filename
                                        let highlighted_name = highlight_capture(&name, &captures);
                                        let highlighted_path = parent + "/" + &highlighted_name;
                                        // TODO check if terminal accepts clickable paths
                                        println!("file://{}", highlighted_path);

                                        for line in content.lines() {
                                            linenumber += 1;
                                            if grep_reg.is_match(&line) {
                                                let highlighted_line =
                                                    highlight_capture(&line, &grep_captures);
                                                println!(
                                                    " {}: {}",
                                                    linenumber.to_string().bright_red(),
                                                    &highlighted_line
                                                );
                                            }
                                        }
                                    }
                                }
                            }
                        } else {
                            if !count_flag {
                                if raw_flag {
                                    // don't use "file://" to make the path clickable in Windows Terminal -> otherwise output can't be piped easily to another program
                                    writeln!(handle, "{}", fullpath).unwrap_or_else(|err| {
                                        error!("Error writing to stdout: {err}");
                                    });
                                } else {
                                    // highlight search pattern in filename
                                    let highlighted_name = highlight_capture(&name, &captures);
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
        handle
            .flush()
            .unwrap_or_else(|err| error!("Error flushing writer: {err}"));

        let hits = if !grep_reg.as_str().is_empty() {
            grep_hits
        } else {
            search_hits
        };

        // TODO FIXME
        if count_flag && !stats_flag {
            println!("{}", hits);
        } else if count_flag && stats_flag || !count_flag && stats_flag {
            println!(
                "[{}  {} {} {}]",
                format!("{:?}", start.elapsed()).bright_blue(),
                entry_count.to_string().dimmed(),
                error_count.to_string().bright_red(),
                hits.to_string().bright_green()
            );
        }
    } else {
        // handle commands
        match matches.subcommand() {
            Some(("log", _)) => {
                if let Ok(logs) = show_log_file(&config_dir) {
                    println!("{}", "Available logs:".bold().yellow());
                    println!("{}", logs);
                } else {
                    error!("Unable to read logs");
                    process::exit(1);
                }
            }
            _ => {
                unreachable!();
            }
        }
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
        .long_about(format!("{}\n", "Simple file and pattern search",))
        // TODO update version
        .version("1.0.0")
        .author("Leann Phydon <leann.phydon@gmail.com>")
        .arg_required_else_help(true)
        .arg(
            Arg::new("args")
                .help("Add a search pattern (regex) and a path")
                .action(ArgAction::Set)
                .num_args(2)
                .value_names(["PATTERN", "PATH"]),
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
                    "{}\n{}",
                    "Only print the number of search results",
                    "Can be combined with the --stats flag to only show stats",
                ))
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("depth")
                .short('D')
                .long("depth")
                .help("Set max search depth")
                .default_value("250")
                .action(ArgAction::Set)
                .num_args(1)
                .value_name("NUMBER"),
        )
        .arg(
            Arg::new("dir")
                .short('d')
                .long("dir")
                .help("Search only in directory names for the pattern")
                .action(ArgAction::SetTrue)
                .conflicts_with("file"),
        )
        .arg(
            Arg::new("extension")
                .short('e')
                .long("extension")
                .help("Only search in files with the given extensions")
                .long_help(format!(
                    "{}\n{}",
                    "Only search in files with the given extensions",
                    "Must be provided after the pattern and the search path"
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
                .help("Enter patterns to exclude from the search")
                .long_help(format!(
                    "{}\n{}",
                    "Enter patterns to exclude from the search",
                    "Must be provided after the pattern and the search path"
                ))
                .action(ArgAction::Set)
                .num_args(1..)
                .value_name("PATTERNS"),
        )
        .arg(
            Arg::new("file")
                .short('f')
                .long("file")
                .help("Search only in file names for the pattern")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("grep")
                .short('g')
                .long("grep")
                .help("Search for specific regex pattern in files")
                .action(ArgAction::Set)
                .num_args(1)
                .value_name("GREP_PATTERN"),
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
        // TODO remove? (useless???)
        // .arg(
        //     Arg::new("override")
        //         .short('o')
        //         .long("override")
        //         .help("Override all previously set flags")
        //         .long_help(format!(
        //             "{}\n{}\n{}",
        //             "Override all previously set flags",
        //             "This can be used when a custom alias for this command is set together with regularly used flags",
        //             "This flag allows to disable these flags and specify new ones"
        //         ))
        //         // TODO if new args -> add here to this list to override if needed
        //         .overrides_with_all(["stats", "stats-long", "file", "dir", "extension", "exclude", "no-hidden", "raw", "count", "show-errors"])
        //         .action(ArgAction::SetTrue),
        // )
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
                    "Cannot be set together with the --stats flag",
                ))
                .action(ArgAction::SetTrue)
                // TODO remove stats-long??
                // .conflicts_with_all(["stats", "stats-long"]),
                .conflicts_with("stats"),
        )
        .arg(
            Arg::new("show-errors")
                .long("show-errors")
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
                .help("Show short search statistics at the end")
                .long_help(format!(
                    "{}\n{}\n{}",
                    "Show short search statistics at the end",
                    "Can be combined with the --count flag to only show stats",
                    "Cannot be set together with the --raw flag",
                ))
                // TODO remove??
                // .conflicts_with("stats-long")
                .action(ArgAction::SetTrue),
        )
        // TODO remove??
        // .arg(
        //     Arg::new("stats-long")
        //         .long("stats-long")
        //         .help("Show search statistics at the end")
        //         .long_help(format!(
        //             "{}\n{}\n{}",
        //             "Show search statistics at the end",
        //             "Can be combined with the --count flag to only show stats",
        //             "Cannot be set together with the --raw flag",
        //         ))
        //         .action(ArgAction::SetTrue),
        // )
        .subcommand(
            Command::new("log")
                .short_flag('L')
                .long_flag("log")
                .about("Show content of the log file"),
        )
}

fn set_search_depth(matches: &ArgMatches) -> u32 {
    if let Some(d) = matches.get_one::<String>("depth") {
        match d.parse() {
            Ok(depth) => return depth,
            Err(err) => {
                error!("Expected an integer for the search depth: {err}");
                process::exit(1);
            }
        }
    } else {
        // default search depth is 250
        return 250;
    }
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

fn highlight_capture(content: &str, captures: &Vec<Match>) -> String {
    assert!(!captures.is_empty());

    let mut result = String::new();
    // FIXME
    for capture in captures {
        let before_capture = &content[..capture.start()];
        let after_capture = &content[capture.end()..];
        let pattern = capture.as_str().bright_blue().to_string();

        result = before_capture.to_string() + &pattern + after_capture;
    }

    result.to_string()
}

// check entries if hidden and compare to hidden flag
fn file_check(entry: &DirEntry, no_hidden_flag: bool) -> bool {
    // TODO bottleneck
    if no_hidden_flag && is_hidden(&entry.path().to_path_buf()).unwrap_or(false) {
        return false;
    }

    return true;
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
