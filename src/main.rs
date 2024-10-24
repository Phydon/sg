// TODO rename performance to raw or raw-mode
use std::{
    env, fs,
    io::{self, Write},
    path::{Path, PathBuf},
    process,
    time::Instant,
};

use clap::{Arg, ArgAction, Command};
use colored::Colorize;
use flexi_logger::{detailed_format, Duplicate, FileSpec, Logger};
use log::{error, warn};
use regex::RegexBuilder;
use walkdir::WalkDir;

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
    let performance_flag = matches.get_flag("performance");
    let count_flag = matches.get_flag("count");
    let file_flag = matches.get_flag("file");
    let dir_flag = matches.get_flag("dir");
    // TODO remove or implement?
    // let no_hidden_flag = matches.get_flag("no-hidden");
    let show_errors_flag = matches.get_flag("show-errors");

    // set default search depth
    let mut depth_flag = 250;
    if let Some(d) = matches.get_one::<String>("depth") {
        match d.parse() {
            Ok(depth) => depth_flag = depth,
            Err(err) => {
                error!("Expected an integer for the search depth: {err}");
                process::exit(1);
            }
        }
    }

    if let Some(args) = matches
        .get_many::<String>("args")
        .map(|a| a.collect::<Vec<_>>())
    {
        // get search pattern from arguments
        // TODO handle unwrap()
        let reg = RegexBuilder::new(args[0].as_str())
            .case_insensitive(case_insensitive_flag)
            // TODO check if needed
            // .unicode(false)
            .build()
            .unwrap();

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

        // TODO
        // get possible file extensions for filtering
        let mut extensions = Vec::new();
        if let Some(mut ext) = matches
            .get_many::<String>("extension")
            .map(|a| a.collect::<Vec<_>>())
        {
            extensions.append(&mut ext);
        }

        // TODO
        // get exclude patterns
        let mut exclude_patterns = Vec::new();
        if let Some(mut excl) = matches
            .get_many::<String>("exclude")
            .map(|a| a.collect::<Vec<_>>())
        {
            // TODO store in regex
            exclude_patterns.append(&mut excl);
        }

        let start = Instant::now();
        let mut entry_count = 0;
        let mut error_count = 0;
        let mut search_hits = 0;

        // TODO handle unwrap()
        for entry in WalkDir::new(path)
            .max_depth(depth_flag as usize) // set maximum search depth
            .into_iter()
        // .filter_map(|e| e.ok())
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

                    // TODO handle extensions here

                    entry_count += 1;

                    // get filename
                    let name = &entry.file_name().to_string_lossy().to_string();

                    // get parent path
                    let parent = entry
                        .path()
                        .parent()
                        .unwrap_or_else(|| Path::new(""))
                        .to_string_lossy()
                        .to_string()
                        .replace("\\", "/");

                    let fullpath = parent + "/" + &name;

                    if let Some(capture) = reg.captures(name) {
                        search_hits += 1;

                        // TODO highlight search patterns in filenames
                        if performance_flag {
                            // don't use "file://" to make the path clickable in Windows Terminal -> otherwise output can't be piped easily to another program
                            writeln!(handle, "{}", format!("{}", fullpath)).unwrap_or_else(|err| {
                                error!("Error writing to stdout: {err}");
                            });
                        } else {
                            println!("file://{}: {}", fullpath, &capture[0]);
                            // println!("file://{}", fullpath);
                        }
                    } else {
                        continue;
                    }
                }
                Err(err) => {
                    error_count += 1;
                    // println!("{}", err);

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

        if count_flag {
            println!(
                "[{}  {} {} {}]",
                format!("{:?}", start.elapsed()).bright_blue(),
                entry_count.to_string().dimmed(),
                error_count.to_string().bright_red(),
                search_hits.to_string().bright_green()
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
            "SIMPLE FIND".bold().truecolor(250, 0, 104),
            "Leann Phydon <leann.phydon@gmail.com>".italic().dimmed()
        ))
        .long_about(format!(
            "{}\n",
            "Simple file and pattern search",
        ))
        // TODO update version
        .version("1.0.0")
        .author("Leann Phydon <leann.phydon@gmail.com>")
        .arg_required_else_help(true)
        .arg(
            Arg::new("args")
                .help("Add a search pattern and a path")
                .action(ArgAction::Set)
                .num_args(2)
                .value_names(["PATTERN", "PATH"]),
        )
        .arg(
            Arg::new("case-insensitive")
                .short('i')
                .long("case-insensitive")
                .help("Search case insensitivly")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("count")
                .short('c')
                .long("count")
                .help("Only print the number of search results")
                .long_help(format!("{}\n{}", 
                    "Only print the number of search results",
                    "Can be combined with the --stats flag to only show stats",
                ))
                .action(ArgAction::SetTrue)
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
            Arg::new("override")
                .short('o')
                .long("override")
                .help("Override all previously set flags")
                .long_help(format!(
                    "{}\n{}\n{}",
                    "Override all previously set flags",
                    "This can be used when a custom alias for this command is set together with regularly used flags",
                    "This flag allows to disable these flags and specify new ones"
                ))
                // TODO if new args -> add here to this list to override if needed
                .overrides_with_all(["stats", "stats-long", "file", "dir", "extension", "exclude", "no-hidden", "performance", "count", "show-errors"])
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("performance")
                .short('p')
                .long("performance")
                .help("Disable spinner, don`t colourize the search output and speed up the output printing")
                .long_help(format!(
                    "{}\n{}\n{}\n{}",
                    "Focus on performance",
                    "Disable search indicating spinner and don`t colourize the search output",
                    "Write the output via BufWriter",
                    "Cannot be set together with the --stats flag",
                ))
                .action(ArgAction::SetTrue)
                .conflicts_with_all(["stats", "stats-long"]),
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
                .action(ArgAction::SetTrue)
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
                    "Cannot be set together with the --performance flag",
                ))
                .conflicts_with("stats-long")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("stats-long")
                .long("stats-long")
                .help("Show search statistics at the end")
                .long_help(format!(
                    "{}\n{}\n{}",
                    "Show search statistics at the end",
                    "Can be combined with the --count flag to only show stats",
                    "Cannot be set together with the --performance flag",
                ))
                .action(ArgAction::SetTrue),
        )
        .subcommand(
            Command::new("log")
                .short_flag('L')
                .long_flag("log")
                .about("Show content of the log file"),
        )
}

// TODO implement
// FIXME adjust for regex -> Regex::captures holds byte offsets of a match
// fn highlight_pattern_in_name(name: &str, config: &Config) -> String {
//     // find first byte of pattern in filename
//     let pat_in_name = name.find(&config.pattern).unwrap_or_else(|| 9999999999);

//     if pat_in_name == 9999999999 {
//         // if no pattern found return just the filename
//         return name.to_string();
//     } else {
//         let first_from_name = &name[..pat_in_name];
//         let last_from_name = &name[(pat_in_name + config.pattern.len())..];
//         // colourize the pattern in the filename
//         let highlighted_pattern = config.pattern.truecolor(112, 110, 255).to_string();

//         let mut result = String::from(first_from_name);
//         result.push_str(&highlighted_pattern);
//         result.push_str(last_from_name);

//         result.to_string()
//     }
// }

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
