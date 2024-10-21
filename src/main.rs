use std::{
    // env,
    fs,
    io::{self, Write},
    // os::windows::prelude::MetadataExt,
    path::{Path, PathBuf},
    process,
    // time::{Duration, Instant},
};

use clap::{Arg, ArgAction, Command};
use flexi_logger::{detailed_format, Duplicate, FileSpec, Logger};
// use indicatif::{HumanDuration, ProgressBar, ProgressStyle};
use colored::Colorize;
use log::error;

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
    // let mut file_flag = matches.get_flag("file");

    // set default search depth
    // let mut depth_flag = 250;
    // if let Some(d) = matches.get_one::<String>("depth") {
    //     match d.parse() {
    //         Ok(depth) => depth_flag = depth,
    //         Err(err) => {
    //             error!("Expected an integer for the search depth: {err}");
    //             process::exit(1);
    //         }
    //     }
    // }

    if let Some(args) = matches
        .get_many::<String>("args")
        .map(|a| a.collect::<Vec<_>>())
    {
        // get search pattern from arguments
        let pattern = vec![args[0].as_str()];

        // get search path from arguments
        let path = Path::new(&args[1]).to_path_buf();

        // empty bufwriter
        handle
            .flush()
            .unwrap_or_else(|err| error!("Error flushing writer: {err}"));
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
        .about("Simple file search")
        .before_long_help(format!(
            "{}\n{}",
            "SIMPLE FIND".bold().truecolor(250, 0, 104),
            "Leann Phydon <leann.phydon@gmail.com>".italic().dimmed()
        ))
        .long_about(format!(
            "{}\n  {}\n  {}\n  {}\n  {}\n  {}\n  {}\n  {}\n  {}\n\n{}",
            "Simple file search",
            "- colourful output and search indicating spinner by default ",
            "- filter by file, directory and file-extension",
            "- exclude patterns from the search ",
            "- exclude hidden files",
            "- show search statistics at the end",
            "- accepts \'.\' as current directory",
            "- search case insensitive",
            "- no regex search",
            "Note: every set filter slows down the search".truecolor(250, 0, 104)
        ))
        // TODO update version
        .version("1.8.6")
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
