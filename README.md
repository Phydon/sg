# sg

***S**imple **G**rep*

> combining [sf](https://github.com/Phydon/sf) and [mg](https://github.com/Phydon/mg)

Simple recursive file and pattern search via regex patterns

## Examples


> todo add more examples


### Example 1

- list everything in the current directory

```shell
sg . .
```


### Example 2

- find all python or rust files in the 'src' directory that contain the word 'main' or 'init' in their filename

```shell
sg "main|init" .\src\ -e rs py
```


### Example 3

- find all files in the current directory that contain the words 'fixme' or 'todo'
- search case insensitively

```shell
sg . . -g "todo|fixme" -i
```


### Example 4

- count all txt-files in the 'document' directory

```shell
sg . .\Documents -e txt -c
```


## Usage

### Short Usage

```
Usage: sg [REGEX] [PATH] [OPTIONS]
       sg [COMMAND]

Commands:
  examples, --examples  Show examples
  log, -L, --log        Show content of the log file
  syntax, -S, --syntax  Show regex syntax information
  help                  Print this message or the help of the given subcommand(s)

Arguments:
  [REGEX] [PATH]  Add a search regex and a path for the file search

Options:
  -i, --case-insensitive            Search case insensitively
  -c, --count                       Only print the number of search results
  -D, --depth <NUMBER>              Set max search depth [default: 1000000]
  -d, --dir                         Search only in directory names for the given regex [aliases: directory, directories]
  -e, --extensions <EXTENSIONS>...  Only search in files with the given extensions [aliases: extensions, ext]
  -E, --exclude <REGEX>...          Exclude regex patterns from the search
  -f, --file                        Search only in filenames for the regex [aliases: files]
  -g, --grep <REGEX>                Search for specific regex pattern in files
  -m, --matching-files              Only show the relevant files that contain the grep regex pattern, without printing the actual matching lines [aliases: matches]
  -H, --no-hidden                   Exclude hidden files and directories from search
  -r, --raw                         Don`t colourize the search output and speed up the output printing
      --show-errors                 Show possible filesystem errors [aliases: show-error]
  -s, --stats                       Show short search statistics at the end [aliases: statistic, statistics]
  -h, --help                        Print help (see more with '--help')
  -V, --version                     Print version
```

### Long Usage

```
Usage: sg [REGEX] [PATH] [OPTIONS]
       sg [COMMAND]

Commands:
  examples, --examples  Show examples
  log, -L, --log        Show content of the log file
  syntax, -S, --syntax  Show regex syntax information
  help                  Print this message or the help of the given subcommand(s)

Arguments:
  [REGEX] [PATH]
          Add a search regex and a path for the file search

Options:
  -i, --case-insensitive
          Search case insensitively

  -c, --count
          Only print the number of search results
          Can be combined with the --stats flag to only show stats
          When used with the --grep flag the first output is the number of files containing at least one match
          The second number is the overall number of matches

  -D, --depth <NUMBER>
          Set max search depth

          [default: 1000000]

  -d, --dir
          Search only in directory names for the given regex

          [aliases: directory, directories]

  -e, --extensions <EXTENSIONS>...
          Only search in files with the given extensions
          Must be provided after the regex and the search path

          [aliases: extensions, ext]

  -E, --exclude <REGEX>...
          Exclude regex patterns from the search
          Must be provided after the regex and the search path

  -f, --file
          Search only in filenames for the regex

          [aliases: files]

  -g, --grep <REGEX>
          Search for specific regex pattern in files

  -m, --matching-files
          Only show the relevant files that contain the grep regex pattern, without printing the actual matching lines
          Can only be used together with the 'grep' flag

          [aliases: matches]

  -H, --no-hidden
          Exclude hidden files and directories from search
          If a directory is hidden, all its content will be skiped as well

  -r, --raw
          Focus on performance
          Don`t colourize the search output
          Write the output via BufWriter
          Print raw filepaths

      --show-errors
          Show possible filesystem errors
          For example for situations such as insufficient permissions

          [aliases: show-error]

  -s, --stats
          Show short search statistics at the end
          Can be combined with the --count flag to only show stats
          Output: ['elapsed time'  'searched number of files' 'errors' 'file search hits' 'grep hits']

          [aliases: statistic, statistics]

  -h, --help
          Print help (see a summary with '-h')

  -V, --version
          Print version
```

## Installation

### Windows

via Cargo or get the ![binary](https://github.com/Phydon/sg/releases)


