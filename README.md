# sg

***S**imple **G**rep*

Simple recursive file and pattern search via regex patterns


## Examples


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


### Example 5

- search e-mails (e.g.: leann.phydon@gmail.com) in files

```shell
$ sg . . -g "[\w\d]*\.*[\w\d]+@[\w]+\.[\w]+"
```


## Usage

### Short Usage

```
Usage: sg [REGEX] [PATH] [OPTIONS]
       sg [COMMAND]

Commands:
  examples, -X, --examples  Show examples [aliases: example, --example]
  log, -L, --log            Show content of the log file
  syntax, -S, --syntax      Show regex syntax information
  help                      Print this message or the help of the given subcommand(s)

Arguments:
  [REGEX] [PATH]  Add a search regex and a path for the file search

Options:
  -i, --case-insensitive            Search case insensitively
  -C, --common                      Set common pre-filters
  -c, --count                       Only print the number of search results
  -D, --depth <NUMBER>              Set max search depth [default: 1000000]
  -d, --dir                         Search only in directory names for the given regex [aliases: directory, directories]
  -e, --extensions <EXTENSIONS>...  Only search in files with the given extensions [aliases: extensions, ext]
  -E, --exclude <REGEX>...          Exclude regex patterns from the search
  -f, --file                        Search only in filenames for the regex [aliases: files]
  -g, --grep <REGEX>                Search for specific regex pattern in files
  -l, --link                        Make filepaths clickable [aliases: hyperlink]
      --list-common                 List all common pre-filters
  -H, --hidden                      Include hidden files and directories in search
  -o, --only-filepaths              Only show the files that contain the grep regex pattern, without printing the actual matching lines [aliases: only]
  -r, --raw                         Don`t colourize the search output and speed up the output printing
      --show-errors                 Show possible filesystem warnings and errors [aliases: show-error]
  -s, --stats                       Show short search statistics at the end [aliases: statistic, statistics]
  -u, --no-unicode                  Exclude unicode in search
  -h, --help                        Print help (see more with '--help')
  -V, --version                     Print version
```

### Long Usage

```
Usage: sg [REGEX] [PATH] [OPTIONS]
       sg [COMMAND]

Commands:
  examples, -X, --examples  Show examples [aliases: example, --example]
  log, -L, --log            Show content of the log file
  syntax, -S, --syntax      Show regex syntax information
  help                      Print this message or the help of the given subcommand(s)

Arguments:
  [REGEX] [PATH]
          Add a search regex and a path for the file search

Options:
  -i, --case-insensitive
          Search case insensitively

  -C, --common
          Set common pre-filters
          Exclude some files from the search, that usually pollute the output with hugh amounts of data
          Common examples are source maps, stored in *.js.map files
          They take thousands of lines of pretty code and turn it into only a few lines of ugly code

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

  -l, --link
          Make filepaths clickable, so that it opens the file or directory with the default tool or program
          Terminal has to accept clickable filepaths

          [aliases: hyperlink]

      --list-common
          List all common pre-filters

  -H, --hidden
          Include hidden files and directories in search
          If a directory is hidden, all its content counts as hidden as well
          Everything starting with '.' counts as hidden as well
          Hidden files and directories are excluded by default

  -o, --only-filepaths
          Only show the files that contain the grep regex pattern, without printing the actual matching lines
          Can only be used together with the 'grep' flag

          [aliases: only]

  -r, --raw
          Focus on performance
          Don`t colourize the search output
          Print raw filepaths

      --show-errors
          Show possible filesystem warnings and errors
          For example in case of insufficient permissions or unreadable non-UTF-8 data

          [aliases: show-error]

  -s, --stats
          Show short search statistics at the end
          Can be combined with the --count flag to only show stats
          Output: ['elapsed time'  'searched number of files' 'errors' 'file search hits' 'grep hits']

          [aliases: statistic, statistics]

  -u, --no-unicode
          Disables unicode mode [Default: Enabled]
          With Unicode character classes like \p{Letter} and \p{Greek} are available
          Note that if Unicode mode is disabled, then the regex will fail to compile if it could match invalid UTF-8
          More information: https://docs.rs/regex/latest/regex/struct.RegexBuilder.html#method.unicode

  -h, --help
          Print help (see a summary with '-h')

  -V, --version
          Print version
```

## Installation

### Windows

via Cargo or get the ![binary](https://github.com/Phydon/sg/releases)


