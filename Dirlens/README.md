# DirLens

DirLens is a lightweight authorized directory listing scanner.

It crawls only paths discovered on the target website, such as links, resources,
`robots.txt`, and sitemap entries. It does not use bruteforce, wordlists, or
invented paths.

By LTX  
https://github.com/LTX128/Dirlens

## Features

- Detects exposed directory listings
- Crawls discovered same-domain resources
- Checks `robots.txt` and sitemap files
- Shows HTTP status codes during testing
- Supports parallel workers and request delay
- Can export JSON and HTML reports

## Installation

```bash
git clone https://github.com/LTX128/Dirlens.git
cd Dirlens
pip install -r requirements.txt
```

## Usage

```bash
python dirlens.py https://example.com
```

With reports:

```bash
python dirlens.py https://example.com --json --html
```

With custom crawl settings:

```bash
python dirlens.py https://example.com --depth 3 --max-pages 200 --workers 20 --delay 0 --timeout 6
```

## Options

```text
--depth N          Crawl depth. Default: 2
--max-pages N      Maximum pages to crawl. Default: 50
--workers N        Parallel crawl workers. Default: 10
--delay SECONDS    Delay between requests per worker. Default: 0
--timeout SECONDS  HTTP request timeout. Default: 8
--json             Save JSON report to reports/
--html             Save HTML report to reports/
--no-color         Disable coloured terminal output
--verbose          Show debug output
```

Use `-h` to display the help screen:

```bash
python dirlens.py -h
```

## Reports

When `--json` or `--html` is used, reports are saved in the `reports/` folder.
The report includes the target, scan metadata, discovered resources, tested
directories, forbidden paths, errors, and any open directory listings found.

## Requirements

- Python 3.10+
- requests
- beautifulsoup4
- colorama

## Legal notice

Use DirLens only on websites you own or have explicit permission to test.
