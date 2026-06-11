# DirLens

DirLens is a lightweight authorized directory listing scanner.

It crawls only paths discovered on the target website, such as links, resources,
`robots.txt`, and sitemap entries. It also seeds the scan with a curated list of
common paths that exist on most sites but are rarely linked explicitly.
It does not use bruteforce or large wordlists.

https://github.com/LTX128/Dirlens

## Features

- Detects exposed directory listings
- Flags exposed non-HTML or sensitive paths (`.log`, `.env`, `.sql`, text files)
- Highlights `/wp-json/wp/v2/users` and `?rest_route=/wp/v2/users` with a
  dedicated `[WP-USERS]` finding
- Highlights other public WordPress REST API endpoints with `[WP-API]`
- Keeps login-like pages in the scan and reports them as warnings instead of
  rejecting them
- Crawls discovered same-domain resources
- Checks `robots.txt` and performs exhaustive sitemap discovery (see below)
- Seeds the scan with a curated set of common paths (`/contact`, `/admin`,
  `/wp-admin`, `/wp-json/wp/v2/users`, `/uploads`, sensitive config/log names,
  API docs, etc.)
- Shows HTTP status codes during testing
- Shows real phase progress based on completed work and discovered results
- Deduplicates result URLs and normalizes trailing-slash duplicates
- Prints all findings without truncating them
- Very fast adaptive `--speed` mode with 429/timeout backoff
- Supports parallel workers and request delay
- Quiet mode for clean output and scripting
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

Very fast scan:

```bash
python dirlens.py https://example.com --speed
```

With custom crawl settings:

```bash
python dirlens.py https://example.com --depth 3 --max-pages 200 --workers 20 --delay 0 --timeout 6
```

Quiet mode (only findings are printed during the scan):

```bash
python dirlens.py https://example.com --quiet
python dirlens.py https://example.com --quiet --json
```

## Options

```text
--depth N          Crawl depth. Default: 2
--max-pages N      Maximum pages to crawl. Default: 50
--workers N        Parallel crawl workers. Default: 10
--delay SECONDS    Delay between requests per worker. Default: 0
--timeout SECONDS  HTTP request timeout. Default: 8
--retries N        Retry failed requests. Default: 1
--speed            Very fast adaptive mode with many threads
--json             Save JSON report to reports/
--html             Save HTML report to reports/
--no-color         Disable coloured terminal output
--verbose          Show debug output
--quiet            Only print findings ([FOUND], [EXPOSED], [403]) and final summary
--no-common        Skip built-in common path seeding
```

Use `-h` to display the help screen:

```bash
python dirlens.py -h
```

## Speed mode

Use `--speed` when you want DirLens to run as fast as possible. It uses many
more threads, removes request delay, skips UI pauses, and uses a fast but more
realistic timeout. It also applies a small adaptive backoff when the target
starts returning `429`, timeout, or connection errors, which is usually faster
in practice than flooding the site until most requests fail.

Default `--speed` settings:

```text
Crawl workers : 64
Test workers  : 192
Timeout       : 4 seconds
Retries       : 0
```

You can still tune it manually, for example:

```bash
python dirlens.py https://example.com --speed --timeout 6
```

Speed scans also count `429` rate limits and speed-related timeouts in the
terminal summary and reports.

## Quiet mode

With `--quiet`, the banner and scan parameters are still shown at startup so you
always know what is running. Everything else — phase headers, `[TEST]` lines,
crawl waves — is silenced. Only open listings (`[FOUND]`), WordPress users API
findings (`[WP-USERS]`), WordPress REST API findings (`[WP-API]`), exposed paths
(`[EXPOSED]`), and forbidden paths (`[403]`) are printed as they are discovered,
followed by a short summary.

Useful for scripting, piping output to a file, or running multiple targets in
sequence without noise.

## Interrupted scans

Press `Ctrl+C` to stop a running scan. DirLens stops scheduling new work and
still prints the summary plus any findings already discovered. If `--json` or
`--html` is enabled, the partial report is still written.

## Common path seeding

Many paths exist on sites without being linked anywhere — `/contact`, `/admin`,
`/uploads`, `/documents`, `/api`, etc. DirLens automatically seeds the directory
test queue with 201 curated common paths plus WordPress REST API probes such as
`/wp-json/wp/v2/users`, so they are always tested even if the crawler never finds
a link to them.

This is not bruteforce — it is a small curated list of universally common paths,
not a wordlist attack. Use `--no-common` to disable this behavior if needed.

## Sitemap discovery

DirLens runs the most thorough sitemap discovery possible:

**51 candidate paths probed automatically**, including:
- Standard paths: `/sitemap.xml`, `/sitemap_index.xml`, `/sitemap-index.xml`
- Gzip variants: `/sitemap.xml.gz`, `/sitemap_index.xml.gz`
- Type-specific sitemaps: `-news`, `-products`, `-categories`, `-pages`, `-posts`,
  `-blog`, `-images`, `-videos`
- Numbered variants: `sitemap1.xml`, `sitemap-0.xml`, `sitemap-1.xml`, etc.
- WordPress sitemaps: `/wp-sitemap.xml`, `/wp-sitemap-posts-post-1.xml`, etc.
- Language prefixes: `/en/sitemap.xml`, `/fr/sitemap.xml`, `/de/sitemap.xml`, `/es/sitemap.xml`

**Recursive sitemap index support** — sitemap indexes that reference other sitemap
indexes are followed recursively (up to 12 levels deep, cycle-safe).

**Gzip decompression** — `.xml.gz` sitemaps are decompressed transparently,
even when the server omits the `Content-Encoding` header.

**Malformed sitemap fallback** — if a sitemap is not valid XML, DirLens still
tries to recover sitemap and URL entries with a regex fallback parser.

**All URL types extracted**:
- `<loc>` — standard page URLs
- `<image:loc>` — Google Images sitemaps
- `<video:content_loc>` / `<video:player_loc>` — Google Video sitemaps
- `<news:loc>` — Google News sitemaps
- `<xhtml:link href="...">` — hreflang alternate URLs (multilingual sites)

**HTML-level discovery** — the homepage is scanned for sitemap references in
`<link>` and `<a>` tags.

**HTTP header discovery** — `X-Sitemap`, `Sitemap`, and `Link: <...>;
rel=sitemap` headers are followed automatically.

## Output behavior

DirLens normalizes finding URLs before printing them. For example, if both
`/wp-admin` and `/wp-admin/` are discovered, the report keeps a single canonical
entry. `/wp-json/wp/v2/users` and `?rest_route=/wp/v2/users` are shown
separately with `[WP-USERS]`, while other WordPress REST API endpoints use
`[WP-API]`. Both categories get their own JSON/HTML report sections. Result
lists are also deduplicated, and final finding sections are printed in full
without `... more` truncation.

If a page contains login-like text, DirLens does not reject it. The URL is kept
in normal detection and also listed under login warnings at the end of the scan
and in reports.

## Reports

When `--json` or `--html` is used, reports are saved in the `reports/` folder.
The report includes the target, scan metadata, discovered resources, tested
directories, WordPress users API endpoints, other WordPress REST API endpoints,
exposed non-HTML/sensitive paths, forbidden paths, login warnings, rate-limit
counters, timeout counters, interruption status, errors, and any open directory
listings found.

## Requirements

- Python 3.10+
- requests
- beautifulsoup4
- colorama

## Legal notice

Use DirLens only on websites you own or have explicit permission to test.
