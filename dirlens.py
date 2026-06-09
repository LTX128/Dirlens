"""
DirLens - Directory Listing Scanner
Detects open directory listings using only paths discovered on the target site.
No bruteforce. No wordlists. No invented paths.
"""

import argparse
import json
import re
import sys
import os
import time
import threading
from collections import deque
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from datetime import datetime
from pathlib import Path
from urllib.parse import urljoin, urlparse, urlunparse

import requests
from bs4 import BeautifulSoup
from colorama import Fore, Style, init as colorama_init

USER_AGENT = "DirLens - Directory Listing Scanner"
AUTHOR_NAME = "LTX"
AUTHOR_GITHUB_URL = "https://github.com/LTX128/Dirlens"

DEFAULT_CRAWL_WORKERS = 10
DEFAULT_TEST_WORKERS = 20

DIRECTORY_LISTING_SIGNATURES = [
    re.compile(r"Index of /", re.IGNORECASE),
    re.compile(r"<title>Index of", re.IGNORECASE),
    re.compile(r"Parent Directory", re.IGNORECASE),
    re.compile(r"Name\s+Last modified\s+Size\s+Description", re.IGNORECASE),
    re.compile(r"Directory listing for", re.IGNORECASE),
    re.compile(r"<h1>Index of", re.IGNORECASE),
    re.compile(r'href="\.\."', re.IGNORECASE),
    re.compile(r"nginx autoindex", re.IGNORECASE),
    re.compile(r"fancy index", re.IGNORECASE),
    re.compile(r"lighttpd.*directory listing", re.IGNORECASE),
    re.compile(r"Microsoft-IIS.*directory listing", re.IGNORECASE),
    re.compile(r"<a href=\"\?C=N&amp;O=D\">", re.IGNORECASE),
    re.compile(r'<a href="\?C=', re.IGNORECASE),
]

FALSE_POSITIVE_SIGNATURES = [
    re.compile(r"404", re.IGNORECASE),
    re.compile(r"not found", re.IGNORECASE),
    re.compile(r"page not found", re.IGNORECASE),
    re.compile(r"wp-login", re.IGNORECASE),
    re.compile(r"login", re.IGNORECASE),
    re.compile(r"sign in", re.IGNORECASE),
    re.compile(r"access denied", re.IGNORECASE),
    re.compile(r"forbidden", re.IGNORECASE),
    re.compile(r"error 4[0-9]{2}", re.IGNORECASE),
    re.compile(r"cloudflare", re.IGNORECASE),
    re.compile(r"just a moment", re.IGNORECASE),
    re.compile(r"<title>Error</title>", re.IGNORECASE),
    re.compile(r"<title>403", re.IGNORECASE),
    re.compile(r"<title>404", re.IGNORECASE),
]

RESOURCE_ATTRS = [
    ("a", "href"),
    ("img", "src"),
    ("img", "srcset"),
    ("link", "href"),
    ("script", "src"),
    ("source", "src"),
    ("source", "srcset"),
    ("video", "src"),
    ("audio", "src"),
    ("embed", "src"),
    ("object", "data"),
    ("iframe", "src"),
]

_thread_local = threading.local()
STOP_EVENT = threading.Event()

icon = r"""
██████  ██ ██████  ██      ███████ ███    ██ ███████ 
██   ██ ██ ██   ██ ██      ██      ████   ██ ██      
██   ██ ██ ██████  ██      █████   ██ ██  ██ ███████ 
██   ██ ██ ██   ██ ██      ██      ██  ██ ██      ██ 
██████  ██ ██   ██ ███████ ███████ ██   ████ ███████ 
                                                     
        https://github.com/LTX128/Dirlens
"""
def _get_thread_session(timeout: int) -> requests.Session:
    """Return (or create) a per-thread requests.Session."""
    if not hasattr(_thread_local, "session"):
        s = requests.Session()
        s.headers.update({"User-Agent": USER_AGENT})
        s.max_redirects = 5
        _thread_local.session = s
    return _thread_local.session


def fetch(url: str, timeout: int) -> "requests.Response | None":
    """Fetch a URL using the calling thread's session."""
    session = _get_thread_session(timeout)
    try:
        return session.get(url, timeout=timeout, allow_redirects=True, stream=False)
    except Exception:
        return None


_print_lock = threading.Lock()


class Palette:
    def __init__(self, enabled: bool = True):
        self.enabled = enabled
        colorama_init(autoreset=True)

    def _c(self, colour: str, text: str) -> str:
        if not self.enabled:
            return text
        return f"{colour}{text}{Style.RESET_ALL}"

    def red(self, text):
        return self._c(Fore.RED, text)

    def green(self, text):
        return self._c(Fore.GREEN, text)

    def yellow(self, text):
        return self._c(Fore.YELLOW, text)

    def cyan(self, text):
        return self._c(Fore.CYAN, text)

    def white(self, text):
        return self._c(Fore.WHITE, text)

    def dim(self, text):
        return self._c(Style.DIM, text)


def safe_print(line: str):
    """Thread-safe print."""
    with _print_lock:
        print(line, flush=True)


def normalise_url(url: str) -> str:
    parsed = urlparse(url.strip())
    normalised = urlunparse(
        (
            parsed.scheme.lower(),
            parsed.netloc.lower(),
            parsed.path or "/",
            parsed.params,
            parsed.query,
            "",
        )
    )
    return normalised.rstrip("?")


def same_domain(url: str, base_host: str) -> bool:
    return urlparse(url).netloc.lower() == base_host.lower()


def parent_directories(url: str) -> list:
    parsed = urlparse(url)
    path = parsed.path
    parts = path.rstrip("/").split("/")

    if parts and "." in parts[-1]:
        parts = parts[:-1]

    dirs = []
    for i in range(len(parts), 0, -1):
        dir_path = "/".join(parts[:i]) + "/"
        if not dir_path.startswith("/"):
            dir_path = "/" + dir_path
        dirs.append(urlunparse((parsed.scheme, parsed.netloc, dir_path, "", "", "")))

    root = urlunparse((parsed.scheme, parsed.netloc, "/", "", "", ""))
    if root not in dirs:
        dirs.append(root)

    return dirs


def extract_urls_from_srcset(srcset: str, base: str) -> list:
    urls = []
    for part in srcset.split(","):
        tokens = part.strip().split()
        if tokens:
            urls.append(urljoin(base, tokens[0]))
    return urls


def is_directory_url(url: str) -> bool:
    return urlparse(url).path.endswith("/")


def is_directory_listing(response: "requests.Response") -> bool:
    if response.status_code != 200:
        return False
    ct = response.headers.get("Content-Type", "")
    if "text/html" not in ct and "text/" not in ct:
        return False
    try:
        body = response.text[:40_000]
    except Exception:
        return False

    for pattern in FALSE_POSITIVE_SIGNATURES:
        if pattern.search(body):
            return False

    hits = sum(1 for p in DIRECTORY_LISTING_SIGNATURES if p.search(body))
    return hits >= 2


def classify_response(response: "requests.Response | None") -> str:
    if response is None:
        return "error"
    code = response.status_code
    if code in (403, 401, 407):
        return "forbidden"
    if code == 200:
        return "listing" if is_directory_listing(response) else "clean"
    return "error"


class DirLens:
    def __init__(self, args: argparse.Namespace):
        self.target = normalise_url(args.url)
        self.parsed_base = urlparse(self.target)
        self.base_host = self.parsed_base.netloc.lower()
        self.depth = args.depth
        self.delay = args.delay
        self.timeout = args.timeout
        self.max_pages = args.max_pages
        self.crawl_workers = args.workers
        self.test_workers = args.workers * 2
        self.verbose = args.verbose
        self.no_color = args.no_color
        self.json_report = args.json
        self.html_report = args.html

        self.palette = Palette(enabled=not self.no_color)

        self._lock = threading.Lock()

        self.pages_crawled: int = 0
        self.resources_found: set = set()
        self.crawled_urls: set = set()

        self.dirs_tested: set = set()
        self.queued_dirs: set = set()

        self.listings_found: list = []
        self.forbidden_paths: list = []
        self.errors: int = 0
        self.crawl_errors: int = 0

    def _tag(self, status: str) -> str:
        p = self.palette
        return {
            "listing": p.green("[FOUND]"),
            "forbidden": p.yellow("[403]"),
            "test": p.red("[TEST]"),
            "error": p.dim("[ERR]"),
            "crawl": p.dim("[CRAWL]"),
        }.get(status, p.dim("[---]"))

    def _code_tag(self, code) -> str:
        p = self.palette
        text = f"[{code}]"
        if code == "timeout":
            return p.red(text)
        if 200 <= code < 400:
            return p.green(text)
        if 400 <= code < 500:
            return p.yellow(text)
        if code >= 500:
            return p.red(text)
        return p.dim(text)

    def _print(self, status: str, url: str, code=None):
        code_text = f" {self._code_tag(code)}" if code is not None else ""
        safe_print(f"{self._tag(status)}{code_text} {url}")

    def _verbose(self, msg: str):
        if self.verbose:
            safe_print(self.palette.dim(f"  > {msg}"))

    def _extract_resources(self, html: str, base_url: str) -> list:
        try:
            soup = BeautifulSoup(html, "html.parser")
        except Exception:
            return []

        found = []
        for tag_name, attr in RESOURCE_ATTRS:
            for tag in soup.find_all(tag_name, **{attr: True}):
                raw = tag[attr]
                if attr == "srcset":
                    found.extend(extract_urls_from_srcset(raw, base_url))
                else:
                    found.append(urljoin(base_url, raw))

        for style_tag in soup.find_all(style=True):
            for u in re.findall(r'url\(["\']?([^"\')\s]+)["\']?\)', style_tag["style"]):
                found.append(urljoin(base_url, u))

        result = []
        for u in found:
            u = normalise_url(u)
            if same_domain(u, self.base_host) and u.startswith("http"):
                result.append(u)
        return result

    def _register_dirs_for_url_locked(self, url: str) -> list:
        """Return list of new directory URLs derived from *url* (lock must be held)."""
        new_dirs = []
        for d in parent_directories(url):
            if d not in self.queued_dirs:
                self.queued_dirs.add(d)
                new_dirs.append(d)
        return new_dirs

    def _process_robots(self) -> list:
        """Fetch robots.txt; return list of (url, depth) pairs to seed crawl."""
        base = f"{self.parsed_base.scheme}://{self.base_host}"
        robots_url = f"{base}/robots.txt"
        self._verbose(f"Fetching robots.txt: {robots_url}")
        resp = fetch(robots_url, self.timeout)
        seed_crawl = []
        new_dirs = []

        if resp and resp.status_code == 200:
            for line in resp.text.splitlines():
                line = line.strip()
                if line.lower().startswith(("disallow:", "allow:")):
                    path = line.split(":", 1)[1].strip()
                    if path and not path.startswith("*"):
                        full = normalise_url(urljoin(base + "/", path.lstrip("/")))
                        if same_domain(full, self.base_host):
                            with self._lock:
                                self.resources_found.add(full)
                                new_dirs.extend(
                                    self._register_dirs_for_url_locked(full)
                                )
                elif line.lower().startswith("sitemap:"):
                    sm = line.split(":", 1)[1].strip()
                    if sm.startswith("//"):
                        sm = self.parsed_base.scheme + ":" + sm
                    c, d = self._process_sitemap(sm)
                    seed_crawl.extend(c)
                    new_dirs.extend(d)

        time.sleep(self.delay)
        return seed_crawl, new_dirs

    def _process_sitemap(self, sitemap_url: str):
        self._verbose(f"Fetching sitemap: {sitemap_url}")
        resp = fetch(sitemap_url, self.timeout)
        seed_crawl = []
        new_dirs = []
        if not resp or resp.status_code != 200:
            return seed_crawl, new_dirs

        locs = re.findall(r"<loc>\s*(.*?)\s*</loc>", resp.text, re.IGNORECASE)
        for loc in locs:
            loc = normalise_url(loc)
            if not same_domain(loc, self.base_host) or not loc.startswith("http"):
                continue
            with self._lock:
                self.resources_found.add(loc)
                new_dirs.extend(self._register_dirs_for_url_locked(loc))
                already_crawled = loc in self.crawled_urls

            if not already_crawled:
                ext = Path(urlparse(loc).path).suffix.lower()
                if not ext or ext in {".html", ".htm", ".php", ".asp", ".aspx"}:
                    seed_crawl.append((loc, 1))

        time.sleep(self.delay)
        return seed_crawl, new_dirs

    def _crawl_worker(self, url: str, depth: int):
        """Fetch one page, extract resources, return (new_pages, new_dirs)."""
        if STOP_EVENT.is_set():
            return [], []

        with self._lock:
            if url in self.crawled_urls or self.pages_crawled >= self.max_pages:
                return [], []
            self.crawled_urls.add(url)

        if self.verbose:
            self._verbose(f"Crawling [{depth}]: {url}")

        resp = fetch(url, self.timeout)
        if self.delay:
            time.sleep(self.delay)

        if STOP_EVENT.is_set():
            return [], []

        if not resp:
            with self._lock:
                self.crawl_errors += 1
            return [], []

        with self._lock:
            self.pages_crawled += 1

        if resp.status_code != 200:
            return [], []
        if "text/html" not in resp.headers.get("Content-Type", ""):
            return [], []

        try:
            body = resp.text
        except Exception:
            return [], []

        resources = self._extract_resources(body, url)

        new_pages = []
        new_dirs = []

        with self._lock:
            for r in resources:
                is_new = r not in self.resources_found
                if is_new:
                    self.resources_found.add(r)
                    if self.verbose:
                        pass

                new_dirs.extend(self._register_dirs_for_url_locked(r))

                if depth < self.depth:
                    ext = Path(urlparse(r).path).suffix.lower()
                    html_like = not ext or ext in {
                        ".html",
                        ".htm",
                        ".php",
                        ".asp",
                        ".aspx",
                        ".jsp",
                    }
                    if html_like and r not in self.crawled_urls:
                        new_pages.append((r, depth + 1))

            if is_directory_url(url):
                new_dirs.extend(self._register_dirs_for_url_locked(url))

        if self.verbose:
            for r in resources:
                self._verbose(f"Resource: {r}")

        return new_pages, new_dirs

    def _run_parallel_crawl(self, seeds: list) -> list:
        """
        BFS crawl using a thread pool.
        Returns the full list of discovered directory URLs to test.
        """
        p = self.palette
        all_dirs: list = []

        wave = list(seeds)
        wave_num = 0

        while wave:
            if STOP_EVENT.is_set():
                break

            wave_num += 1
            safe_print(p.dim(f"  crawl wave {wave_num}: {len(wave)} pages ..."))

            next_wave = []
            pool = ThreadPoolExecutor(max_workers=self.crawl_workers)
            try:
                futures = {
                    pool.submit(self._crawl_worker, url, dep): (url, dep)
                    for url, dep in wave
                }
                pending = set(futures)
                while pending:
                    done, pending = wait(
                        pending, timeout=0.1, return_when=FIRST_COMPLETED
                    )
                    if not done:
                        continue

                    for future in done:
                        try:
                            new_pages, new_dirs = future.result()
                        except Exception:
                            new_pages, new_dirs = [], []

                        next_wave.extend(new_pages)
                        all_dirs.extend(new_dirs)

                        with self._lock:
                            if self.pages_crawled >= self.max_pages:
                                pending.clear()
                                break

                    if STOP_EVENT.is_set():
                        pending.clear()
                        break

            except KeyboardInterrupt:
                STOP_EVENT.set()
                pool.shutdown(wait=False, cancel_futures=True)
                raise
            else:
                pool.shutdown(wait=True)

            seen = set()
            deduped = []
            with self._lock:
                for url, dep in next_wave:
                    if url not in self.crawled_urls and url not in seen:
                        seen.add(url)
                        deduped.append((url, dep))
            wave = deduped

            if self.pages_crawled >= self.max_pages:
                break

        return all_dirs

    def _test_worker(self, url: str):
        """Test one directory URL for open listing. Thread-safe."""
        if STOP_EVENT.is_set():
            return

        with self._lock:
            if url in self.dirs_tested:
                return
            self.dirs_tested.add(url)

        resp = fetch(url, self.timeout)
        if self.delay:
            time.sleep(self.delay)

        if STOP_EVENT.is_set():
            return

        code = resp.status_code if resp else "timeout"
        self._print("test", url, code)

        status = classify_response(resp)

        if status == "listing":
            self._print("listing", url, code)
            with self._lock:
                self.listings_found.append(url)
        elif status == "forbidden":
            self._print("forbidden", url, code)
            with self._lock:
                self.forbidden_paths.append(url)
        elif status == "error":
            with self._lock:
                self.errors += 1
            if self.verbose:
                self._print("error", url, code)

    def _run_parallel_tests(self, dirs: list):
        pool = ThreadPoolExecutor(max_workers=self.test_workers)
        try:
            futures = {pool.submit(self._test_worker, url): url for url in dirs}
            pending = set(futures)
            while pending:
                done, pending = wait(pending, timeout=0.1, return_when=FIRST_COMPLETED)
                if not done:
                    continue

                for future in done:
                    try:
                        future.result()
                    except Exception:
                        pass

                if STOP_EVENT.is_set():
                    pending.clear()
                    break
        except KeyboardInterrupt:
            STOP_EVENT.set()
            pool.shutdown(wait=False, cancel_futures=True)
            raise
        else:
            pool.shutdown(wait=True)

    def run(self):
        time.sleep(1)
        os.system("cls" if os.name == "nt" else "clear")
        p = self.palette
        start_time = datetime.now()

        print()

        safe_print(p.cyan(icon))
        time.sleep(1)
        safe_print(p.cyan("=" * 60))
        safe_print(p.cyan("  DirLens - Directory Listing Scanner"))
        safe_print(p.cyan("=" * 60))
        safe_print(p.white(f"  Target        : {self.target}"))
        safe_print(p.white(f"  Depth         : {self.depth}"))
        safe_print(p.white(f"  Max pages     : {self.max_pages}"))
        safe_print(p.white(f"  Crawl workers : {self.crawl_workers}"))
        safe_print(p.white(f"  Test workers  : {self.test_workers}"))
        safe_print(p.white(f"  Delay         : {self.delay}s"))
        safe_print(p.white(f"  Timeout       : {self.timeout}s"))
        safe_print(p.cyan("-" * 60))
        safe_print("")

        time.sleep(1)

        safe_print(p.white("[*] Phase 1 - robots.txt + sitemap.xml"))
        seed_crawl, init_dirs = self._process_robots()
        base = f"{self.parsed_base.scheme}://{self.base_host}"
        for spath in ("/sitemap.xml", "/sitemap_index.xml"):
            c, d = self._process_sitemap(base + spath)
            seed_crawl.extend(c)
            init_dirs.extend(d)

        seed_crawl.insert(0, (self.target, 0))

        seen = set()
        deduped_seed = []
        for url, dep in seed_crawl:
            if url not in seen:
                seen.add(url)
                deduped_seed.append((url, dep))

        safe_print(p.white("[*] Phase 2 - Crawling pages"))
        crawl_dirs = self._run_parallel_crawl(deduped_seed)

        all_dirs_set = set(init_dirs) | set(crawl_dirs)
        with self._lock:
            all_dirs_set |= self.queued_dirs

        safe_print(
            p.white(
                f"    {self.pages_crawled} pages crawled, "
                f"{len(self.resources_found)} resources found, "
                f"{len(all_dirs_set)} directories queued"
            )
        )

        safe_print(p.white("[*] Phase 3 - Testing directories for open listings"))
        safe_print("")
        self._run_parallel_tests(sorted(all_dirs_set))

        time.sleep(1)

        elapsed = (datetime.now() - start_time).total_seconds()
        safe_print("")
        safe_print(p.cyan("=" * 60))
        safe_print(p.cyan("  DirLens scan completed"))
        safe_print(p.cyan("=" * 60))
        safe_print(p.white(f"  Target             : {self.target}"))
        safe_print(p.white(f"  Pages crawled      : {self.pages_crawled}"))
        safe_print(p.white(f"  Resources found    : {len(self.resources_found)}"))
        safe_print(p.white(f"  Directories tested : {len(self.dirs_tested)}"))
        if self.listings_found:
            safe_print(p.green(f"  Listings found     : {len(self.listings_found)}"))
        else:
            safe_print(p.white(f"  Listings found     : 0"))
        safe_print(p.yellow(f"  Forbidden paths    : {len(self.forbidden_paths)}"))
        safe_print(p.white(f"  Errors             : {self.errors}"))
        safe_print(p.white(f"  Elapsed            : {elapsed:.1f}s"))
        safe_print(p.cyan("=" * 60))

        if self.listings_found:
            time.sleep(1.5)
            safe_print("")
            safe_print(p.green("  [!] Open directory listings:"))
            for u in self.listings_found:
                safe_print(p.green(f"      {u}"))

        report_data = {
            "meta": {
                "tool": "DirLens",
                "version": "1.1",
                "author": f"By {AUTHOR_NAME}",
                "github": AUTHOR_GITHUB_URL,
                "target": self.target,
                "scanned_at": start_time.isoformat(),
                "elapsed_seconds": round(elapsed, 2),
                "workers": self.crawl_workers,
            },
            "summary": {
                "pages_crawled": self.pages_crawled,
                "resources_found": len(self.resources_found),
                "directories_tested": len(self.dirs_tested),
                "listings_found": len(self.listings_found),
                "forbidden_paths": len(self.forbidden_paths),
                "errors": self.errors,
            },
            "listings": self.listings_found,
            "forbidden": self.forbidden_paths,
            "resources": sorted(self.resources_found),
            "dirs_tested": sorted(self.dirs_tested),
        }

        reports_dir = Path("reports")
        reports_dir.mkdir(exist_ok=True)
        ts = start_time.strftime("%Y%m%d_%H%M%S")
        safe_host = self.base_host.replace(":", "_")

        if self.json_report:
            jp = reports_dir / f"dirlens_{safe_host}_{ts}.json"
            jp.write_text(json.dumps(report_data, indent=2), encoding="utf-8")
            safe_print(p.white(f"\n  JSON report : {jp}"))

        if self.html_report:
            hp = reports_dir / f"dirlens_{safe_host}_{ts}.html"
            hp.write_text(_build_html_report(report_data), encoding="utf-8")
            safe_print(p.white(f"  HTML report : {hp}"))

        safe_print("")
        return report_data


def _build_html_report(data: dict) -> str:
    meta = data["meta"]
    summary = data["summary"]
    listings = data["listings"]
    forbidden = data["forbidden"]
    dirs_tested = data["dirs_tested"]

    def row(label, value, colour=""):
        style = f'style="color:{colour}"' if colour else ""
        return f'<tr><td class="lbl">{label}</td><td {style}><strong>{value}</strong></td></tr>'

    def url_rows(urls, colour):
        if not urls:
            return '<tr><td colspan="2" style="color:rgb(136, 136, 136)">None found</td></tr>'
        return "\n".join(
            f'<tr><td colspan="2"><a href="{u}" style="color:{colour}">{u}</a></td></tr>'
            for u in urls
        )

    badge = (
        f'<span style="background:rgb(26, 156, 62);color:rgb(255, 255, 255);padding:2px 8px;border-radius:4px">'
        f'{summary["listings_found"]} FOUND</span>'
        if summary["listings_found"]
        else '<span style="color:rgb(136, 136, 136)">0</span>'
    )
    dirs_html = "".join(f'<tr><td class="dir-url">{u}</td></tr>' for u in dirs_tested)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>DirLens Report - {meta['target']}</title>
<style>
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{font-family:'Courier New',monospace;background:rgb(13, 13, 13);color:rgb(212, 212, 212);font-size:14px;padding:24px}}
  h1{{color:rgb(0, 191, 255);font-size:22px;margin-bottom:4px;letter-spacing:1px}}
  h2{{color:rgb(0, 191, 255);font-size:15px;margin:24px 0 8px;text-transform:uppercase;letter-spacing:2px;border-bottom:1px solid rgb(51, 51, 51);padding-bottom:4px}}
  .byline{{color:rgb(212, 212, 212);font-size:13px;margin:4px 0 10px}}
  .byline a{{color:rgb(0, 191, 255);text-decoration:none;font-weight:bold}}
  .meta{{color:rgb(136, 136, 136);font-size:12px;margin-bottom:20px}}
  table{{width:100%;border-collapse:collapse;margin-bottom:12px}}
  td{{padding:6px 10px;border-bottom:1px solid rgb(34, 34, 34)}}
  td.lbl{{color:rgb(136, 136, 136);width:220px}}
  td.dir-url{{font-size:12px;color:rgb(170, 170, 170);word-break:break-all}}
  .section{{background:rgb(20, 20, 20);border:1px solid rgb(34, 34, 34);border-radius:6px;padding:16px;margin-bottom:20px}}
  a{{word-break:break-all}}
  .banner{{color:rgb(13, 13, 13);background:rgb(0, 191, 255);padding:6px 16px;border-radius:4px;display:inline-block;font-weight:bold;margin-bottom:20px;letter-spacing:2px}}
</style>
</head>
<body>
<div class="banner">DirLens</div>
<h1>Directory Listing Scan Report</h1>
<p class="byline">{meta['author']} &nbsp;|&nbsp; <a href="{meta['github']}">{meta['github']}</a></p>
<p class="meta">Target: {meta['target']} &nbsp;|&nbsp; Scanned: {meta['scanned_at']} &nbsp;|&nbsp; Elapsed: {meta['elapsed_seconds']}s &nbsp;|&nbsp; Workers: {meta['workers']}</p>
<div class="section"><h2>Summary</h2><table>
  {row("Pages crawled",      summary["pages_crawled"])}
  {row("Resources found",    summary["resources_found"])}
  {row("Directories tested", summary["directories_tested"])}
  <tr><td class="lbl">Listings found</td><td>{badge}</td></tr>
  {row("Forbidden paths",    summary["forbidden_paths"], "rgb(200, 166, 0)")}
  {row("Errors",             summary["errors"])}
</table></div>
<div class="section"><h2>Open Directory Listings</h2><table>{url_rows(listings, "rgb(26, 156, 62)")}</table></div>
<div class="section"><h2>Forbidden Paths (403)</h2><table>{url_rows(forbidden, "rgb(200, 166, 0)")}</table></div>
<div class="section"><h2>All Directories Tested ({len(dirs_tested)})</h2><table>{dirs_html}</table></div>
</body></html>
"""


class DirLensArgumentParser(argparse.ArgumentParser):
    def format_usage(self):
        return "Usage: python dirlens.py <url> [options]\n"

    def format_help(self):
        return f"""
============================================================
DirLens
{AUTHOR_GITHUB_URL}
============================================================

Authorized directory listing scanner
No bruteforce, no wordlists, only discovered paths.

Usage:
  python dirlens.py <url> [options]

Target:
  url                    Target URL, example: https://example.com

Scan options:
  --depth N              Crawl depth. Default: 2
  --max-pages N          Maximum pages to crawl. Default: 50
  --workers N            Parallel crawl workers. Default: {DEFAULT_CRAWL_WORKERS}
  --delay SECONDS        Delay between requests per worker. Default: 0
  --timeout SECONDS      HTTP request timeout. Default: 8

Output options:
  --json                 Save JSON report to reports/
  --html                 Save HTML report to reports/
  --no-color             Disable coloured terminal output
  --verbose              Show debug output

Help:
  -h, --help             Show this help screen

Examples:
  python dirlens.py https://example.com
  python dirlens.py https://example.com --depth 3 --max-pages 200 --json --html
  python dirlens.py https://example.com --workers 20 --delay 0 --timeout 6
  python dirlens.py https://example.com --no-color --json
""".lstrip()


def build_parser() -> argparse.ArgumentParser:
    parser = DirLensArgumentParser(
        prog="dirlens",
        description="DirLens - Authorized directory listing scanner. "
        "No bruteforce, no wordlists, only discovered paths.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python dirlens.py https://example.com
  python dirlens.py https://example.com --depth 3 --max-pages 200 --json --html
  python dirlens.py https://example.com --workers 20 --delay 0 --timeout 6
  python dirlens.py https://example.com --no-color --json
        """,
    )
    parser.add_argument("url", help="Target URL (e.g. https://example.com)")
    parser.add_argument("--depth", type=int, default=2, help="Crawl depth (default: 2)")
    parser.add_argument(
        "--delay",
        type=float,
        default=0.0,
        help="Seconds to wait between requests per worker (default: 0)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=8,
        help="HTTP request timeout in seconds (default: 8)",
    )
    parser.add_argument(
        "--max-pages",
        type=int,
        default=50,
        dest="max_pages",
        help="Maximum pages to crawl (default: 50)",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=DEFAULT_CRAWL_WORKERS,
        help=f"Number of parallel crawl workers (default: {DEFAULT_CRAWL_WORKERS})",
    )
    parser.add_argument(
        "--no-color", action="store_true", help="Disable coloured output"
    )
    parser.add_argument("--verbose", action="store_true", help="Verbose debug output")
    parser.add_argument(
        "--json", action="store_true", help="Save JSON report to reports/"
    )
    parser.add_argument(
        "--html", action="store_true", help="Save HTML report to reports/"
    )
    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    parsed = urlparse(args.url)
    if not parsed.scheme or not parsed.netloc:
        print(f"[ERROR] Invalid URL: {args.url}", file=sys.stderr)
        sys.exit(1)
    if parsed.scheme not in ("http", "https"):
        print("[ERROR] Only http/https are supported.", file=sys.stderr)
        sys.exit(1)
    if args.depth < 0:
        print("[ERROR] --depth must be >= 0", file=sys.stderr)
        sys.exit(1)
    if args.delay < 0:
        print("[ERROR] --delay must be >= 0", file=sys.stderr)
        sys.exit(1)
    if args.timeout < 1:
        print("[ERROR] --timeout must be >= 1", file=sys.stderr)
        sys.exit(1)
    if args.max_pages < 1:
        print("[ERROR] --max-pages must be >= 1", file=sys.stderr)
        sys.exit(1)
    if args.workers < 1:
        print("[ERROR] --workers must be >= 1", file=sys.stderr)
        sys.exit(1)

    try:
        STOP_EVENT.clear()
        DirLens(args).run()
    except KeyboardInterrupt:
        STOP_EVENT.set()
        p = Palette(enabled=not args.no_color)
        safe_print("")
        safe_print(p.red("[!] Scan interrupted !"))
        print()
        os._exit(130)


if __name__ == "__main__":
    main()
