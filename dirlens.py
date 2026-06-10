"""
DirLens - Directory Listing Scanner
Detects open directory listings using only paths discovered on the target site.
No bruteforce. No wordlists. No invented paths.
"""

import argparse
import gzip
import html as html_utils
import io
import json
import re
import sys
import os
import time
import threading
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from datetime import datetime
from pathlib import Path
from urllib.parse import urljoin, urlparse, urlunparse
import xml.etree.ElementTree as ET

import requests
from bs4 import BeautifulSoup
from colorama import Fore, Style, init as colorama_init

USER_AGENT = "DirLens - Directory Listing Scanner"
AUTHOR_NAME = "LTX"
AUTHOR_GITHUB_URL = "https://github.com/LTX128/Dirlens"

DEFAULT_CRAWL_WORKERS = 10
DEFAULT_TEST_WORKERS = 20
DEFAULT_RETRIES = 1
DEFAULT_TIMEOUT = 8

SPEED_CRAWL_WORKERS = 64
SPEED_TEST_WORKERS = 192
SPEED_RETRIES = 0
SPEED_TIMEOUT = 4
SPEED_SITEMAP_TIMEOUT = 2
SPEED_SITEMAP_WORKER_LIMIT = 64
SPEED_MAX_ADAPTIVE_DELAY = 0.25

SITEMAP_CANDIDATES = [
    "/sitemap.xml",
    "/sitemap_index.xml",
    "/sitemap-index.xml",
    "/sitemapindex.xml",
    "/sitemap.xml.gz",
    "/sitemap_index.xml.gz",
    "/sitemap-index.xml.gz",
    "/sitemapindex.xml.gz",
    "/sitemaps.xml",
    "/sitemaps.xml.gz",
    "/sitemap.txt",
    "/sitemap-news.xml",
    "/sitemap-news.xml.gz",
    "/sitemap-products.xml",
    "/sitemap-products.xml.gz",
    "/sitemap-categories.xml",
    "/sitemap-pages.xml",
    "/sitemap-posts.xml",
    "/sitemap-blog.xml",
    "/sitemap-images.xml",
    "/sitemap-image.xml",
    "/sitemap-videos.xml",
    "/sitemap-video.xml",
    "/sitemap1.xml",
    "/sitemap2.xml",
    "/sitemap3.xml",
    "/sitemap-0.xml",
    "/sitemap-1.xml",
    "/sitemap-2.xml",
    "/post-sitemap.xml",
    "/page-sitemap.xml",
    "/category-sitemap.xml",
    "/product-sitemap.xml",
    "/wp-sitemap.xml",
    "/wp-sitemap-posts-post-1.xml",
    "/wp-sitemap-posts-page-1.xml",
    "/wp-sitemap-taxonomies-category-1.xml",
    "/news-sitemap.xml",
    "/video-sitemap.xml",
    "/image-sitemap.xml",
    "/mobile-sitemap.xml",
    "/en/sitemap.xml",
    "/fr/sitemap.xml",
    "/de/sitemap.xml",
    "/es/sitemap.xml",
    "/sitemap/sitemap.xml",
    "/sitemap/sitemap-index.xml",
    "/sitemap/sitemap_index.xml",
    "/sitemaps/sitemap.xml",
    "/sitemaps/sitemap-index.xml",
    "/sitemaps/sitemap_index.xml",
]

HTML_LIKE_EXTENSIONS = {
    ".html",
    ".htm",
    ".php",
    ".asp",
    ".aspx",
    ".jsp",
    ".xhtml",
    ".shtml",
}

SITEMAP_RECURSION_LIMIT = 12

KNOWN_PUBLIC_FILENAMES = {
    "robots.txt",
    "sitemap.xml",
    "sitemap_index.xml",
    "sitemap-index.xml",
    "wp-sitemap.xml",
    "security.txt",
    "humans.txt",
    "ads.txt",
    "app-ads.txt",
    "favicon.ico",
    "rss.xml",
    "atom.xml",
    "feed.xml",
}

EXPOSED_FILE_EXTENSIONS = {
    ".bak",
    ".backup",
    ".bin",
    ".conf",
    ".config",
    ".csv",
    ".db",
    ".dump",
    ".env",
    ".htaccess",
    ".htpasswd",
    ".ini",
    ".json",
    ".log",
    ".old",
    ".sql",
    ".sqlite",
    ".sqlite3",
    ".txt",
    ".tar.gz",
    ".xml",
    ".yaml",
    ".yml",
    ".zip",
    ".7z",
}

EXPOSED_CONTENT_TYPES = {
    "application/json",
    "application/x-ndjson",
    "application/xml",
    "application/yaml",
    "text/csv",
    "text/plain",
    "text/xml",
    "text/yaml",
}

EXACT_SENSITIVE_PATH_SUFFIXES = {
    "/.ds_store",
    "/.env",
    "/.env.bak",
    "/.env.dev",
    "/.env.local",
    "/.env.production",
    "/.git/config",
    "/.git/head",
    "/.git/index",
    "/.htaccess",
    "/.htpasswd",
    "/.svn/entries",
    "/.svn/wc.db",
}

COMMON_PATHS = [
    "/contact", "/contacts", "/contact-us", "/contactus", "/contact.html",
    "/about", "/about-us", "/aboutus", "/about.html",
    "/home", "/index", "/index.html", "/index.php",
    "/login", "/signin", "/sign-in", "/logout", "/register", "/signup",
    "/search", "/sitemap", "/faq", "/help", "/support",
    "/news", "/blog", "/posts", "/articles", "/press", "/events",
    "/services", "/products", "/portfolio", "/projects", "/work",
    "/team", "/staff", "/careers", "/jobs", "/legal", "/privacy",
    "/terms", "/tos", "/cgv", "/mentions-legales", "/mentions_legales",
    "/404", "/error",
    "/admin", "/administrator", "/dashboard", "/panel", "/backend",
    "/wp-admin", "/wp-login.php", "/wp-content", "/wp-includes",
    "/api", "/api/v1", "/api/v2", "/rest", "/graphql",
    "/assets", "/static", "/public", "/media", "/files", "/uploads",
    "/images", "/img", "/css", "/js", "/fonts", "/icons", "/svg",
    "/documents", "/docs", "/doc", "/download", "/downloads",
    "/data", "/db", "/database", "/backup", "/backups", "/bak",
    "/cache", "/temp", "/tmp", "/logs", "/log",
    "/config", "/conf", "/settings", "/setup", "/install",
    "/includes", "/inc", "/lib", "/libs", "/vendor", "/node_modules",
    "/src", "/dist", "/build", "/out", "/bin",
    "/cgi-bin", "/scripts", "/resources", "/content",
    "/user", "/users", "/account", "/accounts", "/profile",
    "/old", "/new", "/dev", "/test", "/demo", "/staging",
    "/v1", "/v2", "/version",
    "/admin.php", "/admin.html", "/admin/login", "/admin/login.php",
    "/phpmyadmin", "/pma", "/adminer.php", "/manager", "/console",
    "/swagger", "/swagger-ui", "/swagger-ui.html", "/swagger.json",
    "/api-docs", "/docs/api", "/openapi.json", "/redoc",
    "/actuator", "/actuator/env", "/actuator/health", "/server-status",
    "/server-info",
    "/.env.local", "/.env.production", "/.env.dev", "/.env.bak",
    "/.git/config", "/.git/HEAD", "/.svn", "/.DS_Store",
    "/composer.json", "/composer.lock", "/package.json", "/package-lock.json",
    "/yarn.lock", "/pnpm-lock.yaml", "/config.php", "/configuration.php",
    "/settings.php", "/web.config", "/appsettings.json",
    "/backup.zip", "/backup.tar.gz", "/backup.sql", "/dump.sql",
    "/database.sql", "/db.sql", "/site.zip", "/www.zip",
    "/error.log", "/access.log", "/debug.log", "/laravel.log",
    "/storage/logs/laravel.log",
    "/.well-known", "/.well-known/security.txt", "/security.txt",
    "/robots.txt", "/humans.txt", "/ads.txt", "/app-ads.txt",
    "/crossdomain.xml", "/clientaccesspolicy.xml",
    "/.git", "/.env", "/.htaccess",
    "/feed", "/feed.xml", "/rss", "/rss.xml", "/atom.xml",
    "/health", "/healthcheck", "/ping", "/status", "/version.txt",
]

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

STRONG_DIRECTORY_LISTING_SIGNATURES = [
    re.compile(r"<title>\s*Index of\b", re.IGNORECASE),
    re.compile(r"<h1>\s*Index of\b", re.IGNORECASE),
    re.compile(r"<title>\s*Directory listing for\b", re.IGNORECASE),
    re.compile(r"<h1>\s*Directory listing for\b", re.IGNORECASE),
    re.compile(r"Name\s+Last modified\s+Size\s+Description", re.IGNORECASE),
]

FALSE_POSITIVE_SIGNATURES = [
    re.compile(r"\bpage not found\b", re.IGNORECASE),
    re.compile(r"\bnot found\b", re.IGNORECASE),
    re.compile(r"access denied", re.IGNORECASE),
    re.compile(r"forbidden", re.IGNORECASE),
    re.compile(r"error 4[0-9]{2}", re.IGNORECASE),
    re.compile(r"cloudflare", re.IGNORECASE),
    re.compile(r"just a moment", re.IGNORECASE),
    re.compile(r"<title>Error</title>", re.IGNORECASE),
    re.compile(r"<title>403", re.IGNORECASE),
    re.compile(r"<title>404", re.IGNORECASE),
]

LOGIN_WARNING_SIGNATURES = [
    re.compile(r"\bwp-login\b", re.IGNORECASE),
    re.compile(r"\blog[\s_-]?in\b", re.IGNORECASE),
    re.compile(r"\bsign[\s_-]?in\b", re.IGNORECASE),
    re.compile(r"\bsignin\b", re.IGNORECASE),
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
_fetch_error_lock = threading.Lock()
_fetch_errors = {}

icon = r"""
██████  ██ ██████  ██      ███████ ███    ██ ███████ 
██   ██ ██ ██   ██ ██      ██      ████   ██ ██      
██   ██ ██ ██████  ██      █████   ██ ██  ██ ███████ 
██   ██ ██ ██   ██ ██      ██      ██  ██ ██      ██ 
██████  ██ ██   ██ ███████ ███████ ██   ████ ███████ 
                                                     
        https://github.com/LTX128/Dirlens
"""

ascii_icon = r"""
 ____  _      _                    
|  _ \(_)_ __| |    ___ _ __  ___ 
| | | | | '__| |   / _ \ '_ \/ __|
| |_| | | |  | |__|  __/ | | \__ \
|____/|_|_|  |_____\___|_| |_|___/

        https://github.com/LTX128/Dirlens
"""


def terminal_supports(text: str) -> bool:
    try:
        text.encode(sys.stdout.encoding or "utf-8")
        return True
    except UnicodeEncodeError:
        return False


def _get_thread_session(timeout: int) -> requests.Session:
    """Return (or create) a per-thread requests.Session."""
    if not hasattr(_thread_local, "session"):
        s = requests.Session()
        s.headers.update(
            {
                "User-Agent": USER_AGENT,
                "Accept": "text/html,application/xhtml+xml,application/xml,text/plain,*/*;q=0.8",
            }
        )
        s.max_redirects = 5
        _thread_local.session = s
    return _thread_local.session


def request_timeout(timeout: int) -> tuple:
    if timeout <= SPEED_TIMEOUT:
        connect_timeout = min(1.5, max(0.75, timeout / 3))
    else:
        connect_timeout = min(5, max(2, timeout / 2))
    read_timeout = max(timeout, connect_timeout)
    return connect_timeout, read_timeout


def fetch_error_reason(exc: Exception) -> str:
    if isinstance(exc, requests.exceptions.Timeout):
        return "timeout"
    if isinstance(exc, requests.exceptions.TooManyRedirects):
        return "redirects"
    if isinstance(exc, requests.exceptions.SSLError):
        return "ssl"
    if isinstance(exc, requests.exceptions.ConnectionError):
        return "connect"
    if isinstance(exc, requests.exceptions.RequestException):
        return "request"
    return "error"


def set_fetch_error(url: str, reason: str):
    with _fetch_error_lock:
        _fetch_errors[url] = reason


def clear_fetch_error(url: str):
    with _fetch_error_lock:
        _fetch_errors.pop(url, None)


def get_fetch_error(url: str) -> str:
    with _fetch_error_lock:
        return _fetch_errors.get(url, "error")


def fetch(url: str, timeout: int, retries: int = DEFAULT_RETRIES) -> "requests.Response | None":
    """Fetch a URL using the calling thread's session."""
    session = _get_thread_session(timeout)
    attempts = max(0, retries) + 1
    last_reason = "error"
    for attempt in range(attempts):
        try:
            resp = session.get(
                url,
                timeout=request_timeout(timeout),
                allow_redirects=True,
                stream=False,
            )
            clear_fetch_error(url)
            return resp
        except Exception as exc:
            last_reason = fetch_error_reason(exc)
            if last_reason in {"redirects", "ssl"} or attempt >= attempts - 1:
                break
            time.sleep(min(1.5, 0.25 * (attempt + 1)))

    set_fetch_error(url, last_reason)
    return None


_print_lock = threading.Lock()
_status_line_len = 0
_status_line_active = False
_status_line_text = ""
_CLEAR_LINE = "\x1b[K"
_CLEAR_WHOLE_LINE = "\x1b[2K"


def _console_text(text: str) -> str:
    encoding = sys.stdout.encoding or "utf-8"
    try:
        text.encode(encoding)
        return text
    except UnicodeEncodeError:
        return text.encode(encoding, errors="replace").decode(encoding)


def _clear_status_line_locked(deactivate: bool = True):
    global _status_line_len, _status_line_active, _status_line_text
    if not _status_line_active:
        return
    sys.stdout.write("\r" + _CLEAR_WHOLE_LINE)
    if deactivate:
        _status_line_len = 0
        _status_line_active = False
        _status_line_text = ""


def _redraw_status_line_locked():
    global _status_line_len
    if not _status_line_active or not _status_line_text:
        return
    sys.stdout.write("\r" + _status_line_text + _CLEAR_LINE)
    _status_line_len = max(_status_line_len, len(_status_line_text))
    sys.stdout.flush()


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
        keep_status = _status_line_active and bool(_status_line_text)
        if keep_status:
            _clear_status_line_locked(deactivate=True)
        print(_console_text(str(line)), flush=False)
        sys.stdout.flush()


def safe_status(line: str, done: bool = False):
    """Thread-safe single-line status update."""
    global _status_line_len, _status_line_active, _status_line_text
    text = _console_text(str(line))
    with _print_lock:
        sys.stdout.write("\r" + text + _CLEAR_LINE)
        if done:
            sys.stdout.write("\n")
            _status_line_len = 0
            _status_line_active = False
            _status_line_text = ""
        else:
            _status_line_len = max(_status_line_len, len(text))
            _status_line_active = True
            _status_line_text = text
        sys.stdout.flush()


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


def local_xml_name(tag: str) -> str:
    """Return an XML tag/attribute local name without namespace noise."""
    if not tag:
        return ""
    if "}" in tag:
        tag = tag.rsplit("}", 1)[1]
    if ":" in tag:
        tag = tag.rsplit(":", 1)[1]
    return tag.lower()


def element_attr(element: ET.Element, attr_name: str) -> str:
    for key, value in element.attrib.items():
        if local_xml_name(key) == attr_name:
            return value
    return ""


def append_unique(items: list, value: str):
    if value and value not in items:
        items.append(value)


def canonical_result_url(url: str) -> str:
    parsed = urlparse(url.strip())
    path = parsed.path or "/"
    if path != "/":
        path = path.rstrip("/")
        if not path:
            path = "/"
    return urlunparse(
        (
            parsed.scheme.lower(),
            parsed.netloc.lower(),
            path,
            parsed.params,
            parsed.query,
            "",
        )
    ).rstrip("?")


def append_unique_result(items: list, url: str):
    canonical = canonical_result_url(url)
    if not canonical or canonical in items:
        return False
    items.append(canonical)
    return True


def dedupe_result_urls(urls: list) -> list:
    result = []
    for url in urls:
        append_unique_result(result, url)
    return result


def same_domain(url: str, base_host: str) -> bool:
    return urlparse(url).netloc.lower() == base_host.lower()


def is_http_url(url: str) -> bool:
    return urlparse(url).scheme in ("http", "https")


def is_html_like_url(url: str) -> bool:
    ext = Path(urlparse(url).path).suffix.lower()
    return not ext or ext in HTML_LIKE_EXTENSIONS


def effective_sensitive_file_marker(path: str) -> str:
    path = path.rstrip("/")
    leaf = path.rsplit("/", 1)[-1].lower() if path else ""
    ext = Path(path).suffix.lower()
    lower_path = path.lower()
    if ext:
        return ext
    if leaf in EXPOSED_FILE_EXTENSIONS:
        return leaf
    if any(lower_path.endswith(suffix) for suffix in EXACT_SENSITIVE_PATH_SUFFIXES):
        return "<exact-sensitive>"
    return ""


def should_probe_slash_variant(url: str) -> bool:
    path = urlparse(url).path.rstrip("/")
    if not path or path == "/":
        return False
    return not effective_sensitive_file_marker(path)


def looks_like_sitemap_url(url: str) -> bool:
    path = urlparse(url).path.lower()
    name = path.rsplit("/", 1)[-1]
    if not name:
        return False
    if name in {"sitemap", "sitemaps", "sitemap.xml", "sitemap.txt"}:
        return True
    if "sitemap" not in name:
        return False
    return path.endswith((".xml", ".xml.gz", ".txt", ".gz")) or "." not in name


def parent_directories(url: str) -> list:
    parsed = urlparse(url)
    path = parsed.path
    path_no_slash = path.rstrip("/")
    leaf = path_no_slash.rsplit("/", 1)[-1] if path_no_slash else ""

    candidates = []
    marker = effective_sensitive_file_marker(path_no_slash)
    if leaf and (not marker or marker in EXPOSED_FILE_EXTENSIONS or marker == "<exact-sensitive>"):
        exact = urlunparse((parsed.scheme, parsed.netloc, path_no_slash, "", "", ""))
        append_unique(candidates, exact)
        if not marker:
            slash = urlunparse((parsed.scheme, parsed.netloc, path_no_slash + "/", "", "", ""))
            append_unique(candidates, slash)

    parts = path.rstrip("/").split("/")

    if parts and ("." in parts[-1] or marker):
        parts = parts[:-1]

    dirs = candidates
    for i in range(len(parts), 0, -1):
        dir_path = "/".join(parts[:i]) + "/"
        if not dir_path.startswith("/"):
            dir_path = "/" + dir_path
        append_unique(dirs, urlunparse((parsed.scheme, parsed.netloc, dir_path, "", "", "")))

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

    hits = sum(1 for p in DIRECTORY_LISTING_SIGNATURES if p.search(body))
    strong_hit = any(p.search(body) for p in STRONG_DIRECTORY_LISTING_SIGNATURES)
    listing_layout = re.search(
        r"Parent Directory|Last modified|<pre\b|<table\b|<ul\b|<li>\s*<a\s+href=",
        body,
        re.IGNORECASE,
    )

    if hits >= 2 or (strong_hit and listing_layout):
        return True

    for pattern in FALSE_POSITIVE_SIGNATURES:
        if pattern.search(body):
            return False

    return False


def is_known_public_path(url: str) -> bool:
    path = urlparse(url).path.lower().rstrip("/")
    name = path.rsplit("/", 1)[-1]
    if name in KNOWN_PUBLIC_FILENAMES:
        return True
    return looks_like_sitemap_url(url)


def is_interesting_exposure(response: "requests.Response") -> bool:
    if response.status_code != 200:
        return False
    url = response.url
    if is_known_public_path(url):
        return False

    parsed = urlparse(url)
    path = parsed.path or "/"
    if path == "/":
        return False

    ext = effective_sensitive_file_marker(path)
    ctype = response.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()

    if ext in EXPOSED_FILE_EXTENSIONS or ext == "<exact-sensitive>":
        return True
    if ctype in EXPOSED_CONTENT_TYPES:
        return True
    if not ext and ctype and "html" not in ctype:
        return True

    return False


def has_login_warning_signal(response: "requests.Response | None") -> bool:
    if response is None or response.status_code != 200:
        return False
    ct = response.headers.get("Content-Type", "")
    if "text/html" not in ct and "text/" not in ct:
        return False
    try:
        body = response.text[:40_000]
    except Exception:
        return False
    return any(pattern.search(body) for pattern in LOGIN_WARNING_SIGNATURES)


def classify_response(response: "requests.Response | None") -> str:
    if response is None:
        return "error"
    code = response.status_code
    if code in (403, 401, 407):
        return "forbidden"
    if code == 200:
        if is_directory_listing(response):
            return "listing"
        if is_interesting_exposure(response):
            return "exposed"
        return "clean"
    return "error"


class DirLens:
    def __init__(self, args: argparse.Namespace):
        self.target = normalise_url(args.url)
        self.parsed_base = urlparse(self.target)
        self.base_host = self.parsed_base.netloc.lower()
        self.speed = args.speed
        self.depth = args.depth
        self.delay = 0.0 if self.speed else args.delay
        if self.speed and args.timeout == DEFAULT_TIMEOUT:
            self.timeout = SPEED_TIMEOUT
        else:
            self.timeout = args.timeout
        if self.speed and args.retries == DEFAULT_RETRIES:
            self.retries = SPEED_RETRIES
        else:
            self.retries = args.retries
        self.max_pages = args.max_pages
        self.crawl_workers = (
            max(args.workers, SPEED_CRAWL_WORKERS) if self.speed else args.workers
        )
        self.test_workers = (
            max(args.workers * 2, SPEED_TEST_WORKERS)
            if self.speed
            else args.workers * 2
        )
        self.verbose = args.verbose
        self.no_color = args.no_color
        self.quiet = args.quiet
        self.no_common = getattr(args, "no_common", False)
        self.json_report = args.json
        self.html_report = args.html

        self.palette = Palette(enabled=not self.no_color)
        self.ui_pause = not self.speed
        self.clear_screen = True

        self._lock = threading.Lock()

        self.pages_crawled: int = 0
        self.resources_found: set = set()
        self.crawled_urls: set = set()

        self.dirs_tested: set = set()
        self.queued_dirs: set = set()

        self.listings_found: list = []
        self.exposed_paths: list = []
        self.forbidden_paths: list = []
        self.login_warning_paths: list = []
        self.errors: int = 0
        self.crawl_errors: int = 0
        self.sitemaps_checked: int = 0
        self.sitemaps_loaded: int = 0
        self.sitemaps_seen: set = set()
        self.rate_limit_hits: int = 0
        self.timeout_hits: int = 0
        self._speed_pressure_score: int = 0
        self._speed_pressure_until: float = 0.0

    def _tag(self, status: str) -> str:
        p = self.palette
        return {
            "listing": p.green("[FOUND]"),
            "exposed": p.yellow("[EXPOSED]"),
            "forbidden": p.yellow("[403]"),
            "test": p.red("[TEST]"),
            "error": p.dim("[ERR]"),
            "crawl": p.dim("[CRAWL]"),
        }.get(status, p.dim("[---]"))

    def _code_tag(self, code) -> str:
        p = self.palette
        text = f"[{code}]"
        if isinstance(code, str):
            if code in {"timeout", "connect", "ssl", "redirects"}:
                return p.red(text)
            return p.dim(text)
        if 200 <= code < 400:
            return p.green(text)
        if 400 <= code < 500:
            return p.yellow(text)
        if code >= 500:
            return p.red(text)
        return p.dim(text)

    def _print(self, status: str, url: str, code=None):
        if self.quiet and status not in ("listing", "exposed", "forbidden"):
            return
        code_text = f" {self._code_tag(code)}" if code is not None else ""
        safe_print(f"{self._tag(status)}{code_text} {url}")

    def _verbose(self, msg: str):
        if self.verbose and not self.quiet:
            safe_print(self.palette.dim(f"  > {msg}"))

    def _ui_sleep(self, seconds: float):
        if self.ui_pause:
            time.sleep(seconds)

    def _speed_gate(self):
        if not self.speed:
            return
        with self._lock:
            delay = max(0.0, self._speed_pressure_until - time.monotonic())
        if delay > 0:
            time.sleep(min(delay, SPEED_MAX_ADAPTIVE_DELAY))

    def _note_speed_pressure(self, code):
        if not self.speed:
            return

        is_timeout = code in {"timeout", "connect"}
        is_rate_limited = code == 429
        with self._lock:
            if is_rate_limited:
                self.rate_limit_hits += 1
                self._speed_pressure_score = min(20, self._speed_pressure_score + 4)
            elif is_timeout:
                self.timeout_hits += 1
                self._speed_pressure_score = min(20, self._speed_pressure_score + 2)
            elif isinstance(code, int) and code < 500:
                self._speed_pressure_score = max(0, self._speed_pressure_score - 1)

            if self._speed_pressure_score:
                delay = min(
                    SPEED_MAX_ADAPTIVE_DELAY,
                    0.015 * self._speed_pressure_score,
                )
                self._speed_pressure_until = time.monotonic() + delay
            else:
                self._speed_pressure_until = 0.0

    def _progress_bar(self, completed: int, total: int, width: int = 28) -> str:
        """Build a Unicode block progress bar."""
        if total <= 0:
            bar = "░" * width
            return f"[{bar}]   0%"
        bounded = min(max(completed, 0), total)
        ratio = bounded / total
        percent = int(ratio * 100)

        eighths = ["", "▏", "▎", "▍", "▌", "▋", "▊", "▉", "█"]
        filled_cells = ratio * width
        full = int(filled_cells)
        partial_idx = int((filled_cells - full) * 8)

        if full >= width:
            bar = "█" * width
        else:
            bar = "█" * full
            if partial_idx > 0:
                bar += eighths[partial_idx]
                bar += "░" * (width - full - 1)
            else:
                bar += "░" * (width - full)

        return f"[{bar}] {percent:3d}%"

    _phase_start: dict = {}
    _phase_last_completed: dict = {}
    _phase_last_time: dict = {}

    def _progress(self, label: str, completed: int, total: int, extra: str = "", done: bool = False):
        if self.quiet:
            return

        p = self.palette
        now = time.monotonic()

        if label not in self._phase_start:
            self._phase_start[label] = now
            self._phase_last_completed[label] = 0
            self._phase_last_time[label] = now

        elapsed_phase = now - self._phase_start[label]

        delta_completed = completed - self._phase_last_completed[label]
        delta_time = now - self._phase_last_time[label]
        if delta_time > 0 and delta_completed >= 0:
            speed = delta_completed / delta_time
        else:
            speed = 0.0
        self._phase_last_completed[label] = completed
        self._phase_last_time[label] = now

        if total > 0 and completed > 0 and not done:
            remaining = total - completed
            avg_speed = completed / elapsed_phase if elapsed_phase > 0 else 0
            if avg_speed > 0:
                eta_sec = remaining / avg_speed
                if eta_sec < 60:
                    eta_str = f"eta {int(eta_sec)}s"
                else:
                    eta_str = f"eta {int(eta_sec // 60)}m{int(eta_sec % 60):02d}s"
            else:
                eta_str = "eta --"
        elif done:
            eta_str = f"done in {elapsed_phase:.1f}s"
        else:
            eta_str = ""

        if speed > 0 and not done:
            if speed >= 1:
                speed_str = f"{speed:.0f} req/s"
            else:
                speed_str = f"{speed:.2f} req/s"
        else:
            speed_str = ""

        bar_raw = self._progress_bar(completed, total)
        if done:
            bar_str = p.green(bar_raw)
        elif "Phase 3" in label or "test" in label.lower():
            bar_str = p.cyan(bar_raw)
        elif "Phase 2" in label or "crawl" in label.lower():
            bar_str = p.yellow(bar_raw)
        else:
            bar_str = p.white(bar_raw)

        count_str = f"{completed}/{total}" if total > 0 else ""

        meta_parts = []
        if speed_str:
            meta_parts.append(speed_str)
        if eta_str:
            meta_parts.append(eta_str)
        if extra:
            meta_parts.append(extra)
        meta = " · ".join(meta_parts)

        short_label = label
        if not done:
            label_display = p.dim(f"  {short_label:<32}")
        else:
            label_display = p.dim(f"  {short_label:<32}")

        line = f"{label_display} {bar_str} {count_str}"
        if meta:
            line += f"  {p.dim(meta)}"

        safe_status(line, done=done)

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
        self._speed_gate()
        resp = fetch(robots_url, self.timeout, self.retries)
        self._note_speed_pressure(
            resp.status_code if resp is not None else get_fetch_error(robots_url)
        )
        seed_crawl = []
        new_dirs = []

        if resp is not None and resp.status_code == 200:
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

    def _decode_sitemap_response(self, resp: "requests.Response") -> str:
        """Decode a sitemap response, transparently handling gzip compression."""
        url = resp.url

        if "gzip" in resp.headers.get("Content-Encoding", "") or url.endswith(".gz"):
            try:
                with gzip.GzipFile(fileobj=io.BytesIO(resp.content)) as gz:
                    return gz.read().decode("utf-8", errors="replace")
            except Exception:
                pass

        if url.endswith(".gz"):
            try:
                with gzip.GzipFile(fileobj=io.BytesIO(resp.content)) as gz:
                    return gz.read().decode("utf-8", errors="replace")
            except Exception:
                pass

        return resp.text

    def _normalise_discovered_url(self, raw_url: str, base_url: str) -> str:
        raw_url = html_utils.unescape((raw_url or "").strip()).strip("<>\"'")
        if not raw_url:
            return ""
        if raw_url.startswith("//"):
            raw_url = self.parsed_base.scheme + ":" + raw_url
        elif not urlparse(raw_url).scheme:
            raw_url = urljoin(base_url, raw_url)
        if not is_http_url(raw_url):
            return ""
        return normalise_url(raw_url)

    def _extract_sitemap_urls_from_xml(self, text: str) -> tuple:
        """
        Parse valid XML sitemap content.
        Returns (child_sitemap_urls, content_urls).
        """
        try:
            root = ET.fromstring(text.encode("utf-8"))
        except ET.ParseError:
            return None

        child_sitemaps = []
        content_urls = []
        root_name = local_xml_name(root.tag)

        if root_name == "sitemapindex":
            for node in root.iter():
                if local_xml_name(node.tag) != "sitemap":
                    continue
                for child in node:
                    if local_xml_name(child.tag) == "loc" and child.text:
                        append_unique(child_sitemaps, child.text.strip())
            return child_sitemaps, content_urls

        for node in root.iter():
            name = local_xml_name(node.tag)
            if name in {"loc", "content_loc", "player_loc"} and node.text:
                append_unique(content_urls, node.text.strip())
            elif name == "link":
                href = element_attr(node, "href")
                if href:
                    append_unique(content_urls, href.strip())

        return child_sitemaps, content_urls

    # Real-world sitemaps are often malformed, so XML parsing has a fallback.
    def _extract_sitemap_urls_with_regex(self, text: str) -> tuple:
        """
        Fallback extractor for real-world malformed sitemap XML.
        Returns (child_sitemap_urls, content_urls).
        """
        child_sitemaps = []
        content_urls = []

        child_blocks = re.findall(
            r"<(?:[A-Za-z0-9_.-]+:)?sitemap\b[^>]*>.*?</(?:[A-Za-z0-9_.-]+:)?sitemap>",
            text,
            re.IGNORECASE | re.DOTALL,
        )
        loc_re = re.compile(
            r"<(?:[A-Za-z0-9_.-]+:)?loc\b[^>]*>\s*(.*?)\s*</(?:[A-Za-z0-9_.-]+:)?loc>",
            re.IGNORECASE | re.DOTALL,
        )
        for block in child_blocks:
            for loc in loc_re.findall(block):
                append_unique(child_sitemaps, loc.strip())

        all_url_re = re.compile(
            r"<(?:[A-Za-z0-9_.-]+:)?(?:loc|content_loc|player_loc)\b[^>]*>"
            r"\s*(.*?)\s*</(?:[A-Za-z0-9_.-]+:)?(?:loc|content_loc|player_loc)>",
            re.IGNORECASE | re.DOTALL,
        )
        for loc in all_url_re.findall(text):
            loc = loc.strip()
            if loc and loc not in child_sitemaps:
                append_unique(content_urls, loc)

        for href in re.findall(
            r"<(?:[A-Za-z0-9_.-]+:)?link\b[^>]+\bhref=[\"']([^\"']+)[\"']",
            text,
            re.IGNORECASE,
        ):
            append_unique(content_urls, href.strip())

        if re.search(r"<(?:[A-Za-z0-9_.-]+:)?sitemapindex\b", text, re.IGNORECASE):
            for loc in list(content_urls):
                append_unique(child_sitemaps, loc)
            content_urls = []

        return child_sitemaps, content_urls

    def _process_sitemap(
        self,
        sitemap_url: str,
        _depth: int = 0,
        _visited: set = None,
        _fast_probe: bool = False,
    ):
        """
        Fetch and parse a sitemap or sitemap index recursively.

        Supports:
        - Plain XML sitemaps and sitemap indexes
        - Gzip-compressed sitemaps (.xml.gz)
        - Nested sitemap indexes (unlimited recursion, cycle-safe)
        - All URL variants: <loc>, <news:loc>, <image:loc>, <video:content_loc>
        - Returns (seed_crawl_list, new_dirs_list)
        """
        if _visited is None:
            _visited = self.sitemaps_seen

        base = f"{self.parsed_base.scheme}://{self.base_host}/"
        sitemap_url = self._normalise_discovered_url(sitemap_url, base)
        if not sitemap_url or not same_domain(sitemap_url, self.base_host):
            return [], []

        if _depth > SITEMAP_RECURSION_LIMIT:
            self._verbose(f"Sitemap recursion limit reached: {sitemap_url}")
            return [], []

        with self._lock:
            if sitemap_url in _visited:
                return [], []
            _visited.add(sitemap_url)
            self.sitemaps_checked += 1

        self._verbose(f"Fetching sitemap (depth={_depth}): {sitemap_url}")
        if _fast_probe and _depth == 0:
            probe_timeout = SPEED_SITEMAP_TIMEOUT if self.speed else 3
            fetch_timeout = min(self.timeout, probe_timeout)
            fetch_retries = 0
        else:
            fetch_timeout = self.timeout
            fetch_retries = self.retries
        self._speed_gate()
        resp = fetch(sitemap_url, fetch_timeout, fetch_retries)
        self._note_speed_pressure(
            resp.status_code if resp is not None else get_fetch_error(sitemap_url)
        )
        seed_crawl = []
        new_dirs = []

        if resp is None or resp.status_code != 200:
            return seed_crawl, new_dirs

        try:
            text = self._decode_sitemap_response(resp)
        except Exception:
            return seed_crawl, new_dirs

        if not text or not text.strip():
            return seed_crawl, new_dirs

        with self._lock:
            self.sitemaps_loaded += 1

        xml_result = self._extract_sitemap_urls_from_xml(text)
        xml_children, xml_urls = xml_result if xml_result else ([], [])
        regex_children, regex_urls = self._extract_sitemap_urls_with_regex(text)

        child_sitemap_urls = []
        content_urls = []
        for raw in xml_children + regex_children:
            child_url = self._normalise_discovered_url(raw, sitemap_url)
            if child_url and same_domain(child_url, self.base_host):
                append_unique(child_sitemap_urls, child_url)

        for raw in xml_urls + regex_urls:
            loc = self._normalise_discovered_url(raw, sitemap_url)
            if not loc or not same_domain(loc, self.base_host):
                continue
            if loc in child_sitemap_urls:
                continue

            if looks_like_sitemap_url(loc):
                append_unique(child_sitemap_urls, loc)
                continue

            append_unique(content_urls, loc)

        for child_url in child_sitemap_urls:
            c, d = self._process_sitemap(child_url, _depth + 1, _visited)
            seed_crawl.extend(c)
            new_dirs.extend(d)

        for loc in content_urls:
            with self._lock:
                self.resources_found.add(loc)
                new_dirs.extend(self._register_dirs_for_url_locked(loc))
                already_crawled = loc in self.crawled_urls

            if not already_crawled:
                if is_html_like_url(loc):
                    seed_crawl.append((loc, 1))

        if self.delay:
            time.sleep(self.delay)
        return seed_crawl, new_dirs

    def _run_parallel_sitemap_probes(self, sitemap_urls: list, visited_sitemaps: set):
        seed_crawl = []
        init_dirs = []
        if not sitemap_urls:
            return seed_crawl, init_dirs

        worker_limit = SPEED_SITEMAP_WORKER_LIMIT if self.speed else 24
        workers = min(max(1, self.crawl_workers * 2), len(sitemap_urls), worker_limit)
        pool = ThreadPoolExecutor(max_workers=workers)
        total = len(sitemap_urls)
        completed = 0
        last_progress = 0.0

        def update_progress(force: bool = False, done: bool = False):
            nonlocal last_progress
            if self.quiet:
                return
            now = time.monotonic()
            if not force and not done and now - last_progress < 0.25:
                return
            with self._lock:
                extra = (
                    f"checked {self.sitemaps_checked}, loaded {self.sitemaps_loaded}, "
                    f"resources {len(self.resources_found)}, dirs {len(self.queued_dirs)}"
                )
            self._progress("Phase 1 sitemap probes", completed, total, extra, done=done)
            last_progress = now

        try:
            futures = {
                pool.submit(
                    self._process_sitemap,
                    url,
                    0,
                    visited_sitemaps,
                    True,
                ): url
                for url in sitemap_urls
            }
            pending = set(futures)
            update_progress(force=True)
            while pending:
                done, pending = wait(pending, timeout=0.1, return_when=FIRST_COMPLETED)
                if not done:
                    update_progress()
                    continue

                for future in done:
                    try:
                        c, d = future.result()
                    except Exception:
                        c, d = [], []
                    seed_crawl.extend(c)
                    init_dirs.extend(d)
                    completed += 1

                update_progress()

                if STOP_EVENT.is_set():
                    pending.clear()
                    break
        except KeyboardInterrupt:
            STOP_EVENT.set()
            pool.shutdown(wait=False, cancel_futures=True)
            raise
        else:
            pool.shutdown(wait=True)

        update_progress(force=True, done=True)
        return seed_crawl, init_dirs

    def _discover_sitemaps_from_html(self, html: str, base_url: str) -> list:
        """
        Extract sitemap URLs referenced in HTML <link rel='sitemap'> tags.
        Returns list of sitemap URLs.
        """
        found = []

        def add(raw_url: str, require_sitemap_shape: bool = False):
            url = self._normalise_discovered_url(raw_url, base_url)
            if not url or not same_domain(url, self.base_host):
                return
            if require_sitemap_shape and not looks_like_sitemap_url(url):
                return
            append_unique(found, url)

        try:
            soup = BeautifulSoup(html, "html.parser")
            for tag in soup.find_all("link", href=True):
                rel = tag.get("rel", "")
                rel_text = " ".join(rel) if isinstance(rel, list) else str(rel)
                href = tag["href"]
                if "sitemap" in rel_text.lower():
                    add(href)
                else:
                    add(href, require_sitemap_shape=True)

            for tag in soup.find_all("a", href=True):
                add(tag["href"], require_sitemap_shape=True)
        except Exception:
            pass

        for href in re.findall(
            r"\bhref=[\"']([^\"']*(?:sitemap|sitemaps)[^\"']*)[\"']",
            html,
            re.IGNORECASE,
        ):
            add(href, require_sitemap_shape=True)

        return found

    def _discover_sitemaps_from_headers(self, headers, base_url: str) -> list:
        found = []

        def add(raw_url: str, require_sitemap_shape: bool = False):
            url = self._normalise_discovered_url(raw_url, base_url)
            if not url or not same_domain(url, self.base_host):
                return
            if require_sitemap_shape and not looks_like_sitemap_url(url):
                return
            append_unique(found, url)

        for header_name in ("X-Sitemap", "Sitemap"):
            value = headers.get(header_name, "")
            for raw_url in re.split(r"[\s,]+", value):
                add(raw_url)

        link_header = headers.get("Link", "")
        for url, params in re.findall(r"<([^>]+)>\s*;([^,]+)", link_header):
            if re.search(r"\brel=[\"']?[^\"';,]*sitemap", params, re.IGNORECASE):
                add(url)

        return found

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

        self._speed_gate()
        resp = fetch(url, self.timeout, self.retries)
        self._note_speed_pressure(resp.status_code if resp is not None else get_fetch_error(url))
        if self.delay:
            time.sleep(self.delay)

        if STOP_EVENT.is_set():
            return [], []

        if resp is None:
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
                    if is_html_like_url(r) and r not in self.crawled_urls:
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
            next_wave = []
            pool = ThreadPoolExecutor(max_workers=self.crawl_workers)
            total = len(wave)
            completed = 0
            last_progress = 0.0

            def update_progress(force: bool = False, done: bool = False):
                nonlocal last_progress
                if self.quiet:
                    return
                now = time.monotonic()
                if not force and not done and now - last_progress < 0.25:
                    return
                with self._lock:
                    extra = (
                        f"pages {self.pages_crawled}/{self.max_pages}, "
                        f"resources {len(self.resources_found)}, "
                        f"dirs {len(self.queued_dirs)}, next {len(next_wave)}"
                    )
                self._progress(f"Phase 2 crawl wave {wave_num}", completed, total, extra, done=done)
                last_progress = now

            try:
                futures = {
                    pool.submit(self._crawl_worker, url, dep): (url, dep)
                    for url, dep in wave
                }
                pending = set(futures)
                update_progress(force=True)
                while pending:
                    done, pending = wait(
                        pending, timeout=0.1, return_when=FIRST_COMPLETED
                    )
                    if not done:
                        update_progress()
                        continue

                    for future in done:
                        try:
                            new_pages, new_dirs = future.result()
                        except Exception:
                            new_pages, new_dirs = [], []

                        next_wave.extend(new_pages)
                        all_dirs.extend(new_dirs)
                        completed += 1

                        with self._lock:
                            if self.pages_crawled >= self.max_pages:
                                pending.clear()
                                break

                    update_progress()

                    if STOP_EVENT.is_set():
                        pending.clear()
                        break

            except KeyboardInterrupt:
                STOP_EVENT.set()
                pool.shutdown(wait=False, cancel_futures=True)
                raise
            else:
                pool.shutdown(wait=True)

            update_progress(force=True, done=True)

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

        self._speed_gate()
        resp = fetch(url, self.timeout, self.retries)
        if self.delay:
            time.sleep(self.delay)

        if STOP_EVENT.is_set():
            return

        code = resp.status_code if resp is not None else get_fetch_error(url)
        self._note_speed_pressure(code)
        self._print("test", url, code)

        if has_login_warning_signal(resp):
            with self._lock:
                append_unique_result(self.login_warning_paths, url)

        status = classify_response(resp)

        if status == "listing":
            display_url = canonical_result_url(url)
            with self._lock:
                added = append_unique_result(self.listings_found, url)
            if added:
                self._print("listing", display_url, code)
        elif status == "exposed":
            found_url = resp.url if resp is not None else url
            display_url = canonical_result_url(found_url)
            with self._lock:
                added = append_unique_result(self.exposed_paths, found_url)
            if added:
                self._print("exposed", display_url, code)
        elif status == "forbidden":
            display_url = canonical_result_url(url)
            with self._lock:
                added = append_unique_result(self.forbidden_paths, url)
            if added:
                self._print("forbidden", display_url, code)
        elif status == "error":
            with self._lock:
                self.errors += 1
            if self.verbose:
                self._print("error", url, code)

    def _run_parallel_tests(self, dirs: list):
        pool = ThreadPoolExecutor(max_workers=self.test_workers)
        total = len(dirs)
        completed = 0
        last_progress = 0.0

        def update_progress(force: bool = False, done: bool = False):
            nonlocal last_progress
            if self.quiet:
                return
            now = time.monotonic()
            min_interval = 0.1 if not self.speed else 0.05
            if not force and not done and now - last_progress < min_interval:
                return
            with self._lock:
                extra = (
                    f"tested {len(self.dirs_tested)}, "
                    f"found {len(self.listings_found)}, "
                    f"exposed {len(self.exposed_paths)}, "
                    f"403 {len(self.forbidden_paths)}, "
                    f"429 {self.rate_limit_hits}, "
                    f"timeouts {self.timeout_hits}, errors {self.errors}"
                )
            self._progress("Phase 3 directory tests", completed, total, extra, done=done)
            last_progress = now

        try:
            futures = {pool.submit(self._test_worker, url): url for url in dirs}
            pending = set(futures)
            update_progress(force=True)
            while pending:
                done, pending = wait(pending, timeout=0.05, return_when=FIRST_COMPLETED)
                if not done:
                    update_progress()
                    continue

                for future in done:
                    try:
                        future.result()
                    except Exception:
                        pass
                    completed += 1

                update_progress(force=True)

                if STOP_EVENT.is_set():
                    pending.clear()
                    break
        except KeyboardInterrupt:
            STOP_EVENT.set()
            pool.shutdown(wait=False, cancel_futures=True)
            raise
        else:
            pool.shutdown(wait=True)

        update_progress(force=True, done=True)

    def run(self):
        p = self.palette
        start_time = datetime.now()
        interrupted = False

        try:
            self._ui_sleep(1)
            if self.clear_screen:
                os.system("cls" if os.name == "nt" else "clear")

            print()

            banner = icon if terminal_supports(icon) else ascii_icon
            safe_print(p.cyan(banner))
            self._ui_sleep(1)
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
            safe_print(p.white(f"  Retries       : {self.retries}"))
            if self.speed:
                safe_print(p.yellow("  Mode          : SPEED"))
            if self.quiet:
                safe_print(p.dim("  Mode          : quiet"))
            safe_print(p.cyan("-" * 60))
            if self.speed:
                print()
                safe_print(
                    p.yellow(
                        "[!] SPEED mode: high concurrency with adaptive 429/timeout control."
                    )
                )
                safe_print(
                    p.yellow(
                        "   Still very fast, but backs off slightly when the target starts throttling."
                    )
                )
            safe_print("")
            self._ui_sleep(1)

            if not self.quiet:
                safe_print(p.yellow("[+] Might take some time..."))
                print()
                safe_print(p.white("[*] Phase 1 - robots.txt + sitemap discovery"))
            self._progress("Phase 1 robots.txt", 0, 1, "fetching")
            seed_crawl, init_dirs = self._process_robots()
            with self._lock:
                robots_extra = f"resources {len(self.resources_found)}, dirs {len(self.queued_dirs)}"
            self._progress("Phase 1 robots.txt", 1, 1, robots_extra, done=True)

            base = f"{self.parsed_base.scheme}://{self.base_host}"

            visited_sitemaps = self.sitemaps_seen
            candidate_urls = [base + candidate for candidate in SITEMAP_CANDIDATES]
            c, d = self._run_parallel_sitemap_probes(candidate_urls, visited_sitemaps)
            seed_crawl.extend(c)
            init_dirs.extend(d)

            self._verbose("Checking homepage for <link rel='sitemap'>")
            self._progress("Phase 1 homepage sitemap refs", 0, 1, "fetching")
            self._speed_gate()
            homepage_resp = fetch(self.target, self.timeout, self.retries)
            self._note_speed_pressure(
                homepage_resp.status_code if homepage_resp is not None else get_fetch_error(self.target)
            )
            homepage_refs = 0
            if homepage_resp is not None and homepage_resp.status_code == 200:
                header_sitemaps = self._discover_sitemaps_from_headers(homepage_resp.headers, self.target)
                homepage_refs += len(header_sitemaps)
                for sm_url in header_sitemaps:
                    self._verbose(f"Sitemap header found: {sm_url}")
                    c, d = self._process_sitemap(sm_url, _visited=visited_sitemaps)
                    seed_crawl.extend(c)
                    init_dirs.extend(d)

                try:
                    html_sitemaps = self._discover_sitemaps_from_html(homepage_resp.text, self.target)
                    homepage_refs += len(html_sitemaps)
                    for sm_url in html_sitemaps:
                        self._verbose(f"HTML sitemap reference found: {sm_url}")
                        c, d = self._process_sitemap(sm_url, _visited=visited_sitemaps)
                        seed_crawl.extend(c)
                        init_dirs.extend(d)
                except Exception:
                    pass
            with self._lock:
                homepage_extra = (
                    f"refs {homepage_refs}, checked {self.sitemaps_checked}, "
                    f"loaded {self.sitemaps_loaded}, resources {len(self.resources_found)}"
                )
            self._progress("Phase 1 homepage sitemap refs", 1, 1, homepage_extra, done=True)

            seed_crawl.insert(0, (self.target, 0))

            if not self.no_common:
                if not self.quiet:
                    safe_print(p.white(f"[*] Phase 1b - Seeding {len(COMMON_PATHS)} common paths"))
                total_common = len(COMMON_PATHS)
                last_common_progress = 0.0
                self._progress("Phase 1b common paths", 0, total_common, "seeding")
                for idx, path in enumerate(COMMON_PATHS, start=1):
                    url = normalise_url(base + path)
                    with self._lock:
                        self.resources_found.add(url)
                        if url not in self.queued_dirs:
                            self.queued_dirs.add(url)
                            init_dirs.append(url)
                        new_common_dirs = self._register_dirs_for_url_locked(url)
                    init_dirs.extend(new_common_dirs)
                    if path.endswith("/") or should_probe_slash_variant(url):
                        dir_url = url.rstrip("/") + "/"
                        dir_url = normalise_url(dir_url)
                        with self._lock:
                            if dir_url not in self.queued_dirs:
                                self.queued_dirs.add(dir_url)
                                init_dirs.append(dir_url)
                    now = time.monotonic()
                    if idx == total_common or now - last_common_progress >= 0.15:
                        with self._lock:
                            common_extra = (
                                f"resources {len(self.resources_found)}, "
                                f"dirs {len(self.queued_dirs)}"
                            )
                        self._progress(
                            "Phase 1b common paths",
                            idx,
                            total_common,
                            common_extra,
                            done=idx == total_common,
                        )
                        last_common_progress = now

            seen = set()
            deduped_seed = []
            for url, dep in seed_crawl:
                if url not in seen:
                    seen.add(url)
                    deduped_seed.append((url, dep))

            if not self.quiet:
                safe_print(p.white("[*] Phase 2 - Crawling pages"))
            crawl_dirs = self._run_parallel_crawl(deduped_seed)

            all_dirs_set = set(init_dirs) | set(crawl_dirs)
            with self._lock:
                all_dirs_set |= self.queued_dirs

            if not self.quiet:
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
        except KeyboardInterrupt:
            STOP_EVENT.set()
            interrupted = True
            safe_print("")
            safe_print(p.red("[!] Scan interrupted - generating partial report..."))

        self._ui_sleep(1)
        self.listings_found = dedupe_result_urls(self.listings_found)
        self.exposed_paths = dedupe_result_urls(self.exposed_paths)
        self.forbidden_paths = dedupe_result_urls(self.forbidden_paths)
        self.login_warning_paths = dedupe_result_urls(self.login_warning_paths)

        elapsed = (datetime.now() - start_time).total_seconds()
        safe_print("")
        safe_print(p.cyan("=" * 60))
        if not self.quiet:
            status_line = "  DirLens scan interrupted" if interrupted else "  DirLens scan completed"
            safe_print(p.cyan(status_line))
            safe_print(p.cyan("=" * 60))
            safe_print(p.white(f"  Target             : {self.target}"))
            safe_print(p.white(f"  Pages crawled      : {self.pages_crawled}"))
            safe_print(p.white(f"  Resources found    : {len(self.resources_found)}"))
            safe_print(p.white(f"  Directories tested : {len(self.dirs_tested)}"))
            safe_print(p.white(f"  Sitemaps checked   : {self.sitemaps_checked}"))
            safe_print(p.white(f"  Sitemaps loaded    : {self.sitemaps_loaded}"))
        else:
            status_line = "  DirLens scan interrupted" if interrupted else "  DirLens scan completed"
            safe_print(p.cyan(status_line))
            safe_print(p.cyan("=" * 60))
            safe_print(p.white(f"  Target             : {self.target}"))
        if self.listings_found:
            safe_print(p.green(f"  Listings found     : {len(self.listings_found)}"))
        else:
            safe_print(p.white(f"  Listings found     : 0"))
        if self.exposed_paths:
            safe_print(p.yellow(f"  Exposed paths      : {len(self.exposed_paths)}"))
        elif not self.quiet:
            safe_print(p.white(f"  Exposed paths      : 0"))
        if not self.quiet:
            safe_print(p.yellow(f"  Forbidden paths    : {len(self.forbidden_paths)}"))
            if self.speed:
                safe_print(p.yellow(f"  Rate limits 429    : {self.rate_limit_hits}"))
                safe_print(p.yellow(f"  Speed timeouts     : {self.timeout_hits}"))
            safe_print(p.white(f"  Errors             : {self.errors}"))
        if self.login_warning_paths:
            safe_print(
                p.yellow(
                    f"  Login warnings     : {len(self.login_warning_paths)} "
                    "pages contained login-like text"
                )
            )
        safe_print(p.white(f"  Elapsed            : {elapsed:.1f}s"))
        safe_print(p.cyan("=" * 60))

        if self.listings_found:
            self._ui_sleep(1.5)
            safe_print("")
            safe_print(p.green("  [!] Open directory listings:"))
            for u in self.listings_found:
                safe_print(p.green(f"      {u}"))

        if self.exposed_paths:
            safe_print("")
            safe_print(p.yellow("  [!] Exposed non-HTML or sensitive paths:"))
            for u in self.exposed_paths:
                safe_print(p.yellow(f"      {u}"))

        if self.login_warning_paths:
            safe_print("")
            safe_print(
                p.yellow(
                    "  [!] Login-like text was seen but did not block detection:"
                )
            )
            for u in self.login_warning_paths:
                safe_print(p.yellow(f"      {u}"))

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
                "test_workers": self.test_workers,
                "speed": self.speed,
                "timeout": self.timeout,
                "retries": self.retries,
                "interrupted": interrupted,
            },
            "summary": {
                "pages_crawled": self.pages_crawled,
                "resources_found": len(self.resources_found),
                "directories_tested": len(self.dirs_tested),
                "listings_found": len(self.listings_found),
                "exposed_paths": len(self.exposed_paths),
                "forbidden_paths": len(self.forbidden_paths),
                "login_warnings": len(self.login_warning_paths),
                "sitemaps_checked": self.sitemaps_checked,
                "sitemaps_loaded": self.sitemaps_loaded,
                "errors": self.errors,
                "rate_limit_hits": self.rate_limit_hits,
                "timeout_hits": self.timeout_hits,
                "interrupted": interrupted,
            },
            "listings": self.listings_found,
            "exposed": self.exposed_paths,
            "forbidden": self.forbidden_paths,
            "login_warnings": self.login_warning_paths,
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
    listings = dedupe_result_urls(data["listings"])
    exposed = dedupe_result_urls(data.get("exposed", []))
    forbidden = dedupe_result_urls(data["forbidden"])
    login_warnings = dedupe_result_urls(data.get("login_warnings", []))
    dirs_tested = dedupe_result_urls(data["dirs_tested"])

    def esc(value) -> str:
        return html_utils.escape(str(value), quote=True)

    def row(label, value, colour=""):
        style = f'style="color:{colour}"' if colour else ""
        return f'<tr><td class="lbl">{esc(label)}</td><td {style}><strong>{esc(value)}</strong></td></tr>'

    def url_rows(urls, colour):
        if not urls:
            return '<tr><td colspan="2" style="color:rgb(136, 136, 136)">None found</td></tr>'
        return "\n".join(
            f'<tr><td colspan="2"><a href="{esc(u)}" style="color:{colour}">{esc(u)}</a></td></tr>'
            for u in urls
        )

    badge = (
        f'<span style="background:rgb(26, 156, 62);color:rgb(255, 255, 255);padding:2px 8px;border-radius:4px">'
        f'{summary["listings_found"]} FOUND</span>'
        if summary["listings_found"]
        else '<span style="color:rgb(136, 136, 136)">0</span>'
    )
    dirs_html = "".join(f'<tr><td class="dir-url">{esc(u)}</td></tr>' for u in dirs_tested)
    target = esc(meta["target"])
    author = esc(meta["author"])
    github = esc(meta["github"])
    scanned_at = esc(meta["scanned_at"])
    elapsed_seconds = esc(meta["elapsed_seconds"])
    workers = esc(meta["workers"])
    test_workers = esc(meta.get("test_workers", ""))
    mode = "SPEED" if meta.get("speed") else "normal"
    timeout = meta.get("timeout", "")
    retries = meta.get("retries", "")

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>DirLens Report - {target}</title>
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
<p class="byline">{author} &nbsp;|&nbsp; <a href="{github}">{github}</a></p>
<p class="meta">Target: {target} &nbsp;|&nbsp; Scanned: {scanned_at} &nbsp;|&nbsp; Elapsed: {elapsed_seconds}s &nbsp;|&nbsp; Mode: {esc(mode)} &nbsp;|&nbsp; Crawl workers: {workers} &nbsp;|&nbsp; Test workers: {test_workers}</p>
<div class="section"><h2>Summary</h2><table>
  {row("Mode",               mode)}
  {row("Crawl workers",      meta["workers"])}
  {row("Test workers",       meta.get("test_workers", ""))}
  {row("Timeout",            timeout)}
  {row("Retries",            retries)}
  {row("Pages crawled",      summary["pages_crawled"])}
  {row("Resources found",    summary["resources_found"])}
  {row("Directories tested", summary["directories_tested"])}
  {row("Sitemaps checked",   summary.get("sitemaps_checked", 0))}
  {row("Sitemaps loaded",    summary.get("sitemaps_loaded", 0))}
  {row("Interrupted",        summary.get("interrupted", False))}
  <tr><td class="lbl">Listings found</td><td>{badge}</td></tr>
  {row("Exposed paths",      summary.get("exposed_paths", 0), "rgb(200, 166, 0)")}
  {row("Forbidden paths",    summary["forbidden_paths"], "rgb(200, 166, 0)")}
  {row("Login warnings",     summary.get("login_warnings", 0), "rgb(200, 166, 0)")}
  {row("Rate limits 429",    summary.get("rate_limit_hits", 0), "rgb(200, 166, 0)")}
  {row("Speed timeouts",     summary.get("timeout_hits", 0), "rgb(200, 166, 0)")}
  {row("Errors",             summary["errors"])}
</table></div>
<div class="section"><h2>Open Directory Listings</h2><table>{url_rows(listings, "rgb(26, 156, 62)")}</table></div>
<div class="section"><h2>Exposed Non-HTML or Sensitive Paths</h2><table>{url_rows(exposed, "rgb(200, 166, 0)")}</table></div>
<div class="section"><h2>Forbidden Paths (403)</h2><table>{url_rows(forbidden, "rgb(200, 166, 0)")}</table></div>
<div class="section"><h2>Login-like Text Warnings</h2><table>{url_rows(login_warnings, "rgb(200, 166, 0)")}</table></div>
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
  --timeout SECONDS      HTTP request timeout. Default: {DEFAULT_TIMEOUT}
  --retries N            Retry failed requests. Default: {DEFAULT_RETRIES}
  --speed                Very fast adaptive mode with many threads

Output options:
  --json                 Save JSON report to reports/
  --html                 Save HTML report to reports/
  --no-color             Disable coloured terminal output
  --verbose              Show debug output
  --quiet                Only print findings ([FOUND], [EXPOSED], [403]) and final summary
  --no-common            Skip built-in common path seeding

Help:
  -h, --help             Show this help screen

Examples:
  python dirlens.py https://example.com
  python dirlens.py https://example.com --speed
  python dirlens.py https://example.com --depth 3 --max-pages 200 --json --html
  python dirlens.py https://example.com --workers 20 --delay 0 --timeout 6 --retries 2
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
  python dirlens.py https://example.com --speed
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
        default=DEFAULT_TIMEOUT,
        help=f"HTTP request timeout in seconds (default: {DEFAULT_TIMEOUT})",
    )
    parser.add_argument(
        "--retries",
        type=int,
        default=DEFAULT_RETRIES,
        help=f"Retry failed requests before marking an error (default: {DEFAULT_RETRIES})",
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
        "--speed",
        action="store_true",
        help=(
            "Very fast adaptive mode: many threads with 429/timeout backoff"
        ),
    )
    parser.add_argument(
        "--no-color", action="store_true", help="Disable coloured output"
    )
    parser.add_argument("--verbose", action="store_true", help="Verbose debug output")
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Quiet mode: only print findings ([FOUND], [EXPOSED], [403]) and final summary",
    )
    parser.add_argument(
        "--no-common",
        action="store_true",
        dest="no_common",
        help="Skip common path seeding (disable the built-in curated path list)",
    )
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
    if args.retries < 0:
        print("[ERROR] --retries must be >= 0", file=sys.stderr)
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
        safe_print(p.red("[!] Scan interrupted before a partial report could be generated."))
        print()
        sys.exit(130)


if __name__ == "__main__":
    main()
