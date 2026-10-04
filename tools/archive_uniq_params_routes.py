#!/usr/bin/env python3
"""
route_params_recon.py

Purpose
-------
From a Wayback/archive URL list:

  1) Extract unique query-parameter names
  2) Keep FULL URLs from ALL hosts / subdomains (no single-host filter)
  3) Pattern-dedupe dynamic segments (UUID / hex / number / long-id)
     so similar paths collapse to one representative per host
  4) HTTP-validate: keep only HTTP 200 + HTML Content-Type
  5) Write validated unique full URLs to one file

Dependencies:
    (stdlib only)

Examples:
    python route_params_recon.py -f list.txt
    python route_params_recon.py -f list.txt -ro uniq-all-urls.txt -po params.txt
    python route_params_recon.py -f list.txt -t 20 --timeout 8
    python route_params_recon.py -f list.txt --no-validate
    python route_params_recon.py -f list.txt --no-pattern-dedupe
"""

from __future__ import annotations

import argparse
import concurrent.futures
import html
import re
import ssl
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Iterable, List, Optional, Set, Tuple
from urllib.error import HTTPError, URLError
from urllib.parse import (
    parse_qsl,
    urlparse,
    urlunparse,
)
from urllib.request import Request, urlopen


# Deliberately excludes common non-UI resources.
NON_UI_EXTENSIONS = {
    ".js", ".mjs", ".css", ".map", ".png", ".jpg", ".jpeg", ".gif", ".webp",
    ".svg", ".ico", ".bmp", ".tif", ".tiff", ".avif", ".woff", ".woff2",
    ".ttf", ".otf", ".eot", ".pdf", ".zip", ".gz", ".tar", ".tgz", ".rar",
    ".7z", ".gpg", ".asc", ".pem", ".crt", ".txt", ".xml", ".json", ".csv",
    ".mp3", ".mp4", ".wav", ".webm", ".avi", ".mov", ".mkv", ".wasm",
    ".bin", ".exe", ".dmg", ".apk",
}

# Relaxed UUID: any 8-4-4-4-12 hex (including nil / non-RFC version nibbles)
# so paths like /ide/19f518ad-0000-0000-0000-000000000000 collapse correctly.
DYNAMIC_SEGMENT_PATTERNS = [
    ("uuid", re.compile(
        r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
        r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
    )),
    ("hex", re.compile(r"^[0-9a-fA-F]{16,}$")),
    ("number", re.compile(r"^\d+$")),
]

DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Safari/537.36"
)

_SSL_CTX = ssl.create_default_context()
_SSL_CTX.check_hostname = False
_SSL_CTX.verify_mode = ssl.CERT_NONE


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description=(
            "Archive unique query-parameters + full-URL pattern-dedupe "
            "(ALL subdomains) + HTTP 200/HTML validation"
        ),
        add_help=False,
    )
    p.add_argument("--help", action="help", help="Show this help message and exit")
    p.add_argument(
        "-f", "--file", required=True,
        help="File containing archive URLs, one URL per line.",
    )
    p.add_argument(
        "-ro", "--route-output", default="uniq-all-urls.txt",
        help="Validated unique full-URL output (default: uniq-all-urls.txt)",
    )
    p.add_argument(
        "-po", "--param-output", default="all-uniq-params.txt",
        help="Unique query-parameter output (default: all-uniq-params.txt)",
    )
    p.add_argument(
        "-t", "--threads", type=int, default=15,
        help="Concurrent HTTP workers (default: 15)",
    )
    p.add_argument(
        "--timeout", type=float, default=10.0,
        help="Per-request timeout in seconds (default: 10)",
    )
    p.add_argument(
        "--no-validate", action="store_true",
        help="Skip HTTP validation; write pattern-deduped full URLs only",
    )
    p.add_argument(
        "--no-pattern-dedupe", action="store_true",
        help=(
            "Disable pattern collapse of dynamic segments. "
            "Default is ON so UUID/number/hex paths collapse per host."
        ),
    )
    return p.parse_args()


def read_lines(path: str) -> List[str]:
    return [
        x.strip()
        for x in Path(path).read_text(encoding="utf-8", errors="ignore").splitlines()
        if x.strip()
    ]


def host_key(url: str) -> str:
    return (urlparse(url).hostname or "").lower()


def is_non_ui_path(path: str) -> bool:
    lower = path.lower()
    last = lower.rsplit("/", 1)[-1]
    if "." in last:
        suffix = "." + last.rsplit(".", 1)[-1]
        if suffix in NON_UI_EXTENSIONS:
            return True
    return False


def looks_like_ui_route(url: str) -> bool:
    p = urlparse(url)
    if p.scheme not in {"http", "https"}:
        return False
    if is_non_ui_path(p.path or "/"):
        return False

    path = p.path or "/"
    first = path.strip("/").split("/", 1)[0].lower() if path.strip("/") else ""
    if first in {"api", "apis", "graphql", "rest", "rpc", "webhook", "webhooks"}:
        return False

    return True


# ---------------------------------------------------------------------------
# Parameter pipeline
# ---------------------------------------------------------------------------

def normalize_parameter_for_dedup(name: str) -> str:
    n = name.strip()
    if DYNAMIC_SEGMENT_PATTERNS[0][1].fullmatch(n):
        return "<UUID>"
    if DYNAMIC_SEGMENT_PATTERNS[1][1].fullmatch(n):
        return "<HEX_ID>"
    if DYNAMIC_SEGMENT_PATTERNS[2][1].fullmatch(n):
        return "<NUMBER>"
    return re.sub(r"\d+", "#", n)


def edit_distance(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(
                cur[-1] + 1,
                prev[j] + 1,
                prev[j - 1] + (ca != cb),
            ))
        prev = cur
    return prev[-1]


def similar_parameter(a: str, b: str) -> bool:
    if a == b:
        return True
    if len(a) < 5 or len(b) < 5:
        return False
    dist = edit_distance(a, b)
    max_len = max(len(a), len(b))
    ratio = 1 - (dist / max_len)
    return ratio >= 0.82 and dist <= 3


def dedupe_parameters(params: Iterable[str]) -> List[str]:
    exact_seen: Set[str] = set()
    exact_unique: List[str] = []
    for p in params:
        p = p.strip()
        if p and p not in exact_seen:
            exact_seen.add(p)
            exact_unique.append(p)

    normalized_seen: Set[str] = set()
    candidates: List[str] = []
    for p in exact_unique:
        key = normalize_parameter_for_dedup(p)
        if key not in normalized_seen:
            normalized_seen.add(key)
            candidates.append(p)

    representatives: List[str] = []
    for p in candidates:
        if any(similar_parameter(p, existing) for existing in representatives):
            continue
        representatives.append(p)
    return representatives


def extract_query_parameters(urls: Iterable[str]) -> List[str]:
    params: List[str] = []
    valid_name_re = re.compile(r"^[A-Za-z_][A-Za-z0-9_.:-]*$")

    for url in urls:
        try:
            cleaned_url = html.unescape(url)
            query = urlparse(cleaned_url).query
            for name, _value in parse_qsl(
                query, keep_blank_values=True, strict_parsing=False,
            ):
                name = html.unescape(name).strip()
                name = name.lstrip("?&;")
                if not name or not valid_name_re.fullmatch(name):
                    continue
                if "/" in name or "\\" in name or "?" in name:
                    continue
                params.append(name)
        except Exception:
            continue
    return dedupe_parameters(params)


# ---------------------------------------------------------------------------
# Full-URL helpers
# ---------------------------------------------------------------------------

def classify_dynamic_segment(segment: str) -> Optional[str]:
    """
    Classify a path segment as dynamic.
    Order matters: uuid (with hyphens) before plain hex.
    Also catches long opaque tokens as :id.
    """
    for kind, rx in DYNAMIC_SEGMENT_PATTERNS:
        if rx.fullmatch(segment):
            return kind

    # long opaque id (base64-ish / random token)
    if len(segment) >= 16 and re.fullmatch(r"[A-Za-z0-9_-]+", segment):
        return "id"

    # shorter but clearly hex-like id (8+ hex chars)
    if len(segment) >= 8 and re.fullmatch(r"[0-9a-fA-F]+", segment):
        return "hex"

    return None


def route_pattern(url: str) -> str:
    """
    Convert concrete path into a dedupe pattern.

    Examples:
      /ide/19f518ad-0000-0000-0000-000000000000 -> /ide/:uuid
      /users/123 -> /users/:number
      /x/abcdef0123456789 -> /x/:hex
    """
    p = urlparse(url)
    parts = [x for x in p.path.split("/") if x]
    out = []
    for seg in parts:
        kind = classify_dynamic_segment(seg)
        out.append(":" + kind if kind else seg)
    return "/" + "/".join(out) if out else "/"


def unwrap_wayback(url: str) -> str:
    """
    If the line is a full Wayback wrapper, return the original target URL.
    """
    try:
        p = urlparse(url)
        host = (p.hostname or "").lower()
        if host in {"web.archive.org", "archive.org"} and "/web/" in (p.path or ""):
            m = re.search(
                r"/web/\d+(?:[a-zA-Z_]+)?/(https?://.+)$",
                p.path or "",
                re.I,
            )
            if m:
                return m.group(1)
            parts = (p.path or "").split("/", 3)
            if len(parts) >= 4 and parts[3].startswith(("http://", "https://")):
                return parts[3]
    except Exception:
        pass
    return url


def normalize_full_url(url: str) -> str:
    """
    Canonical form: scheme + host + path (no query, no fragment).
    """
    p = urlparse(url)
    scheme = (p.scheme or "https").lower()
    netloc = (p.netloc or "").lower()
    path = p.path or "/"
    path = re.sub(r"/{2,}", "/", path)
    return urlunparse((scheme, netloc, path, "", "", ""))


# ---------------------------------------------------------------------------
# HTTP validation (200 + HTML)
# ---------------------------------------------------------------------------

def is_html_content_type(headers) -> bool:
    ct = headers.get("Content-Type") or headers.get("content-type") or ""
    ct = ct.lower().split(";")[0].strip()
    return (
        ct in {"text/html", "application/xhtml+xml", "application/html"}
        or ct.startswith("text/html")
    )


def probe_url(url: str, timeout: float) -> Tuple[str, bool, str]:
    """
    Returns (url, is_valid, reason).
    Valid = HTTP 200 and Content-Type looks like HTML.
    Tries HEAD first; falls back to GET.
    """
    headers = {
        "User-Agent": DEFAULT_UA,
        "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Connection": "close",
    }

    def _do(method: str) -> Tuple[bool, str]:
        req = Request(url, headers=headers, method=method)
        try:
            with urlopen(req, timeout=timeout, context=_SSL_CTX) as resp:
                code = getattr(resp, "status", None) or resp.getcode()
                if code != 200:
                    return False, f"status={code}"
                if not is_html_content_type(resp.headers):
                    return False, "not-html"
                return True, "ok"
        except HTTPError as e:
            return False, f"http={e.code}"
        except URLError as e:
            return False, f"urlerr={getattr(e, 'reason', e)}"
        except Exception as e:
            return False, f"err={type(e).__name__}"

    ok, reason = _do("HEAD")
    if ok:
        return url, True, reason

    ok2, reason2 = _do("GET")
    if ok2:
        return url, True, reason2
    return url, False, reason2 if reason2 else reason


# ---------------------------------------------------------------------------
# Files / logging
# ---------------------------------------------------------------------------

def write_lines(path: Path, lines: Iterable[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    unique: List[str] = []
    seen: Set[str] = set()
    for line in lines:
        line = str(line).strip()
        if line and line not in seen:
            seen.add(line)
            unique.append(line)
    path.write_text(
        "\n".join(unique) + ("\n" if unique else ""),
        encoding="utf-8",
    )


def print_stage(name: str, count: int) -> None:
    print(f"[+] {name}: {count}")


def main() -> int:
    args = parse_args()

    archive_urls = read_lines(args.file)
    if not archive_urls:
        print("[!] Input file is empty.", file=sys.stderr)
        return 1

    print(f"[+] Seed lines: {len(archive_urls)}")

    # ================================================================
    # PARAMETER PIPELINE (all URLs, all hosts)
    # ================================================================
    unique_params = extract_query_parameters(archive_urls)
    write_lines(Path(args.param_output), unique_params)
    print_stage("Unique query parameters", len(unique_params))
    print(f"[+] Parameter output: {args.param_output}")

    # ================================================================
    # FULL-URL PIPELINE – ALL hosts / subdomains
    # ================================================================
    candidates: List[str] = []
    exact_seen: Set[str] = set()
    host_counter: Counter = Counter()

    for raw in archive_urls:
        try:
            cleaned = html.unescape(raw).strip()
            cleaned = unwrap_wayback(cleaned)

            p = urlparse(cleaned)
            if p.scheme not in {"http", "https"}:
                continue
            if not p.hostname:
                continue

            full = normalize_full_url(cleaned)
            if full in exact_seen:
                continue
            exact_seen.add(full)

            if not looks_like_ui_route(full):
                continue

            candidates.append(full)
            host_counter[host_key(full)] += 1
        except Exception:
            continue

    print_stage("Exact-unique UI full URLs (ALL hosts/subs)", len(candidates))
    if host_counter:
        print("[+] Hosts found:")
        for h, c in sorted(host_counter.items(), key=lambda x: (-x[1], x[0])):
            print(f"    {h}: {c}")

    # Pattern-dedupe ON by default (collapse :uuid / :number / :hex / :id per host)
    to_probe: List[str] = candidates
    if not args.no_pattern_dedupe:
        pattern_seen: Set[Tuple[str, str]] = set()
        pattern_unique: List[str] = []
        for u in candidates:
            key = (host_key(u), route_pattern(u))
            if key in pattern_seen:
                continue
            pattern_seen.add(key)
            pattern_unique.append(u)
        to_probe = pattern_unique
        print_stage("After pattern-dedupe (per host)", len(to_probe))

        # show a few collapsed examples for clarity
        if len(candidates) != len(to_probe):
            print("[i] Example pattern collapses (first 5 patterns with multiples):")
            from collections import defaultdict
            groups: dict = defaultdict(list)
            for u in candidates:
                groups[(host_key(u), route_pattern(u))].append(u)
            shown = 0
            for key, urls in groups.items():
                if len(urls) > 1:
                    print(f"    {key[0]}{key[1]}  <- {len(urls)} urls, kept: {urls[0]}")
                    shown += 1
                    if shown >= 5:
                        break

    if args.no_validate:
        write_lines(Path(args.url_output), to_probe)
        print(f"[+] URL output (no validation): {args.url_output}")
        print()
        print("[+] Done.")
        print(f"[+] Parameters : {args.param_output}")
        print(f"[+] URLs       : {args.url_output}")
        return 0

    # ================================================================
    # HTTP validation – keep only 200 + HTML
    # ================================================================
    print(
        f"[+] Probing {len(to_probe)} URLs "
        f"(threads={args.threads}, timeout={args.timeout}s) ..."
    )

    valid_urls: List[str] = []
    failed = 0
    start = time.time()

    with concurrent.futures.ThreadPoolExecutor(
        max_workers=max(1, args.threads)
    ) as ex:
        futures = {
            ex.submit(probe_url, u, args.timeout): u for u in to_probe
        }
        done = 0
        total = len(futures)
        for fut in concurrent.futures.as_completed(futures):
            done += 1
            try:
                url, ok, _reason = fut.result()
            except Exception:
                failed += 1
                continue
            if ok:
                valid_urls.append(url)
            else:
                failed += 1

            if done % 25 == 0 or done == total:
                elapsed = time.time() - start
                print(
                    f"    [{done}/{total}] valid={len(valid_urls)} "
                    f"failed={failed}  ({elapsed:.1f}s)",
                    flush=True,
                )

    write_lines(Path(args.url_output), valid_urls)
    print_stage("Validated unique full URLs (200 + HTML)", len(valid_urls))
    print(f"[+] URL output: {args.url_output}")

    if valid_urls:
        valid_hosts = Counter(host_key(u) for u in valid_urls)
        print("[+] Valid hosts:")
        for h, c in sorted(valid_hosts.items(), key=lambda x: (-x[1], x[0])):
            print(f"    {h}: {c}")

    print()
    print("[+] Done.")
    print(f"[+] Parameters : {args.param_output}")
    print(f"[+] URLs       : {args.url_output}")
    print()
    print("[i] Output = FULL URLs (scheme+host+path) from ALL subdomains.")
    print("[i] Pattern-dedupe ON by default: /ide/<any-uuid> -> one representative.")
    print("[i] Only HTTP 200 + HTML Content-Type are kept.")
    print("[i] Use --no-pattern-dedupe or --no-validate if needed.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
