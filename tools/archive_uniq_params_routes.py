#!/usr/bin/env python3
"""
route_params_recon.py

Purpose
-------
From a Wayback/archive URL list:

  1) Extract unique query-parameter names
  2) Keep FULL URLs from ALL hosts / subdomains (no single-host filter)
  3) Dedupe:
       - exact unique full URLs (scheme+host+path)
       - pattern-dedupe dynamic segments per host
         (:uuid / :hex / :number / :id)
  4) Write unique full URLs to one file

No HTTP validation. No browser discovery.

Dependencies:
    (stdlib only)

Examples:
    python archive_uniq_params_routes.py -f list.txt
    python archive_uniq_params_routes.py -f list.txt -ro all-uniq-routs.txt -po all-uniq-params.txt
    python archive_uniq_params_routes.py -f list.txt --no-pattern-dedupe
"""

from __future__ import annotations

import argparse
import html
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple
from urllib.parse import parse_qsl, urlparse, urlunparse


NON_UI_EXTENSIONS = {
    ".js", ".mjs", ".css", ".map", ".png", ".jpg", ".jpeg", ".gif", ".webp",
    ".svg", ".ico", ".bmp", ".tif", ".tiff", ".avif", ".woff", ".woff2",
    ".ttf", ".otf", ".eot", ".pdf", ".zip", ".gz", ".tar", ".tgz", ".rar",
    ".7z", ".gpg", ".asc", ".pem", ".crt", ".txt", ".xml", ".json", ".csv",
    ".mp3", ".mp4", ".wav", ".webm", ".avi", ".mov", ".mkv", ".wasm",
    ".bin", ".exe", ".dmg", ".apk",
}

# Relaxed UUID: any 8-4-4-4-12 hex (including nil / non-RFC version)
DYNAMIC_SEGMENT_PATTERNS = [
    ("uuid", re.compile(
        r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
        r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
    )),
    ("hex", re.compile(r"^[0-9a-fA-F]{16,}$")),
    ("number", re.compile(r"^\d+$")),
]


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description=(
            "Archive unique query-parameters + full-URL dedupe "
            "(ALL subdomains, pattern-deduped)"
        ),
        add_help=False,
    )
    p.add_argument("--help", action="help", help="Show this help message and exit")
    p.add_argument(
        "-f", "--file", required=True,
        help="File containing archive URLs, one URL per line.",
    )
    p.add_argument(
        "-ro", "--route-output", default="all-uniq-routs.txt",
        help="Final route/URL output file (default: all-uniq-routs.txt)",
    )
    p.add_argument(
        "-po", "--param-output", default="all-uniq-params.txt",
        help="Unique query-parameter output (default: all-uniq-params.txt)",
    )
    p.add_argument(
        "--no-pattern-dedupe", action="store_true",
        help="Disable UUID/number/hex path collapse (default: ON)",
    )
    p.add_argument(
        "--strict-ui", action="store_true",
        help=(
            "Also drop paths whose first segment is api/graphql/rest/rpc/webhook. "
            "Default OFF so all subdomains are kept."
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


def is_static_asset(path: str) -> bool:
    lower = path.lower()
    last = lower.rsplit("/", 1)[-1]
    if "." in last:
        suffix = "." + last.rsplit(".", 1)[-1]
        if suffix in NON_UI_EXTENSIONS:
            return True
    return False


def looks_like_candidate(url: str, strict_ui: bool) -> bool:
    p = urlparse(url)
    if p.scheme not in {"http", "https"}:
        return False
    if "/cdn-cgi/challenge-platform/" in (p.path or "").lower():
        return False
    if is_static_asset(p.path or "/"):
        return False
    if strict_ui:
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
    return (1 - dist / max_len) >= 0.82 and dist <= 3


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
                name = html.unescape(name).strip().lstrip("?&;")
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
    """Classify a complete path segment as dynamic."""
    for kind, rx in DYNAMIC_SEGMENT_PATTERNS:
        if rx.fullmatch(segment):
            return kind
    if len(segment) >= 16 and re.fullmatch(r"[A-Za-z0-9_-]+", segment):
        return "id"
    if len(segment) >= 8 and re.fullmatch(r"[0-9a-fA-F]+", segment):
        return "hex"
    return None


# Embedded dynamic values are common in archive URLs.  Keep the stable
# prefix/suffix and normalize only the changing part.
EMBEDDED_DYNAMIC_PATTERNS = [
    (
        "uuid",
        re.compile(
            r"^(?P<prefix>.*?)(?P<value>"
            r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
            r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
            r")(?:$|(?P<suffix>\.[A-Za-z0-9_-]+))"
        ),
    ),
    (
        "number",
        re.compile(
            r"^(?P<prefix>.*?)(?:[_\-=])(?P<value>\d{3,})"
            r"(?P<suffix>\.[A-Za-z0-9_-]+)?$"
        ),
    ),
    (
        "number",
        re.compile(r"^(?P<value>\d{3,})(?P<suffix>\.[A-Za-z0-9_-]+)?$"),
    ),
    (
        "hex",
        re.compile(
            r"^(?P<prefix>.*?)(?:[_\-=])(?P<value>[0-9a-fA-F]{8,})"
            r"(?P<suffix>\.[A-Za-z0-9_-]+)?$"
        ),
    ),
]


def normalize_embedded_dynamic_segment(segment: str) -> str:
    """Normalize dynamic values inside path/file-name segments."""
    kind = classify_dynamic_segment(segment)
    if kind:
        # Preserve extensions for pure dynamic filenames.
        m = re.fullmatch(r"(\d+|[0-9a-fA-F]{8,})(\.[A-Za-z0-9_-]+)?", segment)
        if m and m.group(2):
            return (":number" if m.group(1).isdigit() else ":hex") + m.group(2)
        return ":" + kind

    for kind, rx in EMBEDDED_DYNAMIC_PATTERNS:
        m = rx.fullmatch(segment)
        if not m:
            continue
        prefix = m.groupdict().get("prefix") or ""
        suffix = m.groupdict().get("suffix") or ""
        return prefix + ":" + kind + suffix

    return segment


def route_pattern(url: str) -> str:
    """
    Build a stable route pattern while preserving static text.

    Examples:
      /users/123 -> /users/:number
      /svn/archives/000954.php -> /svn/archives/:number.php
      /svn/archives2/edward_hall_the_perfect_group_size_812.php
        -> /svn/archives2/edward_hall_the_perfect_group_size_:number.php
      /akam/13/pixel_64dec186 -> /akam/13/pixel_:hex
    """
    p = urlparse(url)
    parts = [x for x in p.path.split("/") if x]
    out = [normalize_embedded_dynamic_segment(seg) for seg in parts]
    return "/" + "/".join(out) if out else "/"


def unwrap_wayback(url: str) -> str:
    """If line is a Wayback wrapper, return the original target URL."""
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
    """scheme + host + path (no query, no fragment)."""
    p = urlparse(url)
    scheme = (p.scheme or "https").lower()
    netloc = (p.netloc or "").lower()
    path = re.sub(r"/{2,}", "/", p.path or "/")
    return urlunparse((scheme, netloc, path, "", "", ""))


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


def print_hosts(title: str, counter: Counter, limit: int = 50) -> None:
    if not counter:
        return
    print(f"[+] {title} ({len(counter)} hosts):")
    for h, c in sorted(counter.items(), key=lambda x: (-x[1], x[0]))[:limit]:
        print(f"    {h}: {c}")
    if len(counter) > limit:
        print(f"    ... and {len(counter) - limit} more hosts")


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
    # FULL-URL PIPELINE – ALL hosts / subdomains (no single-host filter)
    # ================================================================
    raw_host_counter: Counter = Counter()
    candidates: List[str] = []
    exact_seen: Set[str] = set()
    host_counter: Counter = Counter()

    for raw in archive_urls:
        try:
            cleaned = html.unescape(raw).strip()
            cleaned = unwrap_wayback(cleaned)

            p = urlparse(cleaned)
            if p.scheme not in {"http", "https"} or not p.hostname:
                continue

            raw_host_counter[p.hostname.lower()] += 1

            full = normalize_full_url(cleaned)
            if full in exact_seen:
                continue
            exact_seen.add(full)

            if not looks_like_candidate(full, strict_ui=args.strict_ui):
                continue

            candidates.append(full)
            host_counter[host_key(full)] += 1
        except Exception:
            continue

    print_hosts("Hosts present in input", raw_host_counter)
    print_stage("Exact-unique full URLs (all hosts)", len(candidates))
    print_hosts("Hosts after static-asset filter", host_counter)

    # Pattern-dedupe ON by default (per host)
    final_urls: List[str] = candidates
    if not args.no_pattern_dedupe:
        pattern_seen: Set[Tuple[str, str]] = set()
        pattern_unique: List[str] = []
        for u in candidates:
            key = (host_key(u), route_pattern(u))
            if key in pattern_seen:
                continue
            pattern_seen.add(key)
            pattern_unique.append(u)
        final_urls = pattern_unique
        print_stage("After pattern-dedupe (per host)", len(final_urls))

        final_hosts = Counter(host_key(u) for u in final_urls)
        print_hosts("Hosts after pattern-dedupe", final_hosts)

        if len(candidates) != len(final_urls):
            print("[i] Example pattern collapses (up to 5):")
            groups: Dict[Tuple[str, str], List[str]] = defaultdict(list)
            for u in candidates:
                groups[(host_key(u), route_pattern(u))].append(u)
            shown = 0
            for key, urls in groups.items():
                if len(urls) > 1:
                    print(f"    {key[0]}{key[1]}  <- {len(urls)} urls, kept: {urls[0]}")
                    shown += 1
                    if shown >= 5:
                        break

    write_lines(Path(args.route_output), final_urls)
    print(f"[+] URL output: {args.route_output}")

    if final_urls:
        out_hosts = Counter(host_key(u) for u in final_urls)
        print_hosts("Final hosts in output", out_hosts)

    print()
    print("[+] Done.")
    print(f"[+] Parameters : {args.param_output}")
    print(f"[+] URLs       : {args.route_output}")
    print()
    print("[i] ALL subdomains kept (no single-host filter).")
    print("[i] Full URLs (scheme+host+path), pattern-deduped per host.")
    print("[i] Use --no-pattern-dedupe to keep every concrete path.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
