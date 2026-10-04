#!/usr/bin/env python3
"""
route_params_recon.py

Purpose
-------
Extract ONLY:
  1) unique query-parameter names from an archive URL list
  2) unique route representatives (pattern-deduped)

No HTTP validation, no top-level selection, no browser discovery.

Dependencies:
    (stdlib only)

Examples:
    python route_params_recon.py -f list.txt
    python route_params_recon.py -f list.txt -ro my-routes.txt -po my-params.txt
"""

from __future__ import annotations

import argparse
import html
import re
import sys
from pathlib import Path
from typing import Iterable, List, Optional, Set, Tuple
from urllib.parse import (
    parse_qsl,
    urlparse,
    urlunparse,
)


# Deliberately excludes common non-UI resources.
NON_UI_EXTENSIONS = {
    ".js", ".mjs", ".css", ".map", ".png", ".jpg", ".jpeg", ".gif", ".webp",
    ".svg", ".ico", ".bmp", ".tif", ".tiff", ".avif", ".woff", ".woff2",
    ".ttf", ".otf", ".eot", ".pdf", ".zip", ".gz", ".tar", ".tgz", ".rar",
    ".7z", ".gpg", ".asc", ".pem", ".crt", ".txt", ".xml", ".json", ".csv",
    ".mp3", ".mp4", ".wav", ".webm", ".avi", ".mov", ".mkv", ".wasm",
    ".bin", ".exe", ".dmg", ".apk",
}

DYNAMIC_SEGMENT_PATTERNS = [
    ("uuid", re.compile(
        r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-"
        r"[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"
    )),
    ("hex", re.compile(r"^[0-9a-fA-F]{16,}$")),
    ("number", re.compile(r"^\d+$")),
]


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Archive unique query-parameters and route representatives only",
        add_help=False,
    )
    p.add_argument(
        "--help",
        action="help",
        help="Show this help message and exit",
    )
    p.add_argument(
        "-f", "--file", required=True,
        help="File containing archive URLs, one URL per line.",
    )
    p.add_argument(
        "-ro", "--route-output", default="all-uniq-routs.txt",
        help="Final route output file (default: all-uniq-routs.txt)",
    )
    p.add_argument(
        "-po", "--param-output", default="all-uniq-params.txt",
        help="Unique query-parameter output file (default: all-uniq-params.txt)",
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
    if is_non_ui_path(p.path):
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
    """
    IMPORTANT:
      - exact duplicates are removed
      - case is NOT normalized
      - structural-pattern detection is NOT used
      - numbers are normalized
      - UUID/hash-like values are normalized
    """
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
    """
    Conservative similarity clustering.
    Case is intentionally significant.
    """
    if a == b:
        return True

    if len(a) < 5 or len(b) < 5:
        return False

    dist = edit_distance(a, b)
    max_len = max(len(a), len(b))
    ratio = 1 - (dist / max_len)

    return ratio >= 0.82 and dist <= 3


def dedupe_parameters(params: Iterable[str]) -> List[str]:
    # Stage 1: exact dedupe, preserving original spelling/case.
    exact_seen: Set[str] = set()
    exact_unique: List[str] = []
    for p in params:
        p = p.strip()
        if p and p not in exact_seen:
            exact_seen.add(p)
            exact_unique.append(p)

    # Stage 2: number/UUID/hash normalization.
    normalized_seen: Set[str] = set()
    candidates: List[str] = []
    for p in exact_unique:
        key = normalize_parameter_for_dedup(p)
        if key not in normalized_seen:
            normalized_seen.add(key)
            candidates.append(p)

    # Stage 3: conservative similarity clustering.
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
                query,
                keep_blank_values=True,
                strict_parsing=False,
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
# Route pattern reconstruction
# ---------------------------------------------------------------------------

def classify_dynamic_segment(segment: str) -> Optional[str]:
    for kind, rx in DYNAMIC_SEGMENT_PATTERNS:
        if rx.fullmatch(segment):
            return kind

    if len(segment) >= 20 and re.fullmatch(r"[A-Za-z0-9_-]+", segment):
        return "id"

    return None


def route_pattern(url: str) -> str:
    """
    Convert a concrete route into a dedupe pattern.

    Examples:
      /users/123 -> /users/:number
      /orders/<uuid> -> /orders/:uuid
    """
    p = urlparse(url)
    parts = [x for x in p.path.split("/") if x]

    out = []
    for seg in parts:
        kind = classify_dynamic_segment(seg)
        if kind:
            out.append(":" + kind)
        else:
            out.append(seg)

    return "/" + "/".join(out) if out else "/"


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

    # Determine target host from the first usable archive URL.
    parsed_seed = None
    for u in archive_urls:
        try:
            p = urlparse(u)
            if p.scheme in {"http", "https"} and p.hostname:
                parsed_seed = p
                break
        except Exception:
            pass

    if parsed_seed is None:
        print("[!] No valid HTTP(S) URL found in -f file.", file=sys.stderr)
        return 1

    target_host = parsed_seed.hostname.lower()

    print(f"[+] Target host: {target_host}")
    print(f"[+] Seed URLs: {len(archive_urls)}")

    # ================================================================
    # PARAMETER PIPELINE
    # ================================================================
    unique_params = extract_query_parameters(archive_urls)
    write_lines(Path(args.param_output), unique_params)
    print_stage("Unique query parameters", len(unique_params))
    print(f"[+] Parameter output: {args.param_output}")

    # ================================================================
    # ROUTE PIPELINE - archive unique representatives only
    # ================================================================
    archive_route_candidates = []

    for raw in archive_urls:
        try:
            p = urlparse(raw)
            if not p.hostname:
                continue
            if p.hostname.lower() != target_host:
                continue

            route_url = urlunparse(
                (p.scheme, p.netloc, p.path or "/", p.params, "", "")
            )

            if looks_like_ui_route(route_url):
                archive_route_candidates.append(route_url)
        except Exception:
            continue

    # Pattern-based route dedupe.
    pattern_seen: Set[Tuple[str, str]] = set()
    archive_unique: List[str] = []

    for u in archive_route_candidates:
        key = (host_key(u), route_pattern(u))
        if key in pattern_seen:
            continue
        pattern_seen.add(key)
        archive_unique.append(u)

    write_lines(Path(args.route_output), archive_unique)
    print_stage("Archive unique route representatives", len(archive_unique))
    print(f"[+] Route output: {args.route_output}")

    print()
    print("[+] Done.")
    print(f"[+] Parameters : {args.param_output}")
    print(f"[+] Routes     : {args.route_output}")
    print()
    print("[i] Route output contains full URLs (pattern-deduped).")
    print("[i] Parameter output contains query parameter names only.")
    print("[i] No HTTP validation, browser discovery, or further steps.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
