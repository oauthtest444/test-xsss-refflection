#!/usr/bin/env python3
"""
route_params_recon.py

Purpose
-------
From a Wayback/archive URL list:

  1) Extract unique query-parameter names
  2) Keep FULL URLs from ALL hosts / subdomains (no single-host filter)
  3) Pattern-dedupe dynamic segments (UUID / hex / number / id) per host
  4) HTTP GET: keep only HTTP 200 + HTML
  5) Fingerprint by total inline script content length PER SUBDOMAIN
     Keep only ONE URL per unique script-content length PER HOST
     (different subdomains never collapse into each other)
  6) Write final unique URLs

Important:
  - ALL subdomains are kept (no seed-host filter)
  - Script-length dedupe is per-host so every sub appears in output
  - Only obvious static assets are excluded before probing

Dependencies:
    (stdlib only)

Examples:
    python archive_uniq_params_routes_v2.py -f list.txt
    python archive_uniq_params_routes_v2.py -f list.txt -ro all-uniq-routs.txt -t 25 --timeout 8
    python archive_uniq_params_routes_v2.py -f list.txt --no-validate
    python archive_uniq_params_routes_v2.py -f list.txt --no-script-dedupe
"""

from __future__ import annotations

import argparse
import concurrent.futures
import html
import re
import ssl
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, urlparse, urlunparse
from urllib.request import Request, urlopen


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
        r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
        r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
    )),
    ("hex", re.compile(r"^[0-9a-fA-F]{16,}$")),
    ("number", re.compile(r"^\d+$")),
]

INLINE_SCRIPT_RE = re.compile(
    r"<script\b[^>]*>(.*?)</script\s*>",
    re.IGNORECASE | re.DOTALL,
)

DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Safari/537.36"
)

MAX_BODY_BYTES = 2_000_000

_SSL_CTX = ssl.create_default_context()
_SSL_CTX.check_hostname = False
_SSL_CTX.verify_mode = ssl.CERT_NONE


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description=(
            "Archive URLs (ALL subs) -> pattern-dedupe -> 200+HTML -> "
            "unique by inline-script length PER subdomain"
        ),
        add_help=False,
    )
    p.add_argument("--help", action="help", help="Show this help message and exit")
    p.add_argument(
        "-f", "--file", required=True,
        help="File containing archive URLs, one URL per line.",
    )
    p.add_argument(
        "-ro", "--url-output", default="all-uniq-routs.txt",
        help="Final unique full-URL output (default: all-uniq-routs.txt)",
    )
    p.add_argument(
        "-po", "--param-output", default="all-uniq-params.txt",
        help="Unique query-parameter output (default: all-uniq-params.txt)",
    )
    p.add_argument(
        "-t", "--threads", type=int, default=20,
        help="Concurrent HTTP workers (default: 20)",
    )
    p.add_argument(
        "--timeout", type=float, default=8.0,
        help="Per-request timeout in seconds (default: 8)",
    )
    p.add_argument(
        "--no-validate", action="store_true",
        help="Skip HTTP + script-length checks; write pattern-deduped URLs only",
    )
    p.add_argument(
        "--no-pattern-dedupe", action="store_true",
        help="Disable UUID/number/hex path collapse (default: ON)",
    )
    p.add_argument(
        "--no-script-dedupe", action="store_true",
        help="Disable inline-script-length dedupe; keep all 200+HTML URLs",
    )
    p.add_argument(
        "--strict-ui", action="store_true",
        help=(
            "Also drop paths whose first segment is api/graphql/rest/rpc/webhook. "
            "Default OFF so all subdomains are kept."
        ),
    )
    p.add_argument(
        "--max-body", type=int, default=MAX_BODY_BYTES,
        help=f"Max response body bytes to read (default: {MAX_BODY_BYTES})",
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
    if is_static_asset(p.path or "/"):
        return False
    if strict_ui:
        path = p.path or "/"
        first = path.strip("/").split("/", 1)[0].lower() if path.strip("/") else ""
        if first in {"api", "apis", "graphql", "rest", "rpc", "webhook", "webhooks"}:
            return False
    return True


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


def classify_dynamic_segment(segment: str) -> Optional[str]:
    for kind, rx in DYNAMIC_SEGMENT_PATTERNS:
        if rx.fullmatch(segment):
            return kind
    if len(segment) >= 16 and re.fullmatch(r"[A-Za-z0-9_-]+", segment):
        return "id"
    if len(segment) >= 8 and re.fullmatch(r"[0-9a-fA-F]+", segment):
        return "hex"
    return None


def route_pattern(url: str) -> str:
    p = urlparse(url)
    parts = [x for x in p.path.split("/") if x]
    out = []
    for seg in parts:
        kind = classify_dynamic_segment(seg)
        out.append(":" + kind if kind else seg)
    return "/" + "/".join(out) if out else "/"


def unwrap_wayback(url: str) -> str:
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
    p = urlparse(url)
    scheme = (p.scheme or "https").lower()
    netloc = (p.netloc or "").lower()
    path = re.sub(r"/{2,}", "/", p.path or "/")
    return urlunparse((scheme, netloc, path, "", "", ""))


def inline_script_content_length(html_text: str) -> int:
    total = 0
    for m in INLINE_SCRIPT_RE.finditer(html_text):
        total += len(m.group(1))
    return total


def is_html_content_type(headers) -> bool:
    ct = headers.get("Content-Type") or headers.get("content-type") or ""
    ct = ct.lower().split(";")[0].strip()
    return (
        ct in {"text/html", "application/xhtml+xml", "application/html"}
        or ct.startswith("text/html")
    )


def probe_url(
    url: str, timeout: float, max_body: int
) -> Tuple[str, bool, int, str]:
    headers = {
        "User-Agent": DEFAULT_UA,
        "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Connection": "close",
    }
    req = Request(url, headers=headers, method="GET")
    try:
        with urlopen(req, timeout=timeout, context=_SSL_CTX) as resp:
            code = getattr(resp, "status", None) or resp.getcode()
            if code != 200:
                return url, False, -1, f"status={code}"
            if not is_html_content_type(resp.headers):
                return url, False, -1, "not-html"

            chunks: List[bytes] = []
            remaining = max_body
            while remaining > 0:
                block = resp.read(min(65536, remaining))
                if not block:
                    break
                chunks.append(block)
                remaining -= len(block)
            raw = b"".join(chunks)

            charset = "utf-8"
            ct = resp.headers.get("Content-Type") or ""
            m = re.search(r"charset=([^\s;]+)", ct, re.I)
            if m:
                charset = m.group(1).strip("\"'")
            try:
                text = raw.decode(charset, errors="ignore")
            except Exception:
                text = raw.decode("utf-8", errors="ignore")

            script_len = inline_script_content_length(text)
            return url, True, script_len, "ok"

    except HTTPError as e:
        return url, False, -1, f"http={e.code}"
    except URLError as e:
        return url, False, -1, f"urlerr={getattr(e, 'reason', e)}"
    except Exception as e:
        return url, False, -1, f"err={type(e).__name__}"


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

    unique_params = extract_query_parameters(archive_urls)
    write_lines(Path(args.param_output), unique_params)
    print_stage("Unique query parameters", len(unique_params))
    print(f"[+] Parameter output: {args.param_output}")

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

            h = p.hostname.lower()
            raw_host_counter[h] += 1

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

    print_hosts("Hosts present in input (before filters)", raw_host_counter)
    print_stage("Exact-unique candidate full URLs", len(candidates))
    print_hosts("Hosts after static-asset filter", host_counter)

    missing = set(raw_host_counter) - set(host_counter)
    if missing:
        print(f"[!] Hosts fully dropped by static-asset filter ({len(missing)}):")
        for h in sorted(missing):
            print(f"    {h}  (had {raw_host_counter[h]} urls)")

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

        probe_hosts = Counter(host_key(u) for u in to_probe)
        print_hosts("Hosts after pattern-dedupe", probe_hosts)

        if len(candidates) != len(to_probe):
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

    if args.no_validate:
        write_lines(Path(args.url_output), to_probe)
        print(f"[+] URL output (no validation): {args.url_output}")
        print()
        print("[+] Done.")
        return 0

    print(
        f"[+] Probing {len(to_probe)} URLs "
        f"(threads={args.threads}, timeout={args.timeout}s, "
        f"max-body={args.max_body}) ..."
    )

    valid_hits: List[Tuple[str, int]] = []
    failed = 0
    fail_reasons: Counter = Counter()
    start = time.time()

    with concurrent.futures.ThreadPoolExecutor(
        max_workers=max(1, args.threads)
    ) as ex:
        futures = {
            ex.submit(probe_url, u, args.timeout, args.max_body): u
            for u in to_probe
        }
        done = 0
        total = len(futures)
        for fut in concurrent.futures.as_completed(futures):
            done += 1
            try:
                url, ok, script_len, reason = fut.result()
            except Exception as e:
                failed += 1
                fail_reasons[f"exc={type(e).__name__}"] += 1
                continue
            if ok:
                valid_hits.append((url, script_len))
            else:
                failed += 1
                fail_reasons[reason] += 1

            if done % 25 == 0 or done == total:
                elapsed = time.time() - start
                print(
                    f"    [{done}/{total}] valid={len(valid_hits)} "
                    f"failed={failed}  ({elapsed:.1f}s)",
                    flush=True,
                )

    print_stage("HTTP 200 + HTML pages", len(valid_hits))
    if fail_reasons:
        print("[i] Top failure reasons:")
        for r, c in fail_reasons.most_common(8):
            print(f"    {r}: {c}")

    valid_hosts = Counter(host_key(u) for u, _ in valid_hits)
    print_hosts("Hosts with 200+HTML", valid_hosts)

    probed_hosts = Counter(host_key(u) for u in to_probe)
    zero_html = sorted(set(probed_hosts) - set(valid_hosts))
    if zero_html:
        print(f"[!] Hosts probed but no 200+HTML ({len(zero_html)}):")
        for h in zero_html:
            print(f"    {h}  (probed {probed_hosts[h]} urls)")

    # Script-length dedupe PER SUBDOMAIN
    if args.no_script_dedupe:
        final_urls = [u for u, _ in valid_hits]
        print_stage("Keeping all 200+HTML (script-dedupe OFF)", len(final_urls))
    else:
        length_seen_per_host: Dict[str, Set[int]] = defaultdict(set)
        final_urls = []
        collapsed = 0

        for url, script_len in valid_hits:
            h = host_key(url)
            if script_len in length_seen_per_host[h]:
                collapsed += 1
                continue
            length_seen_per_host[h].add(script_len)
            final_urls.append(url)

        print_stage(
            "Unique by inline-script length (per subdomain)",
            len(final_urls),
        )
        if collapsed:
            print(
                f"[i] Collapsed {collapsed} pages sharing the same "
                f"script-content length within their own subdomain"
            )
            print("[i] Use --no-script-dedupe to keep all 200+HTML URLs instead.")

        if length_seen_per_host:
            print("[+] Script-length buckets per host:")
            for h in sorted(length_seen_per_host.keys()):
                print(f"    {h}: {len(length_seen_per_host[h])} unique length(s)")

    write_lines(Path(args.url_output), final_urls)
    print(f"[+] URL output: {args.url_output}")

    if final_urls:
        final_hosts = Counter(host_key(u) for u in final_urls)
        print_hosts("Final hosts in output", final_hosts)

    print()
    print("[+] Done.")
    print(f"[+] Parameters : {args.param_output}")
    print(f"[+] URLs       : {args.url_output}")
    print()
    print("[i] ALL subdomains from the input are considered.")
    print("[i] Script-length dedupe is PER subdomain (hosts never merge).")
    print("[i] Pipeline: pattern-dedupe -> 200+HTML -> unique script-len per host")
    print("[i] --no-script-dedupe  keep every 200+HTML URL")
    print("[i] --no-validate       skip live checks")
    print("[i] --no-pattern-dedupe keep every concrete path")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
