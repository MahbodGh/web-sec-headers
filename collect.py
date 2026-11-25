"""Collect security headers for a list of domains.

One GET of each home page, robots.txt honoured. No login, no injected input.

    python collect.py sites/iran.txt --out results/iran.csv
    python collect.py sites/tranco.txt --out results/tranco.csv --workers 12
"""

from __future__ import annotations

import argparse
import csv
import json
import random
import re
import ssl
import sys
import time
import urllib.parse
import urllib.robotparser
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.ssl_ import create_urllib3_context

# Set CONTACT to a page or address if you want site owners to be able to reach you.
CONTACT = ""
USER_AGENT = (
    "WebSecMeasurementBot/1.0 (passive security-header survey; "
    "home page only; respects robots.txt"
    + (f"; contact: {CONTACT}" if CONTACT else "")
    + ")"
)

CONNECT_TIMEOUT = 15
READ_TIMEOUT = 30
RETRIES = 1


class LegacyTLSAdapter(HTTPAdapter):
    """Reach servers on old TLS versions or weak ciphers.

    Without this they count as unreachable when they are only out of date,
    which is common on .ir hosts.
    """

    def __init__(self, *args, insecure: bool = False, **kwargs):
        ctx = create_urllib3_context()
        try:
            ctx.set_ciphers("DEFAULT@SECLEVEL=1")
        except ssl.SSLError:
            pass
        try:
            ctx.minimum_version = ssl.TLSVersion.TLSv1
        except (AttributeError, ValueError):
            pass
        # Tolerate servers that do not support secure renegotiation.
        ctx.options |= getattr(ssl, "OP_LEGACY_SERVER_CONNECT", 0x4)
        if insecure:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        self._ctx = ctx
        super().__init__(*args, **kwargs)

    def init_poolmanager(self, *args, **kwargs):
        kwargs["ssl_context"] = self._ctx
        return super().init_poolmanager(*args, **kwargs)

    def proxy_manager_for(self, *args, **kwargs):
        kwargs["ssl_context"] = self._ctx
        return super().proxy_manager_for(*args, **kwargs)

FIELDS = [
    "domain",
    "ok",
    "error",
    "status",
    "final_url",
    "final_scheme",
    "https_upgrade",      # http:// redirected to https://
    "redirects",
    "tls_error",          # certificate failed to verify
    "server",
    "csp",                # Content-Security-Policy present
    "csp_report_only",    # only Content-Security-Policy-Report-Only present
    "csp_frame_ancestors",
    "csp_unsafe_inline",  # script-src allows 'unsafe-inline'
    "csp_value",
    "xfo",                # X-Frame-Options present
    "xfo_value",
    "framing_protected",  # XFO or CSP frame-ancestors
    "hsts",
    "hsts_max_age",
    "hsts_subdomains",
    "hsts_preload",
    "xcto",               # X-Content-Type-Options: nosniff
    "referrer_policy",
    "permissions_policy",
    "coop",               # Cross-Origin-Opener-Policy
    "cookies_total",
    "cookies_secure",
    "cookies_httponly",
    "cookies_samesite",
    "elapsed_ms",
]


def build_session(legacy_tls: bool = False, insecure: bool = False) -> requests.Session:
    s = requests.Session()
    s.headers.update(
        {
            "User-Agent": USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9,fa;q=0.8",
        }
    )
    if legacy_tls or insecure:
        s.mount("https://", LegacyTLSAdapter(insecure=insecure))
    return s


def robots_allows(session: requests.Session, scheme: str, domain: str, path: str = "/") -> bool:
    """True when robots.txt allows us, or when it cannot be read at all."""
    url = f"{scheme}://{domain}/robots.txt"
    try:
        r = session.get(url, timeout=(CONNECT_TIMEOUT, READ_TIMEOUT), allow_redirects=True)
        if r.status_code >= 400 or not r.text.strip():
            return True  # no usable robots.txt means no restriction
        rp = urllib.robotparser.RobotFileParser()
        rp.parse(r.text.splitlines())
        return rp.can_fetch(USER_AGENT, f"{scheme}://{domain}{path}")
    except Exception:
        return True


def get_set_cookie_headers(resp: requests.Response) -> list[str]:
    """Every Set-Cookie line, not just the last one requests folded together."""
    try:
        return list(resp.raw.headers.getlist("Set-Cookie"))
    except Exception:
        value = resp.headers.get("Set-Cookie")
        return [value] if value else []


def parse_hsts(value: str) -> tuple[int | None, bool, bool]:
    if not value:
        return None, False, False
    m = re.search(r"max-age\s*=\s*\"?(\d+)", value, re.I)
    max_age = int(m.group(1)) if m else None
    return (
        max_age,
        bool(re.search(r"includeSubDomains", value, re.I)),
        bool(re.search(r"preload", value, re.I)),
    )


def parse_csp(value: str) -> tuple[bool, bool]:
    """(has frame-ancestors, script-src allows 'unsafe-inline')."""
    if not value:
        return False, False
    lowered = value.lower()
    has_fa = "frame-ancestors" in lowered
    unsafe = False
    for directive in lowered.split(";"):
        directive = directive.strip()
        if directive.startswith("script-src") or directive.startswith("default-src"):
            if "'unsafe-inline'" in directive:
                unsafe = True
    return has_fa, unsafe


def fetch(domain: str, respect_robots: bool, insecure_retry: bool,
          legacy_tls: bool = False) -> dict:
    """One domain. Starts at http:// so the HTTPS upgrade itself is measured."""
    row = {k: "" for k in FIELDS}
    row["domain"] = domain
    row["ok"] = False
    session = build_session(legacy_tls=legacy_tls)
    started = time.perf_counter()

    if respect_robots and not robots_allows(session, "https", domain):
        row["error"] = "disallowed-by-robots"
        row["elapsed_ms"] = int((time.perf_counter() - started) * 1000)
        return row

    resp = None
    tls_error = False
    last_error = ""

    for scheme in ("http", "https"):
        for attempt in range(RETRIES + 1):
            try:
                resp = session.get(
                    f"{scheme}://{domain}/",
                    timeout=(CONNECT_TIMEOUT, READ_TIMEOUT),
                    allow_redirects=True,
                )
                break
            except requests.exceptions.SSLError as exc:
                tls_error = True
                last_error = f"ssl: {type(exc).__name__}"
                if insecure_retry:
                    try:
                        loose = build_session(insecure=True)
                        resp = loose.get(
                            f"{scheme}://{domain}/",
                            timeout=(CONNECT_TIMEOUT, READ_TIMEOUT),
                            allow_redirects=True,
                            verify=False,
                        )
                        break
                    except Exception as exc2:
                        last_error = f"ssl-retry: {type(exc2).__name__}"
                break
            except Exception as exc:
                last_error = f"{type(exc).__name__}"
                if attempt < RETRIES:
                    time.sleep(1 + random.random())
        if resp is not None:
            break

    row["tls_error"] = tls_error
    if resp is None:
        row["error"] = last_error or "unreachable"
        row["elapsed_ms"] = int((time.perf_counter() - started) * 1000)
        return row

    h = resp.headers
    final = urllib.parse.urlparse(resp.url)

    row["ok"] = True
    row["status"] = resp.status_code
    row["final_url"] = resp.url
    row["final_scheme"] = final.scheme
    row["https_upgrade"] = final.scheme == "https"
    row["redirects"] = len(resp.history)
    row["server"] = h.get("Server", "")[:60]

    csp_value = h.get("Content-Security-Policy", "")
    csp_ro = h.get("Content-Security-Policy-Report-Only", "")
    effective_csp = csp_value or csp_ro
    frame_ancestors, unsafe_inline = parse_csp(effective_csp)

    row["csp"] = bool(csp_value)
    row["csp_report_only"] = bool(csp_ro and not csp_value)
    row["csp_frame_ancestors"] = frame_ancestors
    row["csp_unsafe_inline"] = unsafe_inline
    row["csp_value"] = effective_csp[:300]

    xfo = h.get("X-Frame-Options", "")
    row["xfo"] = bool(xfo)
    row["xfo_value"] = xfo[:40]
    row["framing_protected"] = bool(xfo) or frame_ancestors

    hsts = h.get("Strict-Transport-Security", "")
    max_age, subdomains, preload = parse_hsts(hsts)
    row["hsts"] = bool(hsts)
    row["hsts_max_age"] = max_age if max_age is not None else ""
    row["hsts_subdomains"] = subdomains
    row["hsts_preload"] = preload

    row["xcto"] = h.get("X-Content-Type-Options", "").strip().lower() == "nosniff"
    row["referrer_policy"] = h.get("Referrer-Policy", "")[:40]
    row["permissions_policy"] = bool(h.get("Permissions-Policy"))
    row["coop"] = h.get("Cross-Origin-Opener-Policy", "")[:40]

    cookies = get_set_cookie_headers(resp)
    row["cookies_total"] = len(cookies)
    row["cookies_secure"] = sum(1 for c in cookies if re.search(r";\s*secure", c, re.I))
    row["cookies_httponly"] = sum(1 for c in cookies if re.search(r";\s*httponly", c, re.I))
    row["cookies_samesite"] = sum(1 for c in cookies if re.search(r";\s*samesite", c, re.I))

    row["elapsed_ms"] = int((time.perf_counter() - started) * 1000)
    return row


def read_domains(path: Path) -> list[str]:
    seen, out = set(), []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip().lower()
        if not line:
            continue
        line = line.removeprefix("https://").removeprefix("http://").rstrip("/")
        if line and line not in seen:
            seen.add(line)
            out.append(line)
    return out


def main() -> int:
    global CONNECT_TIMEOUT, READ_TIMEOUT
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("input", type=Path, help="text file, one domain per line")
    ap.add_argument("--out", type=Path, required=True, help="CSV to write")
    ap.add_argument("--workers", type=int, default=8, help="parallel requests (keep it polite)")
    ap.add_argument("--limit", type=int, default=0, help="only the first N domains")
    ap.add_argument("--no-robots", action="store_true", help="skip the robots.txt check")
    ap.add_argument("--insecure-retry", action="store_true",
                    help="on a TLS failure, retry without verification just to read the headers")
    ap.add_argument("--legacy-tls", action="store_true",
                    help="also accept old TLS versions and weak ciphers (many .ir sites need this)")
    ap.add_argument("--timeout", type=float, nargs=2, metavar=("CONNECT", "READ"),
                    help=f"override timeouts in seconds (default {CONNECT_TIMEOUT} {READ_TIMEOUT})")
    ap.add_argument("--resume", action="store_true",
                    help="continue an interrupted run: skip domains already in the .jsonl")
    args = ap.parse_args()

    if args.timeout:
        CONNECT_TIMEOUT, READ_TIMEOUT = args.timeout

    if args.insecure_retry:
        requests.packages.urllib3.disable_warnings()  # type: ignore[attr-defined]

    domains = read_domains(args.input)
    if args.limit:
        domains = domains[: args.limit]
    if not domains:
        print("no domains to measure", file=sys.stderr)
        return 1

    args.out.parent.mkdir(parents=True, exist_ok=True)
    raw_path = args.out.with_suffix(".jsonl")

    # Each result is appended to the .jsonl as it lands, so an interrupted run
    # can be continued with --resume.
    already: dict[str, dict] = {}
    if args.resume and raw_path.exists():
        for line in raw_path.read_text(encoding="utf-8").splitlines():
            try:
                row = json.loads(line)
                already[row["domain"]] = row
            except Exception:
                continue
        todo = [d for d in domains if d not in already]
        print(f"resuming: {len(already)} already measured, {len(todo)} left")
        domains = todo
    elif raw_path.exists() and not args.resume:
        print(f"note: overwriting {raw_path} (pass --resume to continue it instead)")

    started = time.perf_counter()
    print(f"measuring {len(domains)} domains with {args.workers} workers")
    done = 0
    mode = "a" if (args.resume and raw_path.exists()) else "w"
    with raw_path.open(mode, encoding="utf-8") as raw, \
            ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {
            pool.submit(fetch, d, not args.no_robots, args.insecure_retry, args.legacy_tls): d
            for d in domains
        }
        for fut in as_completed(futures):
            domain = futures[fut]
            try:
                row = fut.result()
            except Exception as exc:  # a bug in fetch(), not a site problem
                row = {k: "" for k in FIELDS}
                row.update(domain=domain, ok=False, error=f"crash: {type(exc).__name__}")
            already[domain] = row
            raw.write(json.dumps(row, ensure_ascii=False) + "\n")
            raw.flush()
            done += 1
            if done % 25 == 0 or done == len(domains):
                elapsed = time.perf_counter() - started
                rate = done / elapsed if elapsed else 0
                left = (len(domains) - done) / rate if rate else 0
                print(f"  {done}/{len(domains)}  ~{left / 60:.0f} min left")

    rows = sorted(already.values(), key=lambda r: r["domain"])
    with args.out.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(rows)

    reached = sum(1 for r in rows if r["ok"])
    print(f"\nwrote {args.out} ({reached}/{len(rows)} reachable)")
    print(f"wrote {raw_path}")
    print("next: python analyze.py", args.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
