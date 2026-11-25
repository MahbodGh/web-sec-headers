"""Same measurement as collect.py, through Chrome via Playwright.

Slower, but it reaches hosts that drop plain Python HTTPS connections during
the handshake. Same CSV columns, so analyze.py reads either output.

    python collect_browser.py sites/iran.txt --out results/iran-browser.csv
    python collect_browser.py sites/iran.txt --out results/retry.csv --only-failed results/iran.csv
"""

from __future__ import annotations

import argparse
import asyncio
import csv
import json
import sys
import urllib.parse
from pathlib import Path

from collect import FIELDS, parse_csp, parse_hsts, read_domains

try:
    from playwright.async_api import async_playwright
except ImportError:  # pragma: no cover
    print("playwright is not installed. Run:  pip install playwright", file=sys.stderr)
    print("then once:                          playwright install chromium", file=sys.stderr)
    raise SystemExit(1)

NAV_TIMEOUT_MS = 35_000


def empty_row(domain: str) -> dict:
    row = {k: "" for k in FIELDS}
    row["domain"] = domain
    row["ok"] = False
    return row


async def measure(context, domain: str) -> dict:
    row = empty_row(domain)
    page = await context.new_page()
    try:
        response = await page.goto(f"http://{domain}/", timeout=NAV_TIMEOUT_MS,
                                   wait_until="domcontentloaded")
        if response is None:
            row["error"] = "no-response"
            return row

        headers = await response.all_headers()
        header_pairs = await response.headers_array()
        final = urllib.parse.urlparse(response.url)

        row["ok"] = True
        row["status"] = response.status
        row["final_url"] = response.url
        row["final_scheme"] = final.scheme
        row["https_upgrade"] = final.scheme == "https"
        row["redirects"] = ""  # Playwright reports the chain per request, not needed here
        row["server"] = headers.get("server", "")[:60]

        csp_value = headers.get("content-security-policy", "")
        csp_ro = headers.get("content-security-policy-report-only", "")
        effective = csp_value or csp_ro
        frame_ancestors, unsafe_inline = parse_csp(effective)

        row["csp"] = bool(csp_value)
        row["csp_report_only"] = bool(csp_ro and not csp_value)
        row["csp_frame_ancestors"] = frame_ancestors
        row["csp_unsafe_inline"] = unsafe_inline
        row["csp_value"] = effective[:300]

        xfo = headers.get("x-frame-options", "")
        row["xfo"] = bool(xfo)
        row["xfo_value"] = xfo[:40]
        row["framing_protected"] = bool(xfo) or frame_ancestors

        hsts = headers.get("strict-transport-security", "")
        max_age, subdomains, preload = parse_hsts(hsts)
        row["hsts"] = bool(hsts)
        row["hsts_max_age"] = max_age if max_age is not None else ""
        row["hsts_subdomains"] = subdomains
        row["hsts_preload"] = preload

        row["xcto"] = headers.get("x-content-type-options", "").strip().lower() == "nosniff"
        row["referrer_policy"] = headers.get("referrer-policy", "")[:40]
        row["permissions_policy"] = bool(headers.get("permissions-policy"))
        row["coop"] = headers.get("cross-origin-opener-policy", "")[:40]

        # Header-level, like collect.py, so the two collectors stay comparable.
        set_cookies = [h["value"] for h in header_pairs if h["name"].lower() == "set-cookie"]
        row["cookies_total"] = len(set_cookies)
        row["cookies_secure"] = sum(1 for c in set_cookies if "secure" in c.lower())
        row["cookies_httponly"] = sum(1 for c in set_cookies if "httponly" in c.lower())
        row["cookies_samesite"] = sum(1 for c in set_cookies if "samesite" in c.lower())

    except Exception as exc:
        row["error"] = f"{type(exc).__name__}: {str(exc)[:60]}"
    finally:
        await page.close()
    return row


async def run(domains: list[str], workers: int, headed: bool) -> list[dict]:
    rows: list[dict] = []
    done = 0
    async with async_playwright() as p:
        try:
            browser = await p.chromium.launch(channel="chrome", headless=not headed)
        except Exception:
            try:
                browser = await p.chromium.launch(headless=not headed)
            except Exception as exc:
                print("could not start a browser.", file=sys.stderr)
                print("install Playwright's own Chromium once:  playwright install chromium",
                      file=sys.stderr)
                print(f"({str(exc)[:120]})", file=sys.stderr)
                raise SystemExit(1)

        semaphore = asyncio.Semaphore(workers)

        async def one(domain: str) -> None:
            nonlocal done
            async with semaphore:
                context = await browser.new_context(
                    ignore_https_errors=True,
                    locale="en-US",
                    viewport={"width": 1280, "height": 800},
                )
                try:
                    rows.append(await measure(context, domain))
                finally:
                    await context.close()
                done += 1
                if done % 10 == 0 or done == len(domains):
                    print(f"  {done}/{len(domains)}")

        await asyncio.gather(*(one(d) for d in domains))
        await browser.close()
    return rows


def failed_domains(path: Path) -> set[str]:
    with path.open(encoding="utf-8") as f:
        return {r["domain"] for r in csv.DictReader(f) if r["ok"] != "True"}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("input", type=Path)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--workers", type=int, default=4, help="parallel browser tabs")
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--only-failed", type=Path,
                    help="a collect.py CSV: measure only the domains that failed there")
    ap.add_argument("--headed", action="store_true", help="show the browser window")
    args = ap.parse_args()

    domains = read_domains(args.input)
    if args.only_failed:
        keep = failed_domains(args.only_failed)
        domains = [d for d in domains if d in keep]
    if args.limit:
        domains = domains[: args.limit]
    if not domains:
        print("no domains to measure", file=sys.stderr)
        return 1

    print(f"measuring {len(domains)} domains in Chrome with {args.workers} tabs")
    rows = asyncio.run(run(domains, args.workers, args.headed))
    rows.sort(key=lambda r: r["domain"])

    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(rows)
    with args.out.with_suffix(".jsonl").open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")

    reached = sum(1 for r in rows if r["ok"])
    print(f"\nwrote {args.out} ({reached}/{len(rows)} reachable)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
