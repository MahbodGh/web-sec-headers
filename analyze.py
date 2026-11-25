"""Turn collect.py output into an adoption table.

    python analyze.py results/iran.csv
    python analyze.py results/iran.csv results/tranco.csv --out results/summary.md
"""

from __future__ import annotations

import argparse
import csv
from pathlib import Path

TRUE = {"true", "True", "1", "yes"}


def truthy(value: str) -> bool:
    return str(value).strip() in TRUE


# (column label, how to decide the site counts)
METRICS: list[tuple[str, callable]] = [
    ("HTTPS reachable", lambda r: r["final_scheme"] == "https"),
    ("Upgrades HTTP to HTTPS", lambda r: truthy(r["https_upgrade"])),
    ("HSTS", lambda r: truthy(r["hsts"])),
    ("HSTS max-age >= 1 year", lambda r: (r["hsts_max_age"] or "0").isdigit() and int(r["hsts_max_age"] or 0) >= 31536000),
    ("CSP (enforced)", lambda r: truthy(r["csp"])),
    ("CSP report-only only", lambda r: truthy(r["csp_report_only"])),
    ("CSP has frame-ancestors", lambda r: truthy(r["csp_frame_ancestors"])),
    ("CSP allows 'unsafe-inline'", lambda r: truthy(r["csp_unsafe_inline"])),
    ("X-Frame-Options", lambda r: truthy(r["xfo"])),
    ("Framing protected (XFO or CSP)", lambda r: truthy(r["framing_protected"])),
    ("X-Content-Type-Options: nosniff", lambda r: truthy(r["xcto"])),
    ("Referrer-Policy", lambda r: bool(r["referrer_policy"].strip())),
    ("Permissions-Policy", lambda r: truthy(r["permissions_policy"])),
    ("Sets at least one cookie", lambda r: int(r["cookies_total"] or 0) > 0),
    ("All cookies Secure", lambda r: int(r["cookies_total"] or 0) > 0
        and int(r["cookies_secure"] or 0) == int(r["cookies_total"] or 0)),
    ("All cookies HttpOnly", lambda r: int(r["cookies_total"] or 0) > 0
        and int(r["cookies_httponly"] or 0) == int(r["cookies_total"] or 0)),
    ("All cookies SameSite", lambda r: int(r["cookies_total"] or 0) > 0
        and int(r["cookies_samesite"] or 0) == int(r["cookies_total"] or 0)),
]


def load(path: Path) -> list[dict]:
    with path.open(encoding="utf-8") as f:
        return list(csv.DictReader(f))


def summarise(rows: list[dict]) -> dict:
    reachable = [r for r in rows if truthy(r["ok"])]
    out = {
        "_total": len(rows),
        "_reachable": len(reachable),
        "_tls_errors": sum(1 for r in rows if truthy(r["tls_error"])),
    }
    for label, test in METRICS:
        hits = 0
        for r in reachable:
            try:
                if test(r):
                    hits += 1
            except Exception:
                pass
        out[label] = hits
    return out


def pct(hits: int, total: int) -> str:
    return "—" if not total else f"{hits / total * 100:.1f}%"


def render(datasets: list[tuple[str, dict]]) -> str:
    lines: list[str] = []
    lines.append("# Security-header adoption\n")

    lines.append("| Dataset | Domains | Reachable | TLS errors |")
    lines.append("|---|---:|---:|---:|")
    for name, s in datasets:
        lines.append(f"| {name} | {s['_total']} | {s['_reachable']} | {s['_tls_errors']} |")
    lines.append("")
    lines.append("Percentages below are of the **reachable** sites in each dataset.\n")

    header = "| Mechanism | " + " | ".join(n for n, _ in datasets) + " |"
    sep = "|---|" + "---:|" * len(datasets)
    lines.append(header)
    lines.append(sep)
    for label, _ in METRICS:
        cells = [pct(s[label], s["_reachable"]) for _, s in datasets]
        lines.append(f"| {label} | " + " | ".join(cells) + " |")
    lines.append("")

    if len(datasets) == 2:
        (name_a, a), (name_b, b) = datasets
        lines.append(f"## Largest gaps ({name_a} vs {name_b})\n")
        gaps = []
        for label, _ in METRICS:
            if not a["_reachable"] or not b["_reachable"]:
                continue
            pa = a[label] / a["_reachable"] * 100
            pb = b[label] / b["_reachable"] * 100
            gaps.append((abs(pa - pb), label, pa, pb))
        gaps.sort(reverse=True)
        lines.append(f"| Mechanism | {name_a} | {name_b} | Difference |")
        lines.append("|---|---:|---:|---:|")
        for diff, label, pa, pb in gaps[:8]:
            lines.append(f"| {label} | {pa:.1f}% | {pb:.1f}% | {pa - pb:+.1f} pp |")
        lines.append("")

    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("csvs", nargs="+", type=Path, help="one or more collect.py outputs")
    ap.add_argument("--out", type=Path, help="also write the table to this Markdown file")
    args = ap.parse_args()

    datasets = []
    for path in args.csvs:
        if not path.exists():
            print(f"missing: {path}")
            return 1
        datasets.append((path.stem, summarise(load(path))))

    report = render(datasets)
    print(report)
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(report, encoding="utf-8")
        print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
