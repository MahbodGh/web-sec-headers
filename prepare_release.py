"""Prepare the published dataset from a local run.

Two jobs:

1. Write per-sector aggregate figures to results/sectors.md.
2. Write results/iran.csv for publication with the per-domain rows of one or
   more sectors held back. Those sectors appear in the aggregate table only.

Per-domain records for government hosts are not published. The aggregate is,
and the domain list itself is reproducible with build_iran_list.py, so the
figures can be checked without a per-host inventory of which government site
lacks which header.

    python prepare_release.py
    python prepare_release.py --withhold gov ac
"""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path

from collect import FIELDS

TRUE = {True, "true", "True", "1"}

SECTOR_SUFFIXES = {
    "gov": (".gov.ir",),
    "ac": (".ac.ir",),
    "sch": (".sch.ir",),
    "org": (".org.ir",),
    "co": (".co.ir", ".net.ir", ".id.ir"),
}

SECTOR_LABEL = {
    "gov": "Government (.gov.ir)",
    "ac": "Universities (.ac.ir)",
    "sch": "Schools (.sch.ir)",
    "org": "Non-profit (.org.ir)",
    "co": "Commercial 2nd level",
    "other": "Direct .ir registrations",
}

METRICS = [
    ("hsts", "HSTS"),
    ("csp", "CSP"),
    ("framing_protected", "Framing protected"),
    ("xcto", "nosniff"),
    ("referrer_policy", "Referrer-Policy"),
]


def truthy(v) -> bool:
    return v in TRUE


def sector_of(domain: str) -> str:
    for key, suffixes in SECTOR_SUFFIXES.items():
        if any(domain.endswith(s) for s in suffixes):
            return key
    return "other"


def load_jsonl(path: Path) -> list[dict]:
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        try:
            rows.append(json.loads(line))
        except Exception:
            continue
    # last write per domain wins, as in collect.py
    by_domain = {r["domain"]: r for r in rows}
    return sorted(by_domain.values(), key=lambda r: r["domain"])


def rate(rows: list[dict], col: str) -> str:
    if not rows:
        return "—"
    if col == "referrer_policy":
        hits = sum(1 for r in rows if str(r.get(col) or "").strip())
    else:
        hits = sum(1 for r in rows if truthy(r.get(col)))
    return f"{hits / len(rows) * 100:.1f}%"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--raw", type=Path, default=Path("results/iran.jsonl"),
                    help="the full local run (not published)")
    ap.add_argument("--out-csv", type=Path, default=Path("results/iran.csv"))
    ap.add_argument("--out-md", type=Path, default=Path("results/sectors.md"))
    ap.add_argument("--withhold", nargs="*", default=["gov"],
                    help="sectors whose per-domain rows stay out of the CSV")
    args = ap.parse_args()

    if not args.raw.exists():
        print(f"missing {args.raw} — run collect.py first")
        return 1

    rows = load_jsonl(args.raw)
    reachable = [r for r in rows if truthy(r.get("ok"))]

    buckets: dict[str, list[dict]] = {}
    for r in reachable:
        buckets.setdefault(sector_of(r["domain"]), []).append(r)

    lines = ["# Adoption by sector", ""]
    lines.append("Percentages are of the reachable sites in each sector.")
    lines.append("")
    lines.append("| Sector | Reachable | " + " | ".join(label for _, label in METRICS) + " |")
    lines.append("|---|---:|" + "---:|" * len(METRICS))
    for key in ["gov", "ac", "sch", "org", "co", "other"]:
        group = buckets.get(key, [])
        if not group:
            continue
        cells = " | ".join(rate(group, col) for col, _ in METRICS)
        lines.append(f"| {SECTOR_LABEL[key]} | {len(group)} | {cells} |")
    lines.append(f"| **All** | **{len(reachable)}** | "
                 + " | ".join(f"**{rate(reachable, col)}**" for col, _ in METRICS) + " |")
    lines.append("")
    if args.withhold:
        names = ", ".join(SECTOR_LABEL.get(s, s) for s in args.withhold)
        lines.append(f"Per-domain records for {names} are not published; those sectors "
                     f"appear here in aggregate only. Every other sector is in "
                     f"`results/iran.csv` row by row, and `build_iran_list.py` "
                     f"reproduces the domain list.")
        lines.append("")

    args.out_md.parent.mkdir(parents=True, exist_ok=True)
    args.out_md.write_text("\n".join(lines), encoding="utf-8")
    print(f"wrote {args.out_md}")

    withheld = set(args.withhold or [])
    published = [r for r in rows if sector_of(r["domain"]) not in withheld]
    with args.out_csv.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDS, extrasaction="ignore")
        writer.writeheader()
        for r in published:
            writer.writerow({k: r.get(k, "") for k in FIELDS})
    held = len(rows) - len(published)
    print(f"wrote {args.out_csv} ({len(published)} rows, {held} withheld)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
