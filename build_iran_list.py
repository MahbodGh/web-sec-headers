"""Build the Iranian domain list from the Tranco top-1M list.

Selection rule: every domain whose TLD is .ir, in Tranco rank order. One
sentence to describe, and anybody can reproduce it.

Writes:
    sites/iran.txt          every domain found, most popular first
    sites/iran-gov.txt      *.gov.ir
    sites/iran-ac.txt       *.ac.ir   (universities)
    sites/iran-sch.txt      *.sch.ir  (schools)
    sites/iran-org.txt      *.org.ir
    sites/iran-co.txt       *.co.ir / *.net.ir / *.id.ir
    sites/iran-other.txt    plain example.ir
    sites/iran-manual.txt   Iranian services on non-.ir domains (curated)

Usage:
    python build_iran_list.py --top 2000
    python build_iran_list.py --top 2000 --from-zip top-1m.csv.zip
"""

from __future__ import annotations

import argparse
import csv
import io
import zipfile
from datetime import date
from pathlib import Path

import requests

TRANCO_URL = "https://tranco-list.eu/top-1m.csv.zip"

# Iranian services on non-.ir domains, which the TLD filter misses. Hand-picked.
MANUAL = [
    "digikala.com",
    "aparat.com",
    "torob.com",
    "basalam.com",
    "zoomit.ir",
    "varzesh3.com",
    "ayandebank.com",
    "enbank.net",
    "cafebazaar.ir",
]

SECTORS = [
    ("gov", ".gov.ir", "government"),
    ("ac", ".ac.ir", "universities"),
    ("sch", ".sch.ir", "schools"),
    ("org", ".org.ir", "non-profit"),
    ("co", (".co.ir", ".net.ir", ".id.ir"), "commercial second level"),
]


def download(from_zip: Path | None) -> tuple[bytes, str]:
    if from_zip:
        return from_zip.read_bytes(), str(from_zip)
    print(f"downloading {TRANCO_URL} ...")
    r = requests.get(TRANCO_URL, timeout=180)
    r.raise_for_status()
    print(f"  got {len(r.content) / 1_000_000:.1f} MB")
    return r.content, TRANCO_URL


def iran_domains(data: bytes) -> list[tuple[int, str]]:
    """Every .ir domain in the list, as (tranco_rank, domain)."""
    found: list[tuple[int, str]] = []
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        with z.open(z.namelist()[0]) as f:
            for rank, domain in csv.reader(io.TextIOWrapper(f, encoding="utf-8")):
                domain = domain.strip().lower()
                if domain.endswith(".ir"):
                    found.append((int(rank), domain))
    return found


def sector_of(domain: str) -> str:
    for key, suffix, _ in SECTORS:
        suffixes = suffix if isinstance(suffix, tuple) else (suffix,)
        if any(domain.endswith(s) for s in suffixes):
            return key
    return "other"


def write_list(path: Path, header: list[str], rows: list[tuple[int, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for line in header:
            f.write(f"# {line}\n")
        f.write("#\n# tranco_rank  domain\n")
        for rank, domain in rows:
            f.write(f"{domain}\n")
    print(f"  {path}  ({len(rows)} domains)")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--top", type=int, default=2000, help="how many .ir domains to keep")
    ap.add_argument("--from-zip", type=Path, help="a top-1m.csv.zip already on disk")
    ap.add_argument("--out-dir", type=Path, default=Path("sites"))
    ap.add_argument("--keep-zip", type=Path, help="also save the downloaded zip here")
    args = ap.parse_args()

    data, source = download(args.from_zip)
    if args.keep_zip:
        args.keep_zip.write_bytes(data)
        print(f"  saved {args.keep_zip}")

    everything = iran_domains(data)
    print(f"found {len(everything)} .ir domains in the list")

    selected = everything[: args.top]
    today = date.today().isoformat()
    provenance = [
        f"Iranian domains from the Tranco top-1M list, downloaded {today}",
        f"source: {source}",
        "selection: every domain whose TLD is .ir, in Tranco rank order",
        f"kept: top {len(selected)} of {len(everything)} found",
        "RECORD THE TRANCO LIST ID IN YOUR NOTES - the list changes daily.",
    ]

    write_list(args.out_dir / "iran.txt", provenance, selected)

    by_sector: dict[str, list[tuple[int, str]]] = {}
    for rank, domain in selected:
        by_sector.setdefault(sector_of(domain), []).append((rank, domain))

    for key, _, label in SECTORS:
        rows = by_sector.get(key, [])
        if rows:
            write_list(args.out_dir / f"iran-{key}.txt", provenance + [f"sector: {label}"], rows)
    if by_sector.get("other"):
        write_list(args.out_dir / "iran-other.txt",
                   provenance + ["sector: direct .ir registrations"], by_sector["other"])

    manual_path = args.out_dir / "iran-manual.txt"
    with manual_path.open("w", encoding="utf-8") as f:
        f.write("# Iranian services on non-.ir domains, added by hand.\n")
        f.write("# Not from Tranco - say so when you describe the dataset.\n")
        for d in MANUAL:
            f.write(d + "\n")
    print(f"  {manual_path}  ({len(MANUAL)} domains)")

    print("\nsector breakdown of the selected domains:")
    for key in list(dict.fromkeys([k for k, _, _ in SECTORS] + ["other"])):
        rows = by_sector.get(key, [])
        if rows:
            share = len(rows) / len(selected) * 100
            print(f"  {key:6} {len(rows):5}  ({share:4.1f}%)")

    print(f"\nnext: python collect.py {args.out_dir / 'iran.txt'} "
          f"--out results/iran.csv --legacy-tls --insecure-retry")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
