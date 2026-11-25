"""Write the Tranco top-N as a domain list for collect.py — the global baseline.

    python fetch_tranco.py --top 10000 --out sites/tranco.txt
    python fetch_tranco.py --from-zip top-1m.csv.zip --top 10000 --out sites/tranco.txt

Tranco changes daily, so record the list ID and date you used.
"""

from __future__ import annotations

import argparse
import csv
import io
import zipfile
from pathlib import Path

import requests

TRANCO_URL = "https://tranco-list.eu/top-1m.csv.zip"


def domains_from_zip(data: bytes, top: int) -> list[str]:
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        name = z.namelist()[0]
        with z.open(name) as f:
            text = io.TextIOWrapper(f, encoding="utf-8")
            out = []
            for rank, domain in csv.reader(text):
                out.append(domain.strip())
                if len(out) >= top:
                    break
            return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--top", type=int, default=10000)
    ap.add_argument("--out", type=Path, default=Path("sites/tranco.txt"))
    ap.add_argument("--from-zip", type=Path, help="a top-1m.csv.zip you already downloaded")
    args = ap.parse_args()

    if args.from_zip:
        data = args.from_zip.read_bytes()
        source = str(args.from_zip)
    else:
        print(f"downloading {TRANCO_URL} ...")
        r = requests.get(TRANCO_URL, timeout=120)
        r.raise_for_status()
        data = r.content
        source = TRANCO_URL

    domains = domains_from_zip(data, args.top)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", encoding="utf-8") as f:
        f.write(f"# Tranco top {len(domains)}\n# source: {source}\n")
        f.write("# record the list ID and the date you downloaded it in your notes\n")
        for d in domains:
            f.write(d + "\n")

    print(f"wrote {args.out} ({len(domains)} domains)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
