# Security headers on the Iranian web

How widely are browser-enforced security mechanisms deployed on `.ir` sites,
and how does that compare to the global web?

Passive measurement: one GET of each home page, the same request a browser
makes when someone types the domain. No authentication, no injected input, no
vulnerability testing. `robots.txt` is honoured by default.

## Results, 25 November 2026

3,154 Iranian domains (2,800 reachable) against the Tranco top 10k
(7,277 reachable). Percentages are of reachable sites.

| Mechanism | Iran | Tranco 10k | Difference |
|---|---:|---:|---:|
| Framing protection (XFO or CSP `frame-ancestors`) | 33.1% | 54.9% | −21.7 pp |
| `X-Frame-Options` | 30.7% | 49.3% | −18.7 pp |
| HSTS | 30.8% | 48.6% | −17.8 pp |
| `Referrer-Policy` | 20.6% | 36.6% | −16.0 pp |
| `X-Content-Type-Options: nosniff` | 28.8% | 44.4% | −15.6 pp |
| CSP (enforced) | 21.9% | 33.0% | −11.1 pp |
| `Permissions-Policy` | 9.5% | 17.3% | −7.7 pp |

Full table in [`results/summary.md`](results/summary.md), per-domain data in
`results/*.csv`.

### The gap is not explained by CDN use

A plausible objection is that the global sites sit behind CDNs that add these
headers for them. Splitting both datasets by whether a CDN served the response
does not account for the difference:

| Group | n | HSTS | CSP | Framing |
|---|---:|---:|---:|---:|
| Tranco, CDN | 3,064 | 40.2% | 34.8% | 63.4% |
| Tranco, no CDN | 4,213 | 54.7% | 31.7% | 48.6% |
| Iran, CDN | 465 | 34.0% | 43.9% | 35.3% |
| Iran, no CDN | 2,335 | 30.1% | 17.5% | 32.7% |

Iranian sites trail their global counterparts in both groups. One side effect
is visible though: Iranian sites behind a CDN carry CSP at 43.9% against 17.5%
for the rest, so the local CDN does raise CSP deployment.

### The lag is in the long tail, not in the institutions

Splitting the Iranian data by sector moves the story. Government and university
sites are at or above the global level; the gap comes from the 2,614 ordinary
`.ir` registrations that make up most of the dataset.

| Sector | Reachable | HSTS | CSP | Framing protected |
|---|---:|---:|---:|---:|
| Government (`.gov.ir`) | 20 | 70.0% | 50.0% | 85.0% |
| Universities (`.ac.ir`) | 150 | 51.3% | 41.3% | 70.7% |
| Direct `.ir` registrations | 2,614 | 29.2% | 20.6% | 30.5% |
| All Iranian sites | 2,800 | 30.8% | 21.9% | 33.1% |
| Tranco top 10k | 7,277 | 48.6% | 33.0% | 54.9% |

Twenty reachable government hosts is a small sample and the percentages are
correspondingly noisy, so treat that row as an indication rather than a
measurement. Full table in [`results/sectors.md`](results/sectors.md).

### Known limitation: the baseline is understated

The measurement was run from inside Iran, and 27% of the Tranco list was
unreachable from there. The failures are not random — 75 of the global top 200
did not respond, among them google, facebook, instagram, apple, microsoft and
baidu. Those are some of the best-configured sites on the web, so their absence
pushes the global figures **down**, and the real gap is wider than the table
above shows.

Reproducing the Tranco half from outside Iran would fix this. The code and the
Iranian dataset are here for anyone who wants to do that.

A second vantage-point effect showed up earlier in the work: the same 55
domains were 29/55 reachable on a home connection and 51/55 on a mobile
connection, from the same machine on the same day. Network path affects the
result, so every run reported here comes from one connection on one day.

## Running it

```
pip install requests
python build_iran_list.py --top 999999            # writes sites/iran.txt from Tranco
python collect.py sites/iran.txt --out results/iran.csv --legacy-tls --insecure-retry
python fetch_tranco.py --top 10000 --out sites/tranco.txt
python collect.py sites/tranco.txt --out results/tranco.csv --legacy-tls --insecure-retry
python analyze.py results/iran.csv results/tranco.csv --out results/summary.md
```

A run of 10k domains takes a few hours. Results are appended as they arrive, so
an interrupted run continues with `--resume`.

| File | Purpose |
|---|---|
| `collect.py` | Fetch headers over `requests` |
| `collect_browser.py` | Same columns, through Chrome (Playwright) for hosts that refuse plain clients |
| `analyze.py` | CSV to adoption table |
| `build_iran_list.py` | Build `sites/iran.txt` from the Tranco top-1M |
| `fetch_tranco.py` | Global baseline list |
| `prepare_release.py` | Sector aggregates, and the published CSV |

### Options that matter

- `--legacy-tls` accepts old TLS versions and weak ciphers. Without it, hosts
  that are merely out of date are recorded as unreachable.
- `--insecure-retry` retries once without certificate verification, purely to
  read the headers. The `tls_error` column marks those rows.
- `--resume` continues an interrupted run from the `.jsonl`.
- `--workers` defaults to 8. These are live sites; there is no reason to raise it.

## Dataset

`sites/iran.txt` is every `.ir` domain in the Tranco top-1M, in rank order —
3,154 of them — with per-sector splits in `sites/iran-{ac,sch,org,co}.txt`.
`sites/iran-manual.txt` holds Iranian services on non-`.ir` domains, which the
TLD filter misses; those are hand-picked.

Tranco under-represents government sites: only 24 `.gov.ir` domains appear in
the whole top-1M, so the public-sector slice is small.

**Per-domain records for `.gov.ir` hosts are not published.** That sector is
reported in aggregate in `results/sectors.md` and in the table above, and
`build_iran_list.py` reproduces the domain list from Tranco, so the figures can
be checked without publishing a host-by-host inventory of which government site
is missing which header. `prepare_release.py` performs that step and documents
it. Every other sector is in `results/iran.csv` row by row.

## What is measured

`Content-Security-Policy` (enforced and report-only, whether it sets
`frame-ancestors`, whether `script-src` allows `'unsafe-inline'`),
`X-Frame-Options`, `Strict-Transport-Security` with `max-age`,
`X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`,
`Cross-Origin-Opener-Policy`, `Secure` / `HttpOnly` / `SameSite` on cookies,
and whether `http://` redirects to `https://`.

## Scope

This repository measures publicly served response headers. It does not probe
for vulnerabilities and must not be extended to do so against hosts without
permission.

MIT licensed.
