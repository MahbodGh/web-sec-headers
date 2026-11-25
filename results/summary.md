# Security-header adoption

| Dataset | Domains | Reachable | TLS errors |
|---|---:|---:|---:|
| iran | 3154 | 2800 | 75 |
| tranco | 10000 | 7277 | 151 |

Percentages below are of the **reachable** sites in each dataset.

| Mechanism | iran | tranco |
|---|---:|---:|
| HTTPS reachable | 86.8% | 84.6% |
| Upgrades HTTP to HTTPS | 86.8% | 84.6% |
| HSTS | 30.8% | 48.6% |
| HSTS max-age >= 1 year | 22.2% | 35.8% |
| CSP (enforced) | 21.9% | 33.0% |
| CSP report-only only | 0.9% | 1.6% |
| CSP has frame-ancestors | 11.4% | 18.7% |
| CSP allows 'unsafe-inline' | 8.0% | 11.1% |
| X-Frame-Options | 30.7% | 49.3% |
| Framing protected (XFO or CSP) | 33.1% | 54.9% |
| X-Content-Type-Options: nosniff | 28.8% | 44.4% |
| Referrer-Policy | 20.6% | 36.6% |
| Permissions-Policy | 9.5% | 17.3% |
| Sets at least one cookie | 28.4% | 30.3% |
| All cookies Secure | 13.7% | 13.4% |
| All cookies HttpOnly | 14.1% | 10.9% |
| All cookies SameSite | 12.5% | 11.5% |

## Largest gaps (iran vs tranco)

| Mechanism | iran | tranco | Difference |
|---|---:|---:|---:|
| Framing protected (XFO or CSP) | 33.1% | 54.9% | -21.7 pp |
| X-Frame-Options | 30.7% | 49.3% | -18.7 pp |
| HSTS | 30.8% | 48.6% | -17.8 pp |
| Referrer-Policy | 20.6% | 36.6% | -16.0 pp |
| X-Content-Type-Options: nosniff | 28.8% | 44.4% | -15.6 pp |
| HSTS max-age >= 1 year | 22.2% | 35.8% | -13.6 pp |
| CSP (enforced) | 21.9% | 33.0% | -11.1 pp |
| Permissions-Policy | 9.5% | 17.3% | -7.7 pp |
