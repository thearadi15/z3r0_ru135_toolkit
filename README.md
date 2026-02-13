# z3r0-toolkit

**Production-ready bug bounty automation toolkit** — from reconnaissance to validated findings.

---

## 🛠 Scripts

| # | Script | Description |
|---|--------|-------------|
| 1 | `01-recon.sh` | Subdomain enumeration, DNS resolution, live host detection, URL collection |
| 2 | `02-js-analysis.sh` | JS file scanning for API endpoints, secrets, tokens & sensitive params |
| 3 | `03-param-miner.sh` | Parameter extraction from URLs, JS & APIs with risk categorization |
| 4 | `04-api-enum.sh` | Versioned API discovery (v1–v5), auth detection, missing authz flagging |
| 5 | `05-rate-limit.sh` | Rate limit testing with header/UA/session rotation across concurrency levels |
| 6 | `06-secret-scanner.sh` | Secret leak detection with entropy filtering & false-positive removal |
| 7 | `07-nuclei-templates/` | Custom Nuclei templates for misconfigs, admin panels, CORS, IDOR |
| 8 | `08-pipeline.sh` | End-to-end pipeline orchestrating scripts 1–7 with final report |

---

## ⚡ Quick Start

```bash
# Full pipeline on a target
./08-pipeline.sh -d example.com

# Individual scripts
./01-recon.sh -d example.com
./02-js-analysis.sh -l js-urls.txt
./03-param-miner.sh -u urls.txt
./04-api-enum.sh -t https://example.com
./05-rate-limit.sh -u https://example.com/api/login -n 100
./06-secret-scanner.sh -d ./js-files/

# Nuclei templates
nuclei -l live-hosts.txt -t 07-nuclei-templates/
```

---

## 📦 Prerequisites

### Required
- `bash` 4.0+
- `curl`, `jq`

### Recommended (full functionality)
| Tool | Purpose | Install |
|------|---------|---------|
| [subfinder](https://github.com/projectdiscovery/subfinder) | Subdomain enumeration | `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| [amass](https://github.com/owasp-amass/amass) | Subdomain enumeration | `go install github.com/owasp-amass/amass/v4/...@master` |
| [assetfinder](https://github.com/tomnomnom/assetfinder) | Subdomain enumeration | `go install github.com/tomnomnom/assetfinder@latest` |
| [dnsx](https://github.com/projectdiscovery/dnsx) | DNS resolution | `go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest` |
| [httpx](https://github.com/projectdiscovery/httpx) | HTTP probing | `go install github.com/projectdiscovery/httpx/cmd/httpx@latest` |
| [waybackurls](https://github.com/tomnomnom/waybackurls) | URL collection | `go install github.com/tomnomnom/waybackurls@latest` |
| [gau](https://github.com/lc/gau) | URL collection | `go install github.com/lc/gau/v2/cmd/gau@latest` |
| [katana](https://github.com/projectdiscovery/katana) | Web crawling | `go install github.com/projectdiscovery/katana/cmd/katana@latest` |
| [nuclei](https://github.com/projectdiscovery/nuclei) | Vulnerability scanning | `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |
| [anew](https://github.com/tomnomnom/anew) | Deduplication | `go install github.com/tomnomnom/anew@latest` |

---

## 📂 Output Structure

Each script produces structured output in timestamped directories:

```
pipeline-output/example.com_20260212_034400/
├── stages/
│   ├── 1-recon/           # Subdomains, DNS, live hosts, URLs
│   ├── 2-js-analysis/     # JS endpoints, secrets, sensitive params
│   ├── 3-param-mining/    # Categorized params (critical/high/medium/low)
│   ├── 4-api-enum/        # API discovery, auth analysis
│   ├── 5-rate-limit/      # Rate limit test results
│   ├── 6-secrets/         # Verified secrets with confidence scores
│   └── 7-nuclei/          # Nuclei scan results
├── report/
│   └── final-report.md    # Comprehensive findings report
└── pipeline-status.txt    # Stage timing & status
```

---

## 🧬 Nuclei Templates

| Template | Severity | Detects |
|----------|----------|---------|
| `misconfig-headers.yaml` | Medium | Missing CSP, HSTS, X-Frame-Options, server info leak |
| `exposed-admin.yaml` | High | 35+ admin panel paths (WordPress, phpMyAdmin, Kibana, etc.) |
| `open-redirect.yaml` | Medium | Open redirects via 20+ params with bypass techniques |
| `cors-misconfig.yaml` | High | Reflected origin, wildcard, null origin, protocol downgrade |
| `logic-flaw-idor.yaml` | High | IDOR via sequential IDs, parameter tampering, mass assignment |

---

## ⚠️ Disclaimer

This toolkit is for **authorized security testing only**. Always:
- Obtain written permission before testing
- Respect scope boundaries
- Follow responsible disclosure

---

## 📝 License

MIT — Use responsibly.
