#!/usr/bin/env bash
###############################################################################
# 01-recon.sh — Subdomain Enumeration, Live Host Detection & URL Collection
# Part of z3r0-toolkit
###############################################################################
set -euo pipefail

# ── Colors ──
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; MAGENTA='\033[0;35m'; BOLD='\033[1m'; NC='\033[0m'

# ── Banner ──
banner() {
    echo -e "${MAGENTA}${BOLD}"
    echo "╔══════════════════════════════════════════════════════════╗"
    echo "║           z3r0-toolkit • 01 RECON AUTOMATION            ║"
    echo "╚══════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# ── Logging ──
log_info()  { echo -e "${CYAN}[INFO]${NC}  $*"; }
log_ok()    { echo -e "${GREEN}[OK]${NC}    $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
log_err()   { echo -e "${RED}[ERR]${NC}   $*"; }
log_step()  { echo -e "\n${BOLD}${MAGENTA}━━━ $* ━━━${NC}\n"; }

# ── Safe line count (returns 0 for missing/empty files) ──
safe_count() { if [[ -f "$1" ]]; then wc -l < "$1"; else echo 0; fi; }

# ── Defaults ──
THREADS=50
RESOLVERS=""
OUTPUT_DIR="./recon-output"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# ── Usage ──
usage() {
    cat <<EOF
${BOLD}Usage:${NC} $0 -d <domain> [OPTIONS]

${BOLD}Required:${NC}
  -d, --domain <domain>       Target domain to enumerate

${BOLD}Options:${NC}
  -o, --output <dir>          Output directory (default: ./recon-output)
  -t, --threads <n>           Thread count (default: 50)
  -r, --resolvers <file>      Custom resolvers file for dnsx
  -w, --wordlist <file>       Custom subdomain wordlist
      --skip-urls             Skip URL collection phase
      --skip-screenshots      Skip screenshot capture
  -h, --help                  Show this help
EOF
    exit 0
}

# ── Dependency Check ──
check_deps() {
    local missing=()
    local deps=(subfinder amass assetfinder dnsx httpx waybackurls gau katana anew jq)
    for cmd in "${deps[@]}"; do
        if ! command -v "$cmd" &>/dev/null; then
            missing+=("$cmd")
        fi
    done
    if [[ ${#missing[@]} -gt 0 ]]; then
        log_warn "Missing tools: ${missing[*]}"
        log_warn "Install them to unlock full functionality."
        log_warn "Continuing with available tools..."
    fi
}

# ── Parse Args ──
DOMAIN=""
WORDLIST=""
SKIP_URLS=false
SKIP_SCREENSHOTS=false

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -d|--domain)      DOMAIN="$2"; shift 2;;
            -o|--output)      OUTPUT_DIR="$2"; shift 2;;
            -t|--threads)     THREADS="$2"; shift 2;;
            -r|--resolvers)   RESOLVERS="$2"; shift 2;;
            -w|--wordlist)    WORDLIST="$2"; shift 2;;
            --skip-urls)      SKIP_URLS=true; shift;;
            --skip-screenshots) SKIP_SCREENSHOTS=true; shift;;
            -h|--help)        usage;;
            *)                log_err "Unknown option: $1"; usage;;
        esac
    done
    if [[ -z "$DOMAIN" ]]; then
        log_err "Domain is required. Use -d <domain>"
        exit 1
    fi
}

# ── Setup Output ──
setup_output() {
    OUTPUT_DIR="${OUTPUT_DIR}/${DOMAIN}_${TIMESTAMP}"
    mkdir -p "$OUTPUT_DIR"/{subdomains,dns,live,urls,screenshots}
    log_info "Output directory: ${BOLD}$OUTPUT_DIR${NC}"
}

# ── Phase 1: Subdomain Enumeration ──
phase_subdomains() {
    log_step "PHASE 1 — Subdomain Enumeration"
    local all_subs="$OUTPUT_DIR/subdomains/all-subdomains.txt"
    touch "$all_subs"

    # subfinder
    if command -v subfinder &>/dev/null; then
        log_info "Running subfinder..."
        subfinder -d "$DOMAIN" -silent -all -t "$THREADS" \
            -o "$OUTPUT_DIR/subdomains/subfinder.txt" 2>/dev/null || true
        if [[ -f "$OUTPUT_DIR/subdomains/subfinder.txt" ]]; then
            cat "$OUTPUT_DIR/subdomains/subfinder.txt" >> "$all_subs"
            log_ok "subfinder: $(wc -l < "$OUTPUT_DIR/subdomains/subfinder.txt") subdomains"
        fi
    fi

    # amass (passive)
    if command -v amass &>/dev/null; then
        log_info "Running amass (passive)..."
        timeout 300 amass enum -passive -d "$DOMAIN" \
            -o "$OUTPUT_DIR/subdomains/amass.txt" 2>/dev/null || true
        if [[ -f "$OUTPUT_DIR/subdomains/amass.txt" ]]; then
            cat "$OUTPUT_DIR/subdomains/amass.txt" >> "$all_subs"
            log_ok "amass: $(wc -l < "$OUTPUT_DIR/subdomains/amass.txt") subdomains"
        fi
    fi

    # assetfinder
    if command -v assetfinder &>/dev/null; then
        log_info "Running assetfinder..."
        assetfinder --subs-only "$DOMAIN" 2>/dev/null \
            > "$OUTPUT_DIR/subdomains/assetfinder.txt" || true
        if [[ -s "$OUTPUT_DIR/subdomains/assetfinder.txt" ]]; then
            cat "$OUTPUT_DIR/subdomains/assetfinder.txt" >> "$all_subs"
            log_ok "assetfinder: $(wc -l < "$OUTPUT_DIR/subdomains/assetfinder.txt") subdomains"
        fi
    fi

    # crt.sh
    log_info "Querying crt.sh..."
    curl -s "https://crt.sh/?q=%25.$DOMAIN&output=json" 2>/dev/null \
        | jq -r '.[].name_value' 2>/dev/null \
        | sed 's/\*\.//g' \
        | sort -u \
        > "$OUTPUT_DIR/subdomains/crtsh.txt" || true
    if [[ -s "$OUTPUT_DIR/subdomains/crtsh.txt" ]]; then
        cat "$OUTPUT_DIR/subdomains/crtsh.txt" >> "$all_subs"
        log_ok "crt.sh: $(wc -l < "$OUTPUT_DIR/subdomains/crtsh.txt") subdomains"
    fi

    # Deduplicate
    sort -u "$all_subs" -o "$all_subs"
    log_ok "Total unique subdomains: ${BOLD}$(wc -l < "$all_subs")${NC}"
}

# ── Phase 2: DNS Resolution ──
phase_dns() {
    log_step "PHASE 2 — DNS Resolution"
    local all_subs="$OUTPUT_DIR/subdomains/all-subdomains.txt"
    local resolved="$OUTPUT_DIR/dns/resolved.txt"

    if [[ ! -s "$all_subs" ]]; then
        log_warn "No subdomains found, skipping DNS resolution"
        return
    fi

    if command -v dnsx &>/dev/null; then
        local resolver_flag=""
        [[ -n "$RESOLVERS" ]] && resolver_flag="-r $RESOLVERS"
        log_info "Resolving with dnsx..."
        # shellcheck disable=SC2086
        dnsx -l "$all_subs" -t "$THREADS" $resolver_flag -silent \
            -a -aaaa -cname -resp \
            -o "$OUTPUT_DIR/dns/dnsx-full.txt" 2>/dev/null || true

        dnsx -l "$all_subs" -t "$THREADS" $resolver_flag -silent \
            -o "$resolved" 2>/dev/null || true
        log_ok "Resolved: ${BOLD}$(wc -l < "$resolved")${NC} subdomains"
    else
        log_warn "dnsx not found, using host fallback..."
        while IFS= read -r sub; do
            if host "$sub" &>/dev/null; then
                echo "$sub" >> "$resolved"
            fi
        done < "$all_subs"
        log_ok "Resolved: ${BOLD}$(wc -l < "$resolved")${NC} subdomains"
    fi
}

# ── Phase 3: Live Host Detection ──
phase_live_hosts() {
    log_step "PHASE 3 — Live Host Detection"
    local resolved="$OUTPUT_DIR/dns/resolved.txt"
    local input_file="$resolved"

    # Fallback to all subdomains if resolution was skipped
    if [[ ! -s "$resolved" ]]; then
        input_file="$OUTPUT_DIR/subdomains/all-subdomains.txt"
    fi

    if [[ ! -s "$input_file" ]]; then
        log_warn "No hosts to probe"
        return
    fi

    if command -v httpx &>/dev/null; then
        log_info "Probing with httpx..."
        httpx -l "$input_file" -silent \
            -t "$THREADS" \
            -status-code -title -tech-detect -content-length \
            -follow-redirects \
            -o "$OUTPUT_DIR/live/httpx-full.txt" 2>/dev/null || true

        # Extract just URLs
        httpx -l "$input_file" -silent \
            -t "$THREADS" \
            -follow-redirects \
            -o "$OUTPUT_DIR/live/live-hosts.txt" 2>/dev/null || true

        if [[ -s "$OUTPUT_DIR/live/live-hosts.txt" ]]; then
            log_ok "Live hosts: ${BOLD}$(wc -l < "$OUTPUT_DIR/live/live-hosts.txt")${NC}"
        fi

        # Split by status code
        if [[ -s "$OUTPUT_DIR/live/httpx-full.txt" ]]; then
            grep -E '\[200\]' "$OUTPUT_DIR/live/httpx-full.txt" \
                > "$OUTPUT_DIR/live/200-ok.txt" 2>/dev/null || true
            grep -E '\[30[0-9]\]' "$OUTPUT_DIR/live/httpx-full.txt" \
                > "$OUTPUT_DIR/live/3xx-redirect.txt" 2>/dev/null || true
            grep -E '\[40[0-9]\]' "$OUTPUT_DIR/live/httpx-full.txt" \
                > "$OUTPUT_DIR/live/4xx-errors.txt" 2>/dev/null || true
            grep -E '\[50[0-9]\]' "$OUTPUT_DIR/live/httpx-full.txt" \
                > "$OUTPUT_DIR/live/5xx-errors.txt" 2>/dev/null || true
        fi
    else
        log_warn "httpx not found, using curl fallback..."
        while IFS= read -r sub; do
            for scheme in "https" "http"; do
                code=$(curl -s -o /dev/null -w '%{http_code}' \
                    --connect-timeout 5 --max-time 10 \
                    "${scheme}://${sub}" 2>/dev/null) || true
                if [[ "$code" != "000" ]]; then
                    echo "${scheme}://${sub} [$code]" >> "$OUTPUT_DIR/live/live-hosts.txt"
                    break
                fi
            done
        done < "$input_file"
        log_ok "Live hosts: ${BOLD}$(wc -l < "$OUTPUT_DIR/live/live-hosts.txt" 2>/dev/null || echo 0)${NC}"
    fi
}

# ── Phase 4: URL Collection ──
phase_urls() {
    log_step "PHASE 4 — URL Collection"

    if [[ "$SKIP_URLS" == true ]]; then
        log_warn "URL collection skipped (--skip-urls)"
        return
    fi

    local live_hosts="$OUTPUT_DIR/live/live-hosts.txt"
    local all_urls="$OUTPUT_DIR/urls/all-urls.txt"
    touch "$all_urls"

    if [[ ! -s "$live_hosts" ]]; then
        log_warn "No live hosts, running URL collection against domain directly"
        echo "https://$DOMAIN" > "$live_hosts"
    fi

    # waybackurls
    if command -v waybackurls &>/dev/null; then
        log_info "Running waybackurls..."
        cat "$live_hosts" | waybackurls 2>/dev/null \
            > "$OUTPUT_DIR/urls/waybackurls.txt" || true
        if [[ -s "$OUTPUT_DIR/urls/waybackurls.txt" ]]; then
            cat "$OUTPUT_DIR/urls/waybackurls.txt" >> "$all_urls"
            log_ok "waybackurls: $(wc -l < "$OUTPUT_DIR/urls/waybackurls.txt") URLs"
        fi
    fi

    # gau
    if command -v gau &>/dev/null; then
        log_info "Running gau..."
        echo "$DOMAIN" | gau --threads "$THREADS" 2>/dev/null \
            > "$OUTPUT_DIR/urls/gau.txt" || true
        if [[ -s "$OUTPUT_DIR/urls/gau.txt" ]]; then
            cat "$OUTPUT_DIR/urls/gau.txt" >> "$all_urls"
            log_ok "gau: $(wc -l < "$OUTPUT_DIR/urls/gau.txt") URLs"
        fi
    fi

    # katana
    if command -v katana &>/dev/null; then
        log_info "Running katana (crawling)..."
        katana -list "$live_hosts" -silent \
            -d 3 -jc -ct "$THREADS" \
            -o "$OUTPUT_DIR/urls/katana.txt" 2>/dev/null || true
        if [[ -s "$OUTPUT_DIR/urls/katana.txt" ]]; then
            cat "$OUTPUT_DIR/urls/katana.txt" >> "$all_urls"
            log_ok "katana: $(wc -l < "$OUTPUT_DIR/urls/katana.txt") URLs"
        fi
    fi

    # Deduplicate & categorize
    sort -u "$all_urls" -o "$all_urls"
    log_ok "Total unique URLs: ${BOLD}$(wc -l < "$all_urls")${NC}"

    # Categorize URLs
    grep -iE '\.js(\?|$)' "$all_urls" > "$OUTPUT_DIR/urls/js-files.txt" 2>/dev/null || true
    grep -iE '\.(php|asp|aspx|jsp|cgi)(\?|$)' "$all_urls" > "$OUTPUT_DIR/urls/dynamic-pages.txt" 2>/dev/null || true
    grep -iE '\?(.*=)' "$all_urls" > "$OUTPUT_DIR/urls/parameterized.txt" 2>/dev/null || true
    grep -iE '/api/' "$all_urls" > "$OUTPUT_DIR/urls/api-urls.txt" 2>/dev/null || true

    log_info "JS files:          $(wc -l < "$OUTPUT_DIR/urls/js-files.txt" 2>/dev/null || echo 0)"
    log_info "Dynamic pages:     $(wc -l < "$OUTPUT_DIR/urls/dynamic-pages.txt" 2>/dev/null || echo 0)"
    log_info "Parameterized:     $(wc -l < "$OUTPUT_DIR/urls/parameterized.txt" 2>/dev/null || echo 0)"
    log_info "API URLs:          $(wc -l < "$OUTPUT_DIR/urls/api-urls.txt" 2>/dev/null || echo 0)"
}

# ── Summary Report ──
generate_report() {
    log_step "GENERATING REPORT"
    local report="$OUTPUT_DIR/recon-summary.md"

    cat > "$report" <<-REPORT
# Recon Summary — $DOMAIN
**Date:** $(date '+%Y-%m-%d %H:%M:%S %Z')
**Toolkit:** z3r0-toolkit v1.0

---

## Subdomain Enumeration
| Source       | Count |
|-------------|-------|
| subfinder   | $(safe_count "$OUTPUT_DIR/subdomains/subfinder.txt") |
| amass       | $(safe_count "$OUTPUT_DIR/subdomains/amass.txt") |
| assetfinder | $(safe_count "$OUTPUT_DIR/subdomains/assetfinder.txt") |
| crt.sh      | $(safe_count "$OUTPUT_DIR/subdomains/crtsh.txt") |
| **Total Unique** | **$(safe_count "$OUTPUT_DIR/subdomains/all-subdomains.txt")** |

## DNS Resolution
- Resolved hosts: $(safe_count "$OUTPUT_DIR/dns/resolved.txt")

## Live Hosts
- Total live: $(safe_count "$OUTPUT_DIR/live/live-hosts.txt")
- 200 OK: $(safe_count "$OUTPUT_DIR/live/200-ok.txt")
- 3xx Redirects: $(safe_count "$OUTPUT_DIR/live/3xx-redirect.txt")
- 4xx Errors: $(safe_count "$OUTPUT_DIR/live/4xx-errors.txt")
- 5xx Errors: $(safe_count "$OUTPUT_DIR/live/5xx-errors.txt")

## URL Collection
- Total unique URLs: $(safe_count "$OUTPUT_DIR/urls/all-urls.txt")
- JS files: $(safe_count "$OUTPUT_DIR/urls/js-files.txt")
- Dynamic pages: $(safe_count "$OUTPUT_DIR/urls/dynamic-pages.txt")
- Parameterized URLs: $(safe_count "$OUTPUT_DIR/urls/parameterized.txt")
- API URLs: $(safe_count "$OUTPUT_DIR/urls/api-urls.txt")

---

## Output Directory Structure
\`\`\`
$(find "$OUTPUT_DIR" -type f | sed "s|$OUTPUT_DIR/||" | sort)
\`\`\`
REPORT

    log_ok "Report saved: ${BOLD}$report${NC}"
}

# ── Main ──
main() {
    banner
    parse_args "$@"
    check_deps
    setup_output

    local start_time=$SECONDS
    phase_subdomains
    phase_dns
    phase_live_hosts
    phase_urls
    generate_report

    local elapsed=$(( SECONDS - start_time ))
    echo ""
    log_ok "Recon completed in ${BOLD}${elapsed}s${NC}"
    log_ok "Results: ${BOLD}$OUTPUT_DIR${NC}"
}

main "$@"
