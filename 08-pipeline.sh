#!/usr/bin/env bash
# Copyright (c) 2026 z3r0_ru135
###############################################################################
# 08-pipeline.sh — Full Bug Bounty Automation Pipeline
# End-to-end orchestration from recon to validation with report-ready output
# Part of z3r0-toolkit
###############################################################################
set -euo pipefail

# ── Colors ──
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; MAGENTA='\033[0;35m'; BOLD='\033[1m'; NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── Banner ──
banner() {
    echo -e "${MAGENTA}${BOLD}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║                                                            ║"
    echo "║     ███████╗██████╗ ██████╗  ██████╗                       ║"
    echo "║     ╚══███╔╝╚════██╗██╔══██╗██╔═████╗                     ║"
    echo "║       ███╔╝  █████╔╝██████╔╝██║██╔██║                     ║"
    echo "║      ███╔╝   ╚═══██╗██╔══██╗████╔╝██║                     ║"
    echo "║     ███████╗██████╔╝██║  ██║╚██████╔╝                     ║"
    echo "║     ╚══════╝╚═════╝ ╚═╝  ╚═╝ ╚═════╝  TOOLKIT            ║"
    echo "║                                                            ║"
    echo "║     Full Automation Pipeline — Recon to Report             ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# ── Logging ──
log_info()  { echo -e "${CYAN}[INFO]${NC}  $*"; }
log_ok()    { echo -e "${GREEN}[OK]${NC}    $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
log_err()   { echo -e "${RED}[ERR]${NC}   $*"; }
log_step()  { echo -e "\n${BOLD}${MAGENTA}═══════════════════════════════════════════════${NC}"; echo -e "${BOLD}${MAGENTA}  STAGE: $* ${NC}"; echo -e "${BOLD}${MAGENTA}═══════════════════════════════════════════════${NC}\n"; }

# ── Defaults ──
THREADS=30
OUTPUT_DIR="./pipeline-output"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# ── Pipeline Stages ──
SKIP_RECON=false
SKIP_JS=false
SKIP_PARAMS=false
SKIP_API=false
SKIP_RATELIMIT=false
SKIP_SECRETS=false
SKIP_NUCLEI=false
RATE_LIMIT_URL=""

# ── Usage ──
usage() {
    cat <<EOF
${BOLD}Usage:${NC} $0 -d <domain> [OPTIONS]

${BOLD}Required:${NC}
  -d, --domain <domain>       Target domain

${BOLD}Options:${NC}
  -o, --output <dir>          Output directory (default: ./pipeline-output)
  -t, --threads <n>           Thread count (default: 30)
  --rate-limit-url <url>      Specific URL for rate limit testing
  --skip-recon                Skip recon stage
  --skip-js                   Skip JS analysis stage
  --skip-params               Skip parameter mining stage
  --skip-api                  Skip API enumeration stage
  --skip-ratelimit            Skip rate limit testing stage
  --skip-secrets              Skip secret scanning stage
  --skip-nuclei               Skip Nuclei scanning stage
  -h, --help                  Show this help

${BOLD}Examples:${NC}
  $0 -d example.com
  $0 -d example.com --skip-ratelimit --threads 50
  $0 -d example.com --rate-limit-url https://example.com/api/login
EOF
    exit 0
}

# ── Parse Args ──
DOMAIN=""

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -d|--domain)        DOMAIN="$2"; shift 2;;
            -o|--output)        OUTPUT_DIR="$2"; shift 2;;
            -t|--threads)       THREADS="$2"; shift 2;;
            --rate-limit-url)   RATE_LIMIT_URL="$2"; shift 2;;
            --skip-recon)       SKIP_RECON=true; shift;;
            --skip-js)          SKIP_JS=true; shift;;
            --skip-params)      SKIP_PARAMS=true; shift;;
            --skip-api)         SKIP_API=true; shift;;
            --skip-ratelimit)   SKIP_RATELIMIT=true; shift;;
            --skip-secrets)     SKIP_SECRETS=true; shift;;
            --skip-nuclei)      SKIP_NUCLEI=true; shift;;
            -h|--help)          usage;;
            *)                  log_err "Unknown option: $1"; usage;;
        esac
    done

    if [[ -z "$DOMAIN" ]]; then
        log_err "Domain is required. Use -d <domain>"
        exit 1
    fi
}

# ── Setup ──
setup_pipeline() {
    OUTPUT_DIR="${OUTPUT_DIR}/${DOMAIN}_${TIMESTAMP}"
    mkdir -p "$OUTPUT_DIR"/{stages,report}
    log_info "Pipeline output: ${BOLD}$OUTPUT_DIR${NC}"
    log_info "Target domain:   ${BOLD}$DOMAIN${NC}"
    log_info "Threads:         ${BOLD}$THREADS${NC}"
    log_info "Timestamp:       ${BOLD}$TIMESTAMP${NC}"
    echo ""

    # Pipeline status file
    echo "pipeline_start=$(date -Iseconds)" > "$OUTPUT_DIR/pipeline-status.txt"
    echo "domain=$DOMAIN" >> "$OUTPUT_DIR/pipeline-status.txt"
}

# ── Run Stage with Error Handling ──
run_stage() {
    local stage_name="$1"
    local stage_num="$2"
    shift 2
    local script="$1"
    shift

    local stage_dir="$OUTPUT_DIR/stages/${stage_num}-${stage_name}"
    local stage_log="$OUTPUT_DIR/stages/${stage_num}-${stage_name}.log"

    log_step "[$stage_num/7] $stage_name"

    local start_time=$SECONDS
    echo "stage_${stage_num}_start=$(date -Iseconds)" >> "$OUTPUT_DIR/pipeline-status.txt"

    if bash "$SCRIPT_DIR/$script" "$@" -o "$stage_dir" 2>&1 | tee "$stage_log"; then
        local elapsed=$(( SECONDS - start_time ))
        echo "stage_${stage_num}_status=SUCCESS" >> "$OUTPUT_DIR/pipeline-status.txt"
        echo "stage_${stage_num}_duration=${elapsed}s" >> "$OUTPUT_DIR/pipeline-status.txt"
        log_ok "Stage $stage_num completed in ${elapsed}s"
        return 0
    else
        local elapsed=$(( SECONDS - start_time ))
        echo "stage_${stage_num}_status=FAILED" >> "$OUTPUT_DIR/pipeline-status.txt"
        echo "stage_${stage_num}_duration=${elapsed}s" >> "$OUTPUT_DIR/pipeline-status.txt"
        log_err "Stage $stage_num failed (see $stage_log)"
        return 1
    fi
}

# ── Stage 1: Recon ──
stage_recon() {
    if [[ "$SKIP_RECON" == true ]]; then
        log_warn "Skipping recon stage"
        return 0
    fi
    run_stage "recon" "1" "01-recon.sh" -d "$DOMAIN" -t "$THREADS"
}

# ── Stage 2: JS Analysis ──
stage_js_analysis() {
    if [[ "$SKIP_JS" == true ]]; then
        log_warn "Skipping JS analysis stage"
        return 0
    fi

    local recon_dir
    recon_dir=$(find "$OUTPUT_DIR/stages/1-recon" -maxdepth 2 -name "js-files.txt" -type f 2>/dev/null | head -1 | xargs dirname 2>/dev/null) || true

    if [[ -n "$recon_dir" ]]; then
        run_stage "js-analysis" "2" "02-js-analysis.sh" --from-recon "$(dirname "$recon_dir")" -t "$THREADS"
    else
        log_warn "No JS files from recon, running with domain URL"
        local js_url="https://$DOMAIN"
        echo "$js_url" > "$OUTPUT_DIR/stages/temp-js-urls.txt"
        run_stage "js-analysis" "2" "02-js-analysis.sh" -l "$OUTPUT_DIR/stages/temp-js-urls.txt" -t "$THREADS"
    fi
}

# ── Stage 3: Parameter Mining ──
stage_param_mining() {
    if [[ "$SKIP_PARAMS" == true ]]; then
        log_warn "Skipping parameter mining stage"
        return 0
    fi

    local recon_dir
    recon_dir=$(find "$OUTPUT_DIR/stages/1-recon" -maxdepth 3 -name "parameterized.txt" -type f 2>/dev/null | head -1 | xargs dirname 2>/dev/null) || true

    local js_dir
    js_dir=$(find "$OUTPUT_DIR/stages/2-js-analysis" -maxdepth 3 -name "downloaded" -type d 2>/dev/null | head -1) || true

    local args=()
    [[ -n "$recon_dir" ]] && args+=(--from-recon "$(dirname "$recon_dir")")
    [[ -n "$js_dir" ]] && args+=(-j "$js_dir")

    if [[ ${#args[@]} -gt 0 ]]; then
        run_stage "param-mining" "3" "03-param-miner.sh" "${args[@]}"
    else
        log_warn "No input data available for parameter mining"
    fi
}

# ── Stage 4: API Enumeration ──
stage_api_enum() {
    if [[ "$SKIP_API" == true ]]; then
        log_warn "Skipping API enumeration stage"
        return 0
    fi

    local live_hosts
    live_hosts=$(find "$OUTPUT_DIR/stages/1-recon" -maxdepth 3 -name "live-hosts.txt" -type f 2>/dev/null | head -1) || true

    if [[ -n "$live_hosts" && -s "$live_hosts" ]]; then
        run_stage "api-enum" "4" "04-api-enum.sh" -l "$live_hosts" -c "$THREADS" --methods
    else
        run_stage "api-enum" "4" "04-api-enum.sh" -t "https://$DOMAIN" -c "$THREADS" --methods
    fi
}

# ── Stage 5: Rate Limit Testing ──
stage_rate_limit() {
    if [[ "$SKIP_RATELIMIT" == true ]]; then
        log_warn "Skipping rate limit testing stage"
        return 0
    fi

    local target_url="$RATE_LIMIT_URL"

    # Auto-discover login endpoint
    if [[ -z "$target_url" ]]; then
        local api_results
        api_results=$(find "$OUTPUT_DIR/stages/4-api-enum" -maxdepth 3 -name "accessible-200.txt" -type f 2>/dev/null | head -1) || true

        if [[ -n "$api_results" && -s "$api_results" ]]; then
            target_url=$(grep -iE '(login|auth|signin|register|token)' "$api_results" 2>/dev/null | head -1) || true
        fi
    fi

    if [[ -z "$target_url" ]]; then
        target_url="https://$DOMAIN"
    fi

    run_stage "rate-limit" "5" "05-rate-limit.sh" -u "$target_url" -n 30 --concurrency 1,5,10,25
}

# ── Stage 6: Secret Scanning ──
stage_secrets() {
    if [[ "$SKIP_SECRETS" == true ]]; then
        log_warn "Skipping secret scanning stage"
        return 0
    fi

    local recon_dir
    recon_dir=$(find "$OUTPUT_DIR/stages/1-recon" -maxdepth 1 -type d 2>/dev/null | tail -1) || true

    local js_dir
    js_dir=$(find "$OUTPUT_DIR/stages/2-js-analysis" -maxdepth 3 -name "downloaded" -type d 2>/dev/null | head -1) || true

    local args=()
    [[ -n "$recon_dir" ]] && args+=(--from-recon "$recon_dir")
    [[ -n "$js_dir" ]] && args+=(-d "$js_dir")

    if [[ ${#args[@]} -gt 0 ]]; then
        run_stage "secrets" "6" "06-secret-scanner.sh" "${args[@]}" -t "$THREADS"
    else
        log_warn "No input data for secret scanning"
    fi
}

# ── Stage 7: Nuclei Scanning ──
stage_nuclei() {
    if [[ "$SKIP_NUCLEI" == true ]]; then
        log_warn "Skipping Nuclei scanning stage"
        return 0
    fi

    if ! command -v nuclei &>/dev/null; then
        log_warn "Nuclei not installed, skipping"
        return 0
    fi

    log_step "[7/7] NUCLEI SCANNING"

    local nuclei_dir="$OUTPUT_DIR/stages/7-nuclei"
    mkdir -p "$nuclei_dir"

    local live_hosts
    live_hosts=$(find "$OUTPUT_DIR/stages/1-recon" -maxdepth 3 -name "live-hosts.txt" -type f 2>/dev/null | head -1) || true
    local input_file="$nuclei_dir/targets.txt"

    if [[ -n "$live_hosts" && -s "$live_hosts" ]]; then
        cp "$live_hosts" "$input_file"
    else
        echo "https://$DOMAIN" > "$input_file"
    fi

    local start_time=$SECONDS

    # Run custom templates
    nuclei -l "$input_file" \
        -t "$SCRIPT_DIR/07-nuclei-templates/" \
        -c "$THREADS" \
        -o "$nuclei_dir/nuclei-results.txt" \
        -jsonl \
        -silent 2>/dev/null || true

    local elapsed=$(( SECONDS - start_time ))
    echo "stage_7_status=SUCCESS" >> "$OUTPUT_DIR/pipeline-status.txt"
    echo "stage_7_duration=${elapsed}s" >> "$OUTPUT_DIR/pipeline-status.txt"

    if [[ -s "$nuclei_dir/nuclei-results.txt" ]]; then
        log_ok "Nuclei findings: $(wc -l < "$nuclei_dir/nuclei-results.txt")"
    else
        log_info "No Nuclei findings"
    fi
}

# ── Generate Final Report ──
generate_final_report() {
    log_step "GENERATING FINAL REPORT"

    local report="$OUTPUT_DIR/report/final-report.md"

    # Gather stats
    local total_subs live_hosts total_urls js_secrets
    local critical_params unauth_apis nuclei_findings total_secrets

    total_subs=$(find "$OUTPUT_DIR/stages/1-recon" -name "all-subdomains.txt" -exec wc -l {} \; 2>/dev/null | awk '{print $1}' | head -1) || total_subs=0
    live_hosts=$(find "$OUTPUT_DIR/stages/1-recon" -name "live-hosts.txt" -exec wc -l {} \; 2>/dev/null | awk '{print $1}' | head -1) || live_hosts=0
    total_urls=$(find "$OUTPUT_DIR/stages/1-recon" -name "all-urls.txt" -exec wc -l {} \; 2>/dev/null | awk '{print $1}' | head -1) || total_urls=0
    js_secrets=$(find "$OUTPUT_DIR/stages/2-js-analysis" -name "js-secrets.json" -exec sh -c 'jq length "{}" 2>/dev/null' \; 2>/dev/null | head -1) || js_secrets=0
    critical_params=$(find "$OUTPUT_DIR/stages/3-param-mining" -name "params-critical.txt" -exec wc -l {} \; 2>/dev/null | awk '{print $1}' | head -1) || critical_params=0
    unauth_apis=$(find "$OUTPUT_DIR/stages/4-api-enum" -name "unauth-endpoints.txt" -exec wc -l {} \; 2>/dev/null | awk '{print $1}' | head -1) || unauth_apis=0
    total_secrets=$(find "$OUTPUT_DIR/stages/6-secrets" -name "secrets-verified.json" -exec sh -c 'jq length "{}" 2>/dev/null' \; 2>/dev/null | head -1) || total_secrets=0
    nuclei_findings=$(find "$OUTPUT_DIR/stages/7-nuclei" -name "nuclei-results.txt" -exec wc -l {} \; 2>/dev/null | awk '{print $1}' | head -1) || nuclei_findings=0

    cat > "$report" <<-REPORT
# 🔍 Bug Bounty Report — $DOMAIN
**Generated:** $(date '+%Y-%m-%d %H:%M:%S %Z')
**Toolkit:** z3r0-toolkit v1.0
**Pipeline Run:** $TIMESTAMP

---

## 📊 Executive Summary

| Metric | Count |
|--------|-------|
| Subdomains discovered | $total_subs |
| Live hosts | $live_hosts |
| URLs collected | $total_urls |
| JS secrets found | $js_secrets |
| Critical parameters | $critical_params |
| Unprotected APIs | $unauth_apis |
| Secret leaks | $total_secrets |
| Nuclei findings | $nuclei_findings |

---

## 🔴 Critical Findings

### Unprotected API Endpoints
$(if [[ -f "$OUTPUT_DIR/stages/4-api-enum" ]]; then
    find "$OUTPUT_DIR/stages/4-api-enum" -name "unauth-endpoints.txt" -exec cat {} \; 2>/dev/null | head -20 || echo "None"
else
    echo "Not scanned or no findings"
fi)

### Secret Leaks
$(find "$OUTPUT_DIR/stages/6-secrets" -name "secrets-verified.json" \
    -exec jq -r '.[:10] | .[] | "- [\(.severity)] \(.type) in \(.source):\(.line) (confidence: \(.confidence)%)"' {} \; 2>/dev/null \
    || echo "None detected")

### Critical Parameters
$(find "$OUTPUT_DIR/stages/3-param-mining" -name "params-critical.txt" -exec cat {} \; 2>/dev/null | head -20 || echo "None")

---

## 📋 Stage Results

### Stage 1 — Reconnaissance
$(find "$OUTPUT_DIR/stages/1-recon" -name "recon-summary.md" -exec cat {} \; 2>/dev/null || echo "See stages/1-recon/")

### Stage 2 — JavaScript Analysis
$(find "$OUTPUT_DIR/stages/2-js-analysis" -name "js-analysis-summary.md" -exec cat {} \; 2>/dev/null || echo "See stages/2-js-analysis/")

### Stage 3 — Parameter Mining
$(find "$OUTPUT_DIR/stages/3-param-mining" -name "param-miner-report.md" -exec cat {} \; 2>/dev/null || echo "See stages/3-param-mining/")

### Stage 4 — API Enumeration
$(find "$OUTPUT_DIR/stages/4-api-enum" -name "api-enum-report.md" -exec cat {} \; 2>/dev/null || echo "See stages/4-api-enum/")

### Stage 5 — Rate Limit Testing
$(find "$OUTPUT_DIR/stages/5-rate-limit" -name "rate-limit-report.md" -exec cat {} \; 2>/dev/null || echo "See stages/5-rate-limit/")

### Stage 6 — Secret Scanning
$(find "$OUTPUT_DIR/stages/6-secrets" -name "secret-scanner-report.md" -exec cat {} \; 2>/dev/null || echo "See stages/6-secrets/")

### Stage 7 — Nuclei Scanning
\`\`\`
$(find "$OUTPUT_DIR/stages/7-nuclei" -name "nuclei-results.txt" -exec cat {} \; 2>/dev/null || echo "No results")
\`\`\`

---

## 🕐 Pipeline Timing

\`\`\`
$(cat "$OUTPUT_DIR/pipeline-status.txt" 2>/dev/null || echo "No timing data")
\`\`\`

---

## 📁 Output Structure

\`\`\`
$(find "$OUTPUT_DIR" -maxdepth 3 -type d | sed "s|$OUTPUT_DIR/||" | sort)
\`\`\`

---

*Report generated by z3r0-toolkit. Use responsibly and only on authorized targets.*
REPORT

    log_ok "Final report: ${BOLD}$report${NC}"
}

# ── Main Pipeline ──
main() {
    banner
    parse_args "$@"
    setup_pipeline

    local pipeline_start=$SECONDS

    # Execute pipeline stages
    stage_recon         || log_warn "Recon stage had errors, continuing..."
    stage_js_analysis   || log_warn "JS analysis stage had errors, continuing..."
    stage_param_mining  || log_warn "Param mining stage had errors, continuing..."
    stage_api_enum      || log_warn "API enum stage had errors, continuing..."
    stage_rate_limit    || log_warn "Rate limit stage had errors, continuing..."
    stage_secrets       || log_warn "Secret scanning stage had errors, continuing..."
    stage_nuclei        || log_warn "Nuclei stage had errors, continuing..."

    generate_final_report

    local total_elapsed=$(( SECONDS - pipeline_start ))
    echo "pipeline_end=$(date -Iseconds)" >> "$OUTPUT_DIR/pipeline-status.txt"
    echo "pipeline_duration=${total_elapsed}s" >> "$OUTPUT_DIR/pipeline-status.txt"

    echo ""
    echo -e "${GREEN}${BOLD}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}${BOLD}║             PIPELINE COMPLETE                            ║${NC}"
    echo -e "${GREEN}${BOLD}╚══════════════════════════════════════════════════════════╝${NC}"
    echo ""
    log_ok "Total time: ${BOLD}${total_elapsed}s${NC}"
    log_ok "Results:    ${BOLD}$OUTPUT_DIR${NC}"
    log_ok "Report:     ${BOLD}$OUTPUT_DIR/report/final-report.md${NC}"
}

main "$@"
