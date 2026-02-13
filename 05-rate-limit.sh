#!/usr/bin/env bash
###############################################################################
# 05-rate-limit.sh — Rate Limit Testing
# Tests rate limiting by rotating headers, sessions, tokens & concurrency
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
    echo "║           z3r0-toolkit • 05 RATE LIMIT TESTER           ║"
    echo "╚══════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# ── Logging ──
log_info()  { echo -e "${CYAN}[INFO]${NC}  $*"; }
log_ok()    { echo -e "${GREEN}[OK]${NC}    $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
log_err()   { echo -e "${RED}[ERR]${NC}   $*"; }
log_step()  { echo -e "\n${BOLD}${MAGENTA}━━━ $* ━━━${NC}\n"; }

# ── Defaults ──
REQUESTS=50
DELAY=0
OUTPUT_DIR="./rate-limit-output"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
METHOD="GET"
BODY=""
CONTENT_TYPE=""
CUSTOM_HEADERS=()
CONCURRENCY_LEVELS=(1 5 10 25 50)

# ── User-Agent Pool ──
USER_AGENTS=(
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15"
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0"
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/120.0.0.0"
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1"
    "Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.144 Mobile Safari/537.36"
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
    "curl/8.4.0"
)

# ── Usage ──
usage() {
    cat <<EOF
${BOLD}Usage:${NC} $0 -u <url> [OPTIONS]

${BOLD}Required:${NC}
  -u, --url <url>             Target endpoint URL

${BOLD}Options:${NC}
  -n, --requests <n>          Number of requests per test (default: 50)
  -m, --method <method>       HTTP method (default: GET)
  -b, --body <data>           Request body (for POST/PUT)
  -H, --header <header>       Custom header (repeatable)
  --content-type <type>       Content-Type header
  --delay <ms>                Delay between requests in ms (default: 0)
  --concurrency <levels>      Comma-separated concurrency levels (default: 1,5,10,25,50)
  -o, --output <dir>          Output directory (default: ./rate-limit-output)
  -h, --help                  Show this help

${BOLD}Examples:${NC}
  $0 -u https://api.example.com/login -m POST -b '{"user":"test","pass":"test"}'
  $0 -u https://example.com/api/data -n 100 --concurrency 1,10,50
EOF
    exit 0
}

# ── Parse Args ──
TARGET_URL=""

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -u|--url)         TARGET_URL="$2"; shift 2;;
            -n|--requests)    REQUESTS="$2"; shift 2;;
            -m|--method)      METHOD="${2^^}"; shift 2;;
            -b|--body)        BODY="$2"; shift 2;;
            -H|--header)      CUSTOM_HEADERS+=("$2"); shift 2;;
            --content-type)   CONTENT_TYPE="$2"; shift 2;;
            --delay)          DELAY="$2"; shift 2;;
            --concurrency)    IFS=',' read -ra CONCURRENCY_LEVELS <<< "$2"; shift 2;;
            -o|--output)      OUTPUT_DIR="$2"; shift 2;;
            -h|--help)        usage;;
            *)                log_err "Unknown option: $1"; usage;;
        esac
    done

    if [[ -z "$TARGET_URL" ]]; then
        log_err "Target URL is required. Use -u <url>"
        exit 1
    fi
}

# ── Setup ──
setup_output() {
    OUTPUT_DIR="${OUTPUT_DIR}/${TIMESTAMP}"
    mkdir -p "$OUTPUT_DIR"/{results,raw}
    log_info "Output: ${BOLD}$OUTPUT_DIR${NC}"
}

# ── Generate Random IP ──
random_ip() {
    echo "$((RANDOM % 223 + 1)).$((RANDOM % 255)).$((RANDOM % 255)).$((RANDOM % 255))"
}

# ── Build Curl Command ──
build_curl_opts() {
    local strategy="$1"
    local iteration="$2"

    local opts=(
        -s -o /dev/null
        -w '%{http_code}|%{time_total}|%{size_download}'
        --connect-timeout 10
        --max-time 30
        -X "$METHOD"
    )

    # Content type
    if [[ -n "$CONTENT_TYPE" ]]; then
        opts+=(-H "Content-Type: $CONTENT_TYPE")
    elif [[ -n "$BODY" ]]; then
        opts+=(-H "Content-Type: application/json")
    fi

    # Body
    if [[ -n "$BODY" ]]; then
        opts+=(-d "$BODY")
    fi

    # Custom headers
    for header in "${CUSTOM_HEADERS[@]}"; do
        opts+=(-H "$header")
    done

    # Strategy-specific headers
    case "$strategy" in
        baseline)
            opts+=(-H "User-Agent: ${USER_AGENTS[0]}")
            ;;
        rotate-xff)
            local ip
            ip=$(random_ip)
            opts+=(-H "X-Forwarded-For: $ip")
            opts+=(-H "User-Agent: ${USER_AGENTS[0]}")
            ;;
        rotate-xrealip)
            local ip
            ip=$(random_ip)
            opts+=(-H "X-Real-IP: $ip")
            opts+=(-H "User-Agent: ${USER_AGENTS[0]}")
            ;;
        rotate-xorigip)
            local ip
            ip=$(random_ip)
            opts+=(-H "X-Originating-IP: $ip")
            opts+=(-H "X-Client-IP: $(random_ip)")
            opts+=(-H "X-Remote-IP: $(random_ip)")
            opts+=(-H "X-Remote-Addr: $(random_ip)")
            opts+=(-H "X-Forwarded-Host: $(random_ip)")
            opts+=(-H "User-Agent: ${USER_AGENTS[0]}")
            ;;
        rotate-ua)
            local ua_idx=$((iteration % ${#USER_AGENTS[@]}))
            opts+=(-H "User-Agent: ${USER_AGENTS[$ua_idx]}")
            ;;
        rotate-all)
            local ip
            ip=$(random_ip)
            local ua_idx=$((iteration % ${#USER_AGENTS[@]}))
            opts+=(-H "X-Forwarded-For: $ip")
            opts+=(-H "X-Real-IP: $(random_ip)")
            opts+=(-H "X-Originating-IP: $(random_ip)")
            opts+=(-H "User-Agent: ${USER_AGENTS[$ua_idx]}")
            ;;
        case-variation)
            # URL case variation bypass
            opts+=(-H "User-Agent: ${USER_AGENTS[0]}")
            ;;
    esac

    printf '%s\n' "${opts[@]}"
}

# ── Run Single Strategy ──
run_strategy() {
    local strategy="$1"
    local concurrency="$2"
    local result_file="$OUTPUT_DIR/raw/${strategy}_c${concurrency}.csv"

    echo "request_num,status_code,response_time,response_size,timestamp" > "$result_file"

    local codes_200=0 codes_429=0 codes_403=0 codes_other=0
    local total_time=0
    local pids=()
    local completed=0

    for i in $(seq 1 "$REQUESTS"); do
        (
            # Get curl options
            local -a curl_opts
            mapfile -t curl_opts < <(build_curl_opts "$strategy" "$i")

            local url="$TARGET_URL"

            # Case variation: randomize URL path casing
            if [[ "$strategy" == "case-variation" ]]; then
                # Simple case toggle on path component
                url=$(echo "$url" | sed "s|/api/|/Api/|; s|/API/|/api/|" 2>/dev/null) || url="$TARGET_URL"
            fi

            local result
            result=$(curl "${curl_opts[@]}" "$url" 2>/dev/null) || result="000|0|0"
            local code time_total size
            IFS='|' read -r code time_total size <<< "$result"

            echo "${i},${code},${time_total},${size},$(date +%s%N)" >> "$result_file"
        ) &
        pids+=($!)

        # Throttle concurrency
        if (( ${#pids[@]} >= concurrency )); then
            wait "${pids[@]}" 2>/dev/null || true
            pids=()
        fi

        # Inter-request delay
        if [[ "$DELAY" -gt 0 ]]; then
            sleep "$(echo "scale=3; $DELAY / 1000" | bc 2>/dev/null || echo "0.001")"
        fi
    done

    wait "${pids[@]}" 2>/dev/null || true

    # Analyze results
    if [[ -s "$result_file" ]]; then
        codes_200=$(awk -F',' 'NR>1 && $2 ~ /^2[0-9][0-9]$/ {count++} END {print count+0}' "$result_file")
        codes_429=$(awk -F',' 'NR>1 && $2 == "429" {count++} END {print count+0}' "$result_file")
        codes_403=$(awk -F',' 'NR>1 && $2 == "403" {count++} END {print count+0}' "$result_file")
        codes_other=$(awk -F',' 'NR>1 && $2 !~ /^(2[0-9][0-9]|429|403)$/ {count++} END {print count+0}' "$result_file")
        total_time=$(awk -F',' 'NR>1 {total+=$3} END {printf "%.3f", total+0}' "$result_file")

        local avg_time
        avg_time=$(awk -F',' 'NR>1 {total+=$3; count++} END {printf "%.3f", (count>0 ? total/count : 0)}' "$result_file")

        # Determine rate limit status
        local rl_status="${GREEN}RATE LIMITED${NC}"
        if [[ "$codes_429" -eq 0 && "$codes_403" -eq 0 ]]; then
            rl_status="${RED}NO RATE LIMIT${NC}"
        elif [[ "$codes_429" -gt 0 && "$codes_200" -gt "$codes_429" ]]; then
            rl_status="${YELLOW}PARTIAL RATE LIMIT${NC}"
        fi

        printf "  %-18s C=%-3s │ 2xx: %-4s 429: %-4s 403: %-4s Other: %-4s │ Avg: %ss │ %b\n" \
            "$strategy" "$concurrency" "$codes_200" "$codes_429" "$codes_403" "$codes_other" "$avg_time" "$rl_status"

        # Write to JSON results
        echo "$strategy|$concurrency|$codes_200|$codes_429|$codes_403|$codes_other|$avg_time|$total_time" \
            >> "$OUTPUT_DIR/results/summary.csv"
    fi
}

# ── Main Test Loop ──
run_tests() {
    local strategies=("baseline" "rotate-xff" "rotate-xrealip" "rotate-xorigip" "rotate-ua" "rotate-all" "case-variation")

    echo "strategy|concurrency|2xx|429|403|other|avg_time|total_time" > "$OUTPUT_DIR/results/summary.csv"

    for strategy in "${strategies[@]}"; do
        log_step "Strategy: ${strategy^^}"
        echo -e "  ${BOLD}Strategy          Conc │ Responses                                │ Timing    │ Status${NC}"
        echo    "  ──────────────────────┼──────────────────────────────────────────┼───────────┼────────────────"

        for concurrency in "${CONCURRENCY_LEVELS[@]}"; do
            run_strategy "$strategy" "$concurrency"
        done
        echo ""
    done
}

# ── Generate JSON Report ──
generate_report() {
    log_step "GENERATING REPORT"
    local report="$OUTPUT_DIR/results/rate-limit-report.json"
    local md_report="$OUTPUT_DIR/results/rate-limit-report.md"

    # JSON report
    {
        echo "{"
        echo "  \"target\": \"$TARGET_URL\","
        echo "  \"method\": \"$METHOD\","
        echo "  \"requests_per_test\": $REQUESTS,"
        echo "  \"timestamp\": \"$(date -Iseconds)\","
        echo "  \"results\": ["

        local first=true
        while IFS='|' read -r strategy concurrency c200 c429 c403 cother avg_time total_time; do
            [[ "$strategy" == "strategy" ]] && continue
            [[ "$first" == true ]] && first=false || echo ","

            local rl_detected="false"
            if [[ "$c429" -gt 0 || "$c403" -gt 0 ]]; then
                rl_detected="true"
            fi

            printf '    {"strategy": "%s", "concurrency": %s, "responses": {"2xx": %s, "429": %s, "403": %s, "other": %s}, "avg_response_time": %s, "total_time": %s, "rate_limited": %s}' \
                "$strategy" "$concurrency" "$c200" "$c429" "$c403" "$cother" "$avg_time" "$total_time" "$rl_detected"
        done < "$OUTPUT_DIR/results/summary.csv"

        echo ""
        echo "  ]"
        echo "}"
    } > "$report"

    # Markdown report
    cat > "$md_report" <<-REPORT
# Rate Limit Test Report
**Date:** $(date '+%Y-%m-%d %H:%M:%S %Z')
**Target:** $TARGET_URL
**Method:** $METHOD
**Requests per test:** $REQUESTS

---

## Results Summary

| Strategy | Concurrency | 2xx | 429 | 403 | Other | Avg Time | Rate Limited? |
|----------|------------|-----|-----|-----|-------|----------|---------------|
$(while IFS='|' read -r strategy concurrency c200 c429 c403 cother avg_time total_time; do
    [[ "$strategy" == "strategy" ]] && continue
    local rl="❌ No"
    if [[ "$c429" -gt 0 || "$c403" -gt 0 ]]; then rl="✅ Yes"; fi
    echo "| $strategy | $concurrency | $c200 | $c429 | $c403 | $cother | ${avg_time}s | $rl |"
done < "$OUTPUT_DIR/results/summary.csv")

## Analysis

### Rate Limit Bypass Vectors
$(
    local bypass_found=false
    while IFS='|' read -r strategy concurrency c200 c429 c403 cother avg_time total_time; do
        [[ "$strategy" == "strategy" || "$strategy" == "baseline" ]] && continue
        if [[ "$c429" -eq 0 && "$c403" -eq 0 ]]; then
            echo "- **$strategy** (concurrency=$concurrency): No rate limiting detected — potential bypass"
            bypass_found=true
        fi
    done < "$OUTPUT_DIR/results/summary.csv"
    if [[ "$bypass_found" != true ]]; then
        echo "No bypass vectors identified. Rate limiting appears consistent across all strategies."
    fi
)

---
*Raw CSV data: \`results/summary.csv\`*
*Full JSON report: \`results/rate-limit-report.json\`*
REPORT

    log_ok "JSON report: ${BOLD}$report${NC}"
    log_ok "MD report: ${BOLD}$md_report${NC}"
}

# ── Main ──
main() {
    banner
    parse_args "$@"
    setup_output

    log_info "Target:       ${BOLD}$TARGET_URL${NC}"
    log_info "Method:       ${BOLD}$METHOD${NC}"
    log_info "Requests:     ${BOLD}$REQUESTS${NC}"
    log_info "Concurrency:  ${BOLD}${CONCURRENCY_LEVELS[*]}${NC}"
    log_info "Delay:        ${BOLD}${DELAY}ms${NC}"
    echo ""

    local start_time=$SECONDS
    run_tests
    generate_report

    local elapsed=$(( SECONDS - start_time ))
    echo ""
    log_ok "Rate limit testing completed in ${BOLD}${elapsed}s${NC}"
    log_ok "Results: ${BOLD}$OUTPUT_DIR${NC}"
}

main "$@"
