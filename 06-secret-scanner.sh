#!/usr/bin/env bash
###############################################################################
# 06-secret-scanner.sh — Secret Leak Detection
# Scans HTTP responses & JS files for API keys, cloud secrets & credentials
# Entropy-based filtering + context-aware false-positive removal
# Part of z3r0-toolkit
###############################################################################
set -euo pipefail

# ── Colors ──
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; MAGENTA='\033[0;35m'; BOLD='\033[1m'; NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PATTERNS_FILE="$SCRIPT_DIR/config/secrets-patterns.conf"

# ── Banner ──
banner() {
    echo -e "${MAGENTA}${BOLD}"
    echo "╔══════════════════════════════════════════════════════════╗"
    echo "║           z3r0-toolkit • 06 SECRET SCANNER              ║"
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
THREADS=20
OUTPUT_DIR="./secret-scanner-output"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
MIN_ENTROPY=3.0
VERIFY_LIVE=false

# ── Usage ──
usage() {
    cat <<EOF
${BOLD}Usage:${NC} $0 [OPTIONS]

${BOLD}Input (at least one required):${NC}
  -u, --urls <file>           File with URLs to fetch and scan
  -d, --dir <directory>       Directory of files to scan (JS, HTML, JSON)
  --from-recon <dir>          Use live hosts from recon output

${BOLD}Options:${NC}
  -o, --output <dir>          Output directory (default: ./secret-scanner-output)
  -p, --patterns <file>       Custom patterns file
  -t, --threads <n>           Download threads (default: 20)
  --min-entropy <float>       Minimum Shannon entropy (default: 3.0)
  --verify                    Verify secrets are live (e.g., test API keys)
  -h, --help                  Show this help
EOF
    exit 0
}

# ── Parse Args ──
URLS_FILE=""
SCAN_DIR=""
RECON_DIR=""

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -u|--urls)        URLS_FILE="$2"; shift 2;;
            -d|--dir)         SCAN_DIR="$2"; shift 2;;
            --from-recon)     RECON_DIR="$2"; shift 2;;
            -o|--output)      OUTPUT_DIR="$2"; shift 2;;
            -p|--patterns)    PATTERNS_FILE="$2"; shift 2;;
            -t|--threads)     THREADS="$2"; shift 2;;
            --min-entropy)    MIN_ENTROPY="$2"; shift 2;;
            --verify)         VERIFY_LIVE=true; shift;;
            -h|--help)        usage;;
            *)                log_err "Unknown option: $1"; usage;;
        esac
    done

    if [[ -z "$URLS_FILE" && -z "$SCAN_DIR" && -z "$RECON_DIR" ]]; then
        log_err "At least one input source required"
        exit 1
    fi
}

# ── Setup ──
setup_output() {
    OUTPUT_DIR="${OUTPUT_DIR}/${TIMESTAMP}"
    mkdir -p "$OUTPUT_DIR"/{fetched,results}
    log_info "Output: ${BOLD}$OUTPUT_DIR${NC}"
}

# ── Load Patterns ──
declare -a PATTERN_NAMES=()
declare -a PATTERN_REGEXES=()
declare -a PATTERN_SEVERITIES=()
declare -a FP_PATTERNS=()

load_patterns() {
    log_info "Loading patterns from: $PATTERNS_FILE"

    if [[ ! -f "$PATTERNS_FILE" ]]; then
        log_err "Patterns file not found: $PATTERNS_FILE"
        exit 1
    fi

    while IFS= read -r line; do
        # Skip comments and empty lines
        [[ "$line" =~ ^#.*$ || -z "$line" || "$line" =~ ^[[:space:]]*$ ]] && continue

        # Split on ::: delimiter
        local name regex severity_or_rest
        name=$(echo "$line" | awk -F':::' '{print $1}')
        regex=$(echo "$line" | awk -F':::' '{print $2}')
        severity_or_rest=$(echo "$line" | awk -F':::' '{print $3}')

        if [[ "$name" == "FP" ]]; then
            FP_PATTERNS+=("$regex")
        else
            PATTERN_NAMES+=("$name")
            PATTERN_REGEXES+=("$regex")
            PATTERN_SEVERITIES+=("${severity_or_rest:-MEDIUM}")
        fi
    done < "$PATTERNS_FILE"

    log_ok "Loaded ${#PATTERN_NAMES[@]} patterns, ${#FP_PATTERNS[@]} FP filters"
}

# ── Shannon Entropy Calculator ──
calculate_entropy() {
    local str="$1"
    local len=${#str}

    if [[ $len -lt 8 ]]; then
        echo "0.0"
        return
    fi

    # Calculate character frequency and Shannon entropy using awk
    echo "$str" | fold -w1 | sort | uniq -c | awk -v len="$len" '
    BEGIN { entropy = 0.0 }
    {
        freq = $1 / len
        if (freq > 0) {
            entropy -= freq * log(freq) / log(2)
        }
    }
    END { printf "%.2f", entropy }
    '
}

# ── Check False Positive ──
is_false_positive() {
    local match="$1"
    local context="$2"

    # Check against FP patterns
    for fp_regex in ${FP_PATTERNS[@]+"${FP_PATTERNS[@]}"}; do
        if echo "$match" | grep -qiP "$fp_regex" 2>/dev/null; then
            return 0  # Is a false positive
        fi
    done

    # Context-aware checks
    # Check if in a comment
    if echo "$context" | grep -qP '^\s*(//|/\*|\*|<!--|#)' 2>/dev/null; then
        # Still flag if the match looks like a real credential
        local entropy
        entropy=$(calculate_entropy "$match")
        local is_high
        is_high=$(awk -v e="$entropy" -v min="4.5" 'BEGIN {print (e >= min) ? 1 : 0}')
        if [[ "$is_high" -eq 0 ]]; then
            return 0  # Low entropy in comment = likely FP
        fi
    fi

    # Check if in documentation/example block
    if echo "$context" | grep -qiP '(example|sample|demo|documentation|readme|tutorial|placeholder)' 2>/dev/null; then
        return 0
    fi

    # Check for repeated characters (AAAA..., xxxx..., 0000...)
    if echo "$match" | grep -qP '^(.)\1{7,}$' 2>/dev/null; then
        return 0
    fi

    return 1  # Not a false positive
}

# ── Fetch HTTP Responses ──
phase_fetch() {
    log_step "PHASE 1 — Fetching HTTP Responses"

    local urls_to_fetch="$OUTPUT_DIR/urls-to-fetch.txt"
    touch "$urls_to_fetch"

    if [[ -n "$URLS_FILE" && -s "$URLS_FILE" ]]; then
        cat "$URLS_FILE" >> "$urls_to_fetch"
    fi

    if [[ -n "$RECON_DIR" ]]; then
        # Gather JS files, live hosts, and API URLs from recon
        local files_to_check=("js-files.txt" "live-hosts.txt" "api-urls.txt")
        for fname in "${files_to_check[@]}"; do
            local found_file
            found_file=$(find "$RECON_DIR" -name "$fname" -type f 2>/dev/null | head -1)
            if [[ -n "$found_file" && -s "$found_file" ]]; then
                cat "$found_file" >> "$urls_to_fetch"
                log_info "Added $(wc -l < "$found_file") URLs from $fname"
            fi
        done
    fi

    sort -u "$urls_to_fetch" -o "$urls_to_fetch"

    if [[ ! -s "$urls_to_fetch" ]]; then
        log_warn "No URLs to fetch"
        return
    fi

    local total
    total=$(wc -l < "$urls_to_fetch")
    log_info "Fetching $total URLs..."

    local count=0
    while IFS= read -r url; do
        [[ -z "$url" ]] && continue
        count=$((count + 1))

        local hash
        hash=$(echo "$url" | md5sum | cut -d' ' -f1)

        (
            curl -sL --connect-timeout 10 --max-time 30 \
                -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)" \
                -D "$OUTPUT_DIR/fetched/${hash}.headers" \
                -o "$OUTPUT_DIR/fetched/${hash}.body" \
                "$url" 2>/dev/null || true

            echo "${hash}:::$url" >> "$OUTPUT_DIR/fetched/url-map.txt"
        ) &

        if (( count % THREADS == 0 )); then
            wait
            log_info "Fetched $count / $total"
        fi
    done < "$urls_to_fetch"
    wait

    log_ok "Fetched $count responses"
}

# ── Phase 2: Scan for Secrets ──
phase_scan() {
    log_step "PHASE 2 — Scanning for Secrets"

    local scan_dirs=("$OUTPUT_DIR/fetched")
    [[ -n "$SCAN_DIR" && -d "$SCAN_DIR" ]] && scan_dirs+=("$SCAN_DIR")

    local secrets_json="$OUTPUT_DIR/results/secrets-raw.json"
    local secrets_txt="$OUTPUT_DIR/results/secrets-raw.txt"
    echo "[]" > "$secrets_json"
    touch "$secrets_txt"

    local found_count=0
    local fp_count=0
    local total_files=0

    for dir in "${scan_dirs[@]}"; do
        for file in "$dir"/*; do
            [[ ! -f "$file" ]] && continue
            [[ "$file" == *.headers ]] && continue
            [[ "$file" == *url-map.txt ]] && continue
            total_files=$((total_files + 1))

            local basename_file
            basename_file=$(basename "$file")

            # Get source URL
            local source_url="file://$basename_file"
            if [[ -f "$OUTPUT_DIR/fetched/url-map.txt" ]]; then
                local hash="${basename_file%%.*}"
                local mapped
                mapped=$(grep "^${hash}:::" "$OUTPUT_DIR/fetched/url-map.txt" 2>/dev/null \
                    | head -1 | sed 's/^[^:]*::://') || true
                [[ -n "$mapped" ]] && source_url="$mapped"
            fi

            # Scan with each pattern
            for i in "${!PATTERN_NAMES[@]}"; do
                local name="${PATTERN_NAMES[$i]}"
                local regex="${PATTERN_REGEXES[$i]}"
                local severity="${PATTERN_SEVERITIES[$i]}"

                grep -noP "$regex" "$file" 2>/dev/null | while IFS=: read -r line_num match; do
                    [[ -z "$match" ]] && continue

                    # Get context line
                    local context
                    context=$(sed -n "${line_num}p" "$file" 2>/dev/null) || context=""

                    # Check false positive
                    if is_false_positive "$match" "$context"; then
                        fp_count=$((fp_count + 1))
                        continue
                    fi

                    # Compute entropy
                    local entropy
                    entropy=$(calculate_entropy "$match")

                    # Filter low-entropy matches
                    local passes_entropy
                    passes_entropy=$(awk -v e="$entropy" -v min="$MIN_ENTROPY" \
                        'BEGIN {print (e >= min) ? 1 : 0}')

                    if [[ "$passes_entropy" -eq 0 ]]; then
                        fp_count=$((fp_count + 1))
                        continue
                    fi

                    found_count=$((found_count + 1))

                    # Confidence score based on severity + entropy
                    local confidence
                    case "$severity" in
                        CRITICAL) confidence=$(awk -v e="$entropy" 'BEGIN {printf "%.0f", 70 + (e * 5)}');;
                        HIGH)     confidence=$(awk -v e="$entropy" 'BEGIN {printf "%.0f", 50 + (e * 5)}');;
                        MEDIUM)   confidence=$(awk -v e="$entropy" 'BEGIN {printf "%.0f", 30 + (e * 5)}');;
                        *)        confidence=$(awk -v e="$entropy" 'BEGIN {printf "%.0f", 20 + (e * 5)}');;
                    esac
                    [[ "$confidence" -gt 100 ]] && confidence=100

                    # Truncate for display
                    local display="${match:0:80}"
                    [[ ${#match} -gt 80 ]] && display="${display}..."

                    echo "[$severity] ($confidence%) $name | $source_url:$line_num | $display" >> "$secrets_txt"

                    # Append to JSON
                    local entry
                    entry=$(jq -n \
                        --arg type "$name" \
                        --arg severity "$severity" \
                        --arg source "$source_url" \
                        --arg file "$basename_file" \
                        --arg line "$line_num" \
                        --arg match "$display" \
                        --arg entropy "$entropy" \
                        --arg confidence "$confidence" \
                        '{type: $type, severity: $severity, source: $source, file: $file, line: ($line | tonumber), match: $match, entropy: ($entropy | tonumber), confidence: ($confidence | tonumber)}' \
                        2>/dev/null) || continue

                    local updated
                    updated=$(jq --argjson entry "$entry" '. += [$entry]' "$secrets_json" 2>/dev/null) || continue
                    echo "$updated" > "$secrets_json"

                done
            done
        done
    done

    log_ok "Scanned ${BOLD}$total_files${NC} files"
    log_ok "Secrets found: ${BOLD}$found_count${NC}"
    log_ok "False positives filtered: ${BOLD}$fp_count${NC}"
}

# ── Phase 3: Post-Processing ──
phase_postprocess() {
    log_step "PHASE 3 — Post-Processing & Verification"

    local raw_json="$OUTPUT_DIR/results/secrets-raw.json"
    local verified_json="$OUTPUT_DIR/results/secrets-verified.json"

    if [[ ! -s "$raw_json" ]] || [[ $(jq length "$raw_json" 2>/dev/null) -eq 0 ]]; then
        log_warn "No secrets to post-process"
        echo "[]" > "$verified_json"
        return
    fi

    # Sort by confidence (descending), then severity
    jq 'sort_by(-.confidence) | sort_by(
        if .severity == "CRITICAL" then 0
        elif .severity == "HIGH" then 1
        elif .severity == "MEDIUM" then 2
        else 3 end
    )' "$raw_json" > "$verified_json" 2>/dev/null || cp "$raw_json" "$verified_json"

    # Generate severity breakdown
    local critical high medium low
    critical=$(jq '[.[] | select(.severity == "CRITICAL")] | length' "$verified_json" 2>/dev/null || echo 0)
    high=$(jq '[.[] | select(.severity == "HIGH")] | length' "$verified_json" 2>/dev/null || echo 0)
    medium=$(jq '[.[] | select(.severity == "MEDIUM")] | length' "$verified_json" 2>/dev/null || echo 0)
    low=$(jq '[.[] | select(.severity == "LOW")] | length' "$verified_json" 2>/dev/null || echo 0)

    echo ""
    echo -e "  ${RED}${BOLD}CRITICAL${NC}  $critical findings"
    echo -e "  ${YELLOW}${BOLD}HIGH${NC}      $high findings"
    echo -e "  ${CYAN}${BOLD}MEDIUM${NC}    $medium findings"
    echo -e "  ${GREEN}${BOLD}LOW${NC}       $low findings"

    # Optional: Verify secrets are live
    if [[ "$VERIFY_LIVE" == true ]]; then
        log_info "Verifying secrets (live checks)..."

        jq -c '.[] | select(.severity == "CRITICAL")' "$verified_json" 2>/dev/null \
        | while IFS= read -r entry; do
            local type match
            type=$(echo "$entry" | jq -r '.type')
            match=$(echo "$entry" | jq -r '.match')

            case "$type" in
                GCP_API_KEY|FIREBASE_API_KEY)
                    local check_url="https://maps.googleapis.com/maps/api/staticmap?center=0,0&zoom=1&size=1x1&key=${match}"
                    local code
                    code=$(curl -s -o /dev/null -w '%{http_code}' "$check_url" 2>/dev/null) || code="000"
                    if [[ "$code" == "200" ]]; then
                        log_warn "VERIFIED LIVE: $type — Google API key is active!"
                    fi
                    ;;
                GITHUB_TOKEN)
                    local code
                    code=$(curl -s -o /dev/null -w '%{http_code}' \
                        -H "Authorization: token ${match}" \
                        "https://api.github.com/user" 2>/dev/null) || code="000"
                    if [[ "$code" == "200" ]]; then
                        log_warn "VERIFIED LIVE: $type — GitHub token is active!"
                    fi
                    ;;
            esac
        done
    fi
}

# ── Report ──
generate_report() {
    log_step "GENERATING REPORT"
    local report="$OUTPUT_DIR/results/secret-scanner-report.md"
    local verified_json="$OUTPUT_DIR/results/secrets-verified.json"

    local total
    total=$(jq length "$verified_json" 2>/dev/null || echo 0)

    cat > "$report" <<-REPORT
# Secret Leak Detection Report
**Date:** $(date '+%Y-%m-%d %H:%M:%S %Z')
**Toolkit:** z3r0-toolkit v1.0
**Entropy Threshold:** $MIN_ENTROPY

---

## Summary
| Severity | Count |
|----------|-------|
| 🔴 CRITICAL | $(jq '[.[] | select(.severity == "CRITICAL")] | length' "$verified_json" 2>/dev/null || echo 0) |
| 🟠 HIGH | $(jq '[.[] | select(.severity == "HIGH")] | length' "$verified_json" 2>/dev/null || echo 0) |
| 🟡 MEDIUM | $(jq '[.[] | select(.severity == "MEDIUM")] | length' "$verified_json" 2>/dev/null || echo 0) |
| 🟢 LOW | $(jq '[.[] | select(.severity == "LOW")] | length' "$verified_json" 2>/dev/null || echo 0) |
| **Total** | **$total** |

## Top Findings (High Confidence)
$(jq -r '.[:20] | .[] | "- [\(.severity)] **\(.type)** in \(.source):\(.line) (confidence: \(.confidence)%) — \(.match)"' \
    "$verified_json" 2>/dev/null || echo "No findings")

## Findings by Type
$(jq -r 'group_by(.type) | .[] | "- **\(.[0].type)** [\(.[0].severity)]: \(length) occurrence(s)"' \
    "$verified_json" 2>/dev/null || echo "No data")

---
*Full JSON: \`results/secrets-verified.json\`*
REPORT

    log_ok "Report: ${BOLD}$report${NC}"
}

# ── Main ──
main() {
    banner
    parse_args "$@"
    load_patterns
    setup_output

    local start_time=$SECONDS
    phase_fetch
    phase_scan
    phase_postprocess
    generate_report

    local elapsed=$(( SECONDS - start_time ))
    echo ""
    log_ok "Secret scanning completed in ${BOLD}${elapsed}s${NC}"
    log_ok "Results: ${BOLD}$OUTPUT_DIR${NC}"
}

main "$@"
