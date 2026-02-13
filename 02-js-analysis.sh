#!/usr/bin/env bash
# Copyright (c) 2026 z3r0_ru135
###############################################################################
# 02-js-analysis.sh — JavaScript File Scanner
# Extracts API endpoints, secrets, tokens & sensitive parameters from JS files
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
    echo "║           z3r0-toolkit • 02 JS ANALYSIS                 ║"
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
OUTPUT_DIR="./js-analysis-output"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# ── Usage ──
usage() {
    cat <<EOF
${BOLD}Usage:${NC} $0 [OPTIONS]

${BOLD}Input (one required):${NC}
  -u, --url <url>             Single JS URL to analyze
  -l, --list <file>           File with JS URLs (one per line)
  -d, --dir <directory>       Directory of downloaded JS files
  --from-recon <dir>          Use js-files.txt from recon output

${BOLD}Options:${NC}
  -o, --output <dir>          Output directory (default: ./js-analysis-output)
  -t, --threads <n>           Download threads (default: 20)
  -p, --patterns <file>       Custom patterns file
      --no-download           Skip download, analyze existing files only
  -h, --help                  Show this help
EOF
    exit 0
}

# ── Parse Args ──
INPUT_URL=""
INPUT_LIST=""
INPUT_DIR=""
RECON_DIR=""
NO_DOWNLOAD=false

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -u|--url)         INPUT_URL="$2"; shift 2;;
            -l|--list)        INPUT_LIST="$2"; shift 2;;
            -d|--dir)         INPUT_DIR="$2"; shift 2;;
            --from-recon)     RECON_DIR="$2"; shift 2;;
            -o|--output)      OUTPUT_DIR="$2"; shift 2;;
            -t|--threads)     THREADS="$2"; shift 2;;
            -p|--patterns)    PATTERNS_FILE="$2"; shift 2;;
            --no-download)    NO_DOWNLOAD=true; shift;;
            -h|--help)        usage;;
            *)                log_err "Unknown option: $1"; usage;;
        esac
    done

    if [[ -z "$INPUT_URL" && -z "$INPUT_LIST" && -z "$INPUT_DIR" && -z "$RECON_DIR" ]]; then
        log_err "Input required. Use -u, -l, -d, or --from-recon"
        exit 1
    fi
}

# ── Setup ──
setup_output() {
    OUTPUT_DIR="${OUTPUT_DIR}/${TIMESTAMP}"
    mkdir -p "$OUTPUT_DIR"/{downloaded,endpoints,secrets,report}
    log_info "Output: ${BOLD}$OUTPUT_DIR${NC}"
}

# ── Load Patterns ──
declare -A SECRET_PATTERNS
declare -a FP_PATTERNS=()

load_patterns() {
    log_info "Loading patterns from: $PATTERNS_FILE"
    if [[ ! -f "$PATTERNS_FILE" ]]; then
        log_warn "Patterns file not found, using built-in patterns"
        return
    fi

    while IFS= read -r line; do
        # Skip comments and empty lines
        [[ "$line" =~ ^#.*$ || -z "$line" || "$line" =~ ^[[:space:]]*$ ]] && continue
        local name regex severity
        name=$(echo "$line" | awk -F':::' '{print $1}')
        regex=$(echo "$line" | awk -F':::' '{print $2}')
        severity=$(echo "$line" | awk -F':::' '{print $3}')
        if [[ "$name" == "FP" ]]; then
            FP_PATTERNS+=("$regex")
        else
            SECRET_PATTERNS["$name"]="${severity}§${regex}"
        fi
    done < "$PATTERNS_FILE"

    log_ok "Loaded ${#SECRET_PATTERNS[@]} secret patterns, ${#FP_PATTERNS[@]} FP filters"
}

# ── Build JS URL List ──
build_js_list() {
    local js_urls="$OUTPUT_DIR/js-urls.txt"
    touch "$js_urls"

    if [[ -n "$INPUT_URL" ]]; then
        echo "$INPUT_URL" >> "$js_urls"
    fi

    if [[ -n "$INPUT_LIST" ]]; then
        cat "$INPUT_LIST" >> "$js_urls"
    fi

    if [[ -n "$RECON_DIR" ]]; then
        local recon_js
        recon_js=$(find "$RECON_DIR" -name "js-files.txt" -type f 2>/dev/null | head -1)
        if [[ -n "$recon_js" && -s "$recon_js" ]]; then
            cat "$recon_js" >> "$js_urls"
            log_ok "Loaded $(wc -l < "$recon_js") JS URLs from recon"
        else
            log_warn "No js-files.txt found in recon directory"
        fi
    fi

    sort -u "$js_urls" -o "$js_urls"
    log_info "Total JS URLs: $(wc -l < "$js_urls")"
}

# ── Download JS Files ──
download_js() {
    log_step "PHASE 1 — Downloading JS Files"

    if [[ "$NO_DOWNLOAD" == true ]]; then
        log_warn "Download skipped (--no-download)"
        return
    fi

    local js_urls="$OUTPUT_DIR/js-urls.txt"
    if [[ ! -s "$js_urls" ]]; then
        log_warn "No JS URLs to download"
        return
    fi

    local count=0
    local total
    total=$(wc -l < "$js_urls")

    while IFS= read -r url; do
        count=$((count + 1))
        local filename
        filename=$(echo "$url" | md5sum | cut -d' ' -f1)
        local ext="${url##*.}"
        [[ "$ext" != "js" ]] && ext="js"

        if [[ ! -f "$OUTPUT_DIR/downloaded/${filename}.${ext}" ]]; then
            curl -sL --connect-timeout 10 --max-time 30 \
                -o "$OUTPUT_DIR/downloaded/${filename}.${ext}" \
                "$url" 2>/dev/null &

            # URL-to-filename mapping
            echo "${filename}.${ext}:::$url" >> "$OUTPUT_DIR/downloaded/url-map.txt"

            # Throttle concurrency
            if (( count % THREADS == 0 )); then
                wait
                log_info "Downloaded $count / $total"
            fi
        fi
    done < "$js_urls"
    wait

    log_ok "Downloaded $count JS files"
}

# ── Phase 2: Extract API Endpoints ──
extract_endpoints() {
    log_step "PHASE 2 — Extracting API Endpoints"

    local js_dir="$OUTPUT_DIR/downloaded"
    [[ -n "$INPUT_DIR" ]] && js_dir="$INPUT_DIR"

    local endpoints_file="$OUTPUT_DIR/endpoints/all-endpoints.txt"
    local endpoints_json="$OUTPUT_DIR/endpoints/endpoints.json"
    touch "$endpoints_file"
    echo "[]" > "$endpoints_json"

    # Endpoint extraction patterns
    local -a endpoint_patterns=(
        # Absolute URLs
        'https?://[a-zA-Z0-9./?=_%&:#\-]+'
        # Relative paths
        '/[a-zA-Z0-9._\-/]{2,}(?:\?[a-zA-Z0-9._=&\-%]+)?'
        # API paths
        '/api/v[0-9]+/[a-zA-Z0-9._\-/]+'
        # fetch/axios calls
        'fetch\s*\(\s*['\''"`][^'\''"`]+['\''"`]'
        'axios\.[a-z]+\s*\(\s*['\''"`][^'\''"`]+['\''"`]'
        # XMLHttpRequest
        '\.open\s*\(\s*['\''"](?:GET|POST|PUT|DELETE|PATCH)['\''"],\s*['\''"`][^'\''"`]+['\''"`]'
        # jQuery AJAX
        '\$\.(?:ajax|get|post)\s*\(\s*[{'\''"`]'
        # WebSocket
        'wss?://[a-zA-Z0-9./?=_%&:#\-]+'
        # GraphQL
        '/graphql'
        'query\s*\{[^}]+\}'
    )

    local temp_matches="$OUTPUT_DIR/endpoints/raw-matches.txt"
    touch "$temp_matches"

    for jsfile in "$js_dir"/*.js; do
        [[ ! -f "$jsfile" ]] && continue
        local basename_file
        basename_file=$(basename "$jsfile")

        for pattern in "${endpoint_patterns[@]}"; do
            (grep -oP "$pattern" "$jsfile" 2>/dev/null || true) | while IFS= read -r match; do
                echo "$match" >> "$temp_matches"
                # Build JSON
                local source_url=""
                if [[ -f "$OUTPUT_DIR/downloaded/url-map.txt" ]]; then
                    source_url=$(grep "^${basename_file}:::" "$OUTPUT_DIR/downloaded/url-map.txt" \
                        | sed 's/^[^:]*::://' || true)
                fi
            done
        done
    done

    # Deduplicate and clean
    sort -u "$temp_matches" | grep -vE '^/$|^/\.$|^\s*$' > "$endpoints_file" 2>/dev/null || true

    # Categorize endpoints
    grep -iE '/api/' "$endpoints_file" > "$OUTPUT_DIR/endpoints/api-endpoints.txt" 2>/dev/null || true
    grep -iE 'https?://' "$endpoints_file" > "$OUTPUT_DIR/endpoints/absolute-urls.txt" 2>/dev/null || true
    grep -iE '/graphql|/gql' "$endpoints_file" > "$OUTPUT_DIR/endpoints/graphql.txt" 2>/dev/null || true
    grep -iE 'wss?://' "$endpoints_file" > "$OUTPUT_DIR/endpoints/websockets.txt" 2>/dev/null || true

    log_ok "Extracted endpoints: ${BOLD}$(wc -l < "$endpoints_file")${NC}"
    log_info "  API endpoints:  $(wc -l < "$OUTPUT_DIR/endpoints/api-endpoints.txt" 2>/dev/null || echo 0)"
    log_info "  Absolute URLs:  $(wc -l < "$OUTPUT_DIR/endpoints/absolute-urls.txt" 2>/dev/null || echo 0)"
    log_info "  GraphQL:        $(wc -l < "$OUTPUT_DIR/endpoints/graphql.txt" 2>/dev/null || echo 0)"
    log_info "  WebSockets:     $(wc -l < "$OUTPUT_DIR/endpoints/websockets.txt" 2>/dev/null || echo 0)"
}

# ── Phase 3: Secret Detection ──
detect_secrets() {
    log_step "PHASE 3 — Secret & Token Detection"

    local js_dir="$OUTPUT_DIR/downloaded"
    [[ -n "$INPUT_DIR" ]] && js_dir="$INPUT_DIR"

    local secrets_json="$OUTPUT_DIR/secrets/js-secrets.json"
    local secrets_txt="$OUTPUT_DIR/secrets/js-secrets.txt"
    echo "[]" > "$secrets_json"
    touch "$secrets_txt"

    local found_count=0
    local filtered_count=0

    for jsfile in "$js_dir"/*.js; do
        [[ ! -f "$jsfile" ]] && continue
        local basename_file
        basename_file=$(basename "$jsfile")

        # Get source URL
        local source_url="local://$basename_file"
        if [[ -f "$OUTPUT_DIR/downloaded/url-map.txt" ]]; then
            local mapped
            mapped=$(grep "^${basename_file}:::" "$OUTPUT_DIR/downloaded/url-map.txt" 2>/dev/null \
                | head -1 | sed 's/^[^:]*::://') || true
            [[ -n "$mapped" ]] && source_url="$mapped"
        fi

        for pattern_name in "${!SECRET_PATTERNS[@]}"; do
            local _val="${SECRET_PATTERNS[$pattern_name]}"
            severity="${_val%%§*}"
            regex="${_val#*§}"

            (grep -noP "$regex" "$jsfile" 2>/dev/null || true) | while IFS=: read -r line_num match; do
                # Check false positives
                local is_fp=false
                for fp in ${FP_PATTERNS[@]+"${FP_PATTERNS[@]}"}; do
                    if echo "$match" | grep -qiP "$fp" 2>/dev/null; then
                        is_fp=true
                        filtered_count=$((filtered_count + 1))
                        break
                    fi
                done

                if [[ "$is_fp" == false ]]; then
                    found_count=$((found_count + 1))

                    # Get surrounding context (3 lines before/after)
                    local context
                    context=$(sed -n "$((line_num > 3 ? line_num - 3 : 1)),$((line_num + 3))p" "$jsfile" 2>/dev/null || true)

                    # Check if in comment
                    local in_comment="false"
                    local line_content
                    line_content=$(sed -n "${line_num}p" "$jsfile" 2>/dev/null || true)
                    if echo "$line_content" | grep -qE '^\s*(//|/\*|\*)' 2>/dev/null; then
                        in_comment="true"
                    fi

                    # Truncate match for display
                    local display_match="${match:0:80}"
                    [[ ${#match} -gt 80 ]] && display_match="${display_match}..."

                    echo "[${severity}] ${pattern_name} in ${basename_file}:${line_num} => ${display_match}" >> "$secrets_txt"

                    # Build JSON entry
                    local json_entry
                    json_entry=$(jq -n \
                        --arg type "$pattern_name" \
                        --arg severity "$severity" \
                        --arg file "$basename_file" \
                        --arg source "$source_url" \
                        --arg line "$line_num" \
                        --arg match "$display_match" \
                        --arg in_comment "$in_comment" \
                        '{type: $type, severity: $severity, file: $file, source: $source, line: ($line | tonumber), match: $match, in_comment: ($in_comment == "true")}' \
                        2>/dev/null) || true

                    if [[ -n "$json_entry" ]]; then
                        local tmp_json
                        tmp_json=$(jq --argjson entry "$json_entry" '. += [$entry]' "$secrets_json" 2>/dev/null) || true
                        [[ -n "$tmp_json" ]] && echo "$tmp_json" > "$secrets_json"
                    fi
                fi
            done
        done
    done

    # Sort by severity
    if [[ -s "$secrets_json" ]]; then
        local sorted
        sorted=$(jq 'sort_by(
            if .severity == "CRITICAL" then 0
            elif .severity == "HIGH" then 1
            elif .severity == "MEDIUM" then 2
            else 3 end
        )' "$secrets_json" 2>/dev/null) || true
        [[ -n "$sorted" ]] && echo "$sorted" > "$secrets_json"
    fi

    log_ok "Secrets found: ${BOLD}$found_count${NC} (filtered $filtered_count false positives)"
}

# ── Phase 4: Sensitive Parameter Detection ──
detect_sensitive_params() {
    log_step "PHASE 4 — Sensitive Parameter Extraction"

    local js_dir="$OUTPUT_DIR/downloaded"
    [[ -n "$INPUT_DIR" ]] && js_dir="$INPUT_DIR"

    local params_file="$OUTPUT_DIR/endpoints/sensitive-params.txt"
    touch "$params_file"

    # Patterns for sensitive parameter names in JS
    local -a sensitive_param_patterns=(
        '["\x27](?:api[_-]?key|apikey|api[_-]?secret)["\x27]\s*[=:]'
        '["\x27](?:token|access[_-]?token|auth[_-]?token|session[_-]?token)["\x27]\s*[=:]'
        '["\x27](?:password|passwd|pwd|pass)["\x27]\s*[=:]'
        '["\x27](?:secret|client[_-]?secret|app[_-]?secret)["\x27]\s*[=:]'
        '["\x27](?:private[_-]?key|priv[_-]?key)["\x27]\s*[=:]'
        '["\x27](?:authorization|auth[_-]?header)["\x27]\s*[=:]'
        '["\x27](?:aws[_-]?access|aws[_-]?secret|aws[_-]?key)["\x27]\s*[=:]'
        '["\x27](?:database[_-]?url|db[_-]?password|db[_-]?host)["\x27]\s*[=:]'
        '["\x27](?:smtp[_-]?password|mail[_-]?password)["\x27]\s*[=:]'
        '["\x27](?:encryption[_-]?key|signing[_-]?key)["\x27]\s*[=:]'
    )

    for jsfile in "$js_dir"/*.js; do
        [[ ! -f "$jsfile" ]] && continue
        local basename_file
        basename_file=$(basename "$jsfile")

        for pattern in "${sensitive_param_patterns[@]}"; do
            (grep -noP "$pattern" "$jsfile" 2>/dev/null || true) | while IFS=: read -r line_num match; do
                echo "$basename_file:$line_num: $match" >> "$params_file"
            done
        done
    done

    sort -u "$params_file" -o "$params_file"
    log_ok "Sensitive parameters: ${BOLD}$(wc -l < "$params_file")${NC}"
}

# ── Summary ──
generate_report() {
    log_step "GENERATING REPORT"
    local report="$OUTPUT_DIR/report/js-analysis-summary.md"

    cat > "$report" <<-REPORT
# JS Analysis Report
**Date:** $(date '+%Y-%m-%d %H:%M:%S %Z')
**Toolkit:** z3r0-toolkit v1.0

---

## Endpoints Discovered
- **Total:** $(wc -l < "$OUTPUT_DIR/endpoints/all-endpoints.txt" 2>/dev/null || echo 0)
- API: $(wc -l < "$OUTPUT_DIR/endpoints/api-endpoints.txt" 2>/dev/null || echo 0)
- Absolute URLs: $(wc -l < "$OUTPUT_DIR/endpoints/absolute-urls.txt" 2>/dev/null || echo 0)
- GraphQL: $(wc -l < "$OUTPUT_DIR/endpoints/graphql.txt" 2>/dev/null || echo 0)
- WebSockets: $(wc -l < "$OUTPUT_DIR/endpoints/websockets.txt" 2>/dev/null || echo 0)

## Secrets & Tokens
$(if [[ -s "$OUTPUT_DIR/secrets/js-secrets.json" ]]; then
    echo "| Severity | Type | File | Line |"
    echo "|----------|------|------|------|"
    jq -r '.[] | "| \(.severity) | \(.type) | \(.file) | \(.line) |"' \
        "$OUTPUT_DIR/secrets/js-secrets.json" 2>/dev/null || echo "| - | - | - | - |"
else
    echo "No secrets detected."
fi)

## Sensitive Parameters
- Found: $(wc -l < "$OUTPUT_DIR/endpoints/sensitive-params.txt" 2>/dev/null || echo 0)

---
*Full details in \`secrets/js-secrets.json\`*
REPORT

    log_ok "Report: ${BOLD}$report${NC}"
}

# ── Main ──
main() {
    banner
    parse_args "$@"
    load_patterns
    setup_output
    build_js_list

    local start_time=$SECONDS
    download_js
    extract_endpoints
    detect_secrets
    detect_sensitive_params
    generate_report

    local elapsed=$(( SECONDS - start_time ))
    echo ""
    log_ok "JS analysis completed in ${BOLD}${elapsed}s${NC}"
    log_ok "Results: ${BOLD}$OUTPUT_DIR${NC}"
}

main "$@"
