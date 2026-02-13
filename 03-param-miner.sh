#!/usr/bin/env bash
###############################################################################
# 03-param-miner.sh — Parameter Extraction & Risk Categorization
# Extracts params from URLs, JS files & APIs, categorizes by risk level
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
    echo "║           z3r0-toolkit • 03 PARAMETER MINER             ║"
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
OUTPUT_DIR="./param-miner-output"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# ── Risk categorization maps ──
# CRITICAL: Authentication, authorization, secrets
CRITICAL_PARAMS='(api[-_]?key|apikey|api[-_]?secret|secret[-_]?key|private[-_]?key|token|access[-_]?token|auth[-_]?token|session[-_]?token|refresh[-_]?token|jwt|bearer|password|passwd|pwd|pass|credentials|client[-_]?secret|client[-_]?id|oauth|authorization|x[-_]?api[-_]?key|x[-_]?auth[-_]?token|auth|authentication|session[-_]?id|sessionid|sid|ssn|credit[-_]?card|cc[-_]?number|cvv|account[-_]?number)'

# HIGH: Injection-prone, redirect, file access
HIGH_PARAMS='(redirect|redirect[-_]?url|redirect[-_]?uri|return[-_]?url|return[-_]?to|next|goto|url|uri|link|dest|destination|target|continue|rurl|callback|callback[-_]?url|file|filename|filepath|path|folder|dir|directory|document|template|include|require|load|read|fetch|download|upload|cmd|exec|command|run|system|process|eval|code|query|sql|ldap|xpath|xml|ssrf|proxy|host|ip|port|domain|server|admin|debug|test|internal)'

# MEDIUM: Data identifiers, search, user input
MEDIUM_PARAMS='(id|user[-_]?id|userid|uid|account[-_]?id|account|profile[-_]?id|order[-_]?id|item[-_]?id|product[-_]?id|ref|reference|key|email|mail|username|user|name|phone|address|search|q|query|filter|find|keyword|term|text|body|content|message|comment|note|description|title|subject|data|value|input|param|type|category|class|group|role|permission|scope|level|status|state|action|method|mode|format|lang|locale|currency|country|region)'

# LOW: Pagination, display, UI
LOW_PARAMS='(page|p|pagesize|page[-_]?size|per[-_]?page|limit|offset|skip|start|count|num|number|size|length|max|min|from|to|begin|end|after|before|cursor|sort|order|orderby|order[-_]?by|sortby|sort[-_]?by|asc|desc|view|display|show|hide|columns|fields|expand|embed|include[-_]?fields|exclude[-_]?fields|format|output|response[-_]?type|pretty|indent|verbose|v|version|ver|ts|timestamp|t|time|date|cache|nocache|no[-_]?cache|refresh|reload|force|width|height|w|h|color|theme|style|font|bg|background|tab|section|step|index|pos|position)'

# ── Usage ──
usage() {
    cat <<EOF
${BOLD}Usage:${NC} $0 [OPTIONS]

${BOLD}Input (at least one required):${NC}
  -u, --urls <file>           File with URLs containing parameters
  -j, --js-dir <dir>          Directory of JS files to mine
  -a, --api-responses <dir>   Directory of API response files (JSON/XML)
  --from-recon <dir>          Use parameterized.txt from recon output
  --from-js <dir>             Use endpoints from JS analysis output

${BOLD}Options:${NC}
  -o, --output <dir>          Output directory (default: ./param-miner-output)
  -h, --help                  Show this help
EOF
    exit 0
}

# ── Parse Args ──
URLS_FILE=""
JS_DIR=""
API_DIR=""
RECON_DIR=""
JS_ANALYSIS_DIR=""

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -u|--urls)        URLS_FILE="$2"; shift 2;;
            -j|--js-dir)      JS_DIR="$2"; shift 2;;
            -a|--api-responses) API_DIR="$2"; shift 2;;
            --from-recon)     RECON_DIR="$2"; shift 2;;
            --from-js)        JS_ANALYSIS_DIR="$2"; shift 2;;
            -o|--output)      OUTPUT_DIR="$2"; shift 2;;
            -h|--help)        usage;;
            *)                log_err "Unknown option: $1"; usage;;
        esac
    done

    if [[ -z "$URLS_FILE" && -z "$JS_DIR" && -z "$API_DIR" && -z "$RECON_DIR" && -z "$JS_ANALYSIS_DIR" ]]; then
        log_err "At least one input source required"
        exit 1
    fi
}

# ── Setup ──
setup_output() {
    OUTPUT_DIR="${OUTPUT_DIR}/${TIMESTAMP}"
    mkdir -p "$OUTPUT_DIR"
    log_info "Output: ${BOLD}$OUTPUT_DIR${NC}"
}

# ── Phase 1: Extract from URLs ──
extract_from_urls() {
    log_step "PHASE 1 — Extracting Parameters from URLs"

    local url_file=""
    if [[ -n "$URLS_FILE" ]]; then
        url_file="$URLS_FILE"
    elif [[ -n "$RECON_DIR" ]]; then
        url_file=$(find "$RECON_DIR" -name "parameterized.txt" -type f 2>/dev/null | head -1)
        if [[ -z "$url_file" ]]; then
            url_file=$(find "$RECON_DIR" -name "all-urls.txt" -type f 2>/dev/null | head -1)
        fi
    fi

    local params_raw="$OUTPUT_DIR/url-params-raw.txt"
    touch "$params_raw"

    if [[ -n "$url_file" && -s "$url_file" ]]; then
        log_info "Processing URLs from: $url_file"

        # Extract parameter names from query strings
        grep -oP '[?&]([a-zA-Z0-9_\-]+)=' "$url_file" 2>/dev/null \
            | sed 's/^[?&]//; s/=$//' \
            | sort -u >> "$params_raw" || true

        # Extract from URL fragments
        grep -oP '#([a-zA-Z0-9_\-]+)=' "$url_file" 2>/dev/null \
            | sed 's/^#//; s/=$//' \
            | sort -u >> "$params_raw" || true

        # Extract path parameters (e.g., /users/{id})
        grep -oP '/\{([a-zA-Z0-9_\-]+)\}' "$url_file" 2>/dev/null \
            | sed 's|^/\{||; s|\}$||' \
            | sort -u >> "$params_raw" || true

        log_ok "URL params: $(wc -l < "$params_raw")"
    else
        log_warn "No URL file available"
    fi
}

# ── Phase 2: Extract from JS Files ──
extract_from_js() {
    log_step "PHASE 2 — Extracting Parameters from JavaScript"

    local js_source="$JS_DIR"
    if [[ -z "$js_source" && -n "$JS_ANALYSIS_DIR" ]]; then
        js_source=$(find "$JS_ANALYSIS_DIR" -name "downloaded" -type d 2>/dev/null | head -1)
    fi

    local params_js="$OUTPUT_DIR/js-params-raw.txt"
    touch "$params_js"

    if [[ -z "$js_source" || ! -d "$js_source" ]]; then
        log_warn "No JS directory available"
        return
    fi

    log_info "Mining JS files from: $js_source"

    for jsfile in "$js_source"/*.js; do
        [[ ! -f "$jsfile" ]] && continue

        # Query parameter patterns
        grep -oP '[?&]([a-zA-Z0-9_\-]+)=' "$jsfile" 2>/dev/null \
            | sed 's/^[?&]//; s/=$//' >> "$params_js" || true

        # Object property access patterns
        grep -oP '(?:params|query|body|data|payload|formData|searchParams)\s*[\[.]\s*['\''"]([a-zA-Z0-9_\-]+)['\''"]' "$jsfile" 2>/dev/null \
            | grep -oP '['\''"]([a-zA-Z0-9_\-]+)['\''"]' \
            | tr -d "\"'" >> "$params_js" || true

        # URLSearchParams
        grep -oP 'URLSearchParams.*?(?:append|set|get|has)\s*\(\s*['\''"]([a-zA-Z0-9_\-]+)['\''"]' "$jsfile" 2>/dev/null \
            | grep -oP '['\''"]([a-zA-Z0-9_\-]+)['\''"]' \
            | tr -d "\"'" >> "$params_js" || true

        # FormData append
        grep -oP 'FormData.*?append\s*\(\s*['\''"]([a-zA-Z0-9_\-]+)['\''"]' "$jsfile" 2>/dev/null \
            | grep -oP '['\''"]([a-zA-Z0-9_\-]+)['\''"]' \
            | tr -d "\"'" >> "$params_js" || true

        # Request headers
        grep -oP '['\''"]([Xx][-_][a-zA-Z0-9\-]+)['\''"]' "$jsfile" 2>/dev/null \
            | tr -d "\"'" >> "$params_js" || true

    done

    sort -u "$params_js" -o "$params_js"
    log_ok "JS params: $(wc -l < "$params_js")"
}

# ── Phase 3: Extract from API Responses ──
extract_from_apis() {
    log_step "PHASE 3 — Extracting Parameters from API Responses"

    local params_api="$OUTPUT_DIR/api-params-raw.txt"
    touch "$params_api"

    if [[ -z "$API_DIR" || ! -d "$API_DIR" ]]; then
        log_warn "No API response directory available"
        return
    fi

    log_info "Mining API responses from: $API_DIR"

    # JSON files
    for jsonfile in "$API_DIR"/*.json; do
        [[ ! -f "$jsonfile" ]] && continue
        jq -r '[paths | .[] | select(type == "string")] | unique | .[]' \
            "$jsonfile" 2>/dev/null >> "$params_api" || true
    done

    # XML files
    for xmlfile in "$API_DIR"/*.xml; do
        [[ ! -f "$xmlfile" ]] && continue
        grep -oP '<([a-zA-Z0-9_\-]+)[> /]' "$xmlfile" 2>/dev/null \
            | sed 's/^<//; s/[> /]$//' >> "$params_api" || true
        grep -oP '([a-zA-Z0-9_\-]+)=' "$xmlfile" 2>/dev/null \
            | sed 's/=$//' >> "$params_api" || true
    done

    sort -u "$params_api" -o "$params_api"
    log_ok "API params: $(wc -l < "$params_api")"
}

# ── Phase 4: Categorize by Risk ──
categorize_params() {
    log_step "PHASE 4 — Risk Categorization"

    # Merge all params
    local all_params="$OUTPUT_DIR/params-all-raw.txt"
    cat "$OUTPUT_DIR"/*-params-raw.txt 2>/dev/null \
        | tr '[:upper:]' '[:lower:]' \
        | sort -u > "$all_params" || true

    if [[ ! -s "$all_params" ]]; then
        log_warn "No parameters found to categorize"
        return
    fi

    local total
    total=$(wc -l < "$all_params")
    log_info "Categorizing $total unique parameters..."

    local crit="$OUTPUT_DIR/params-critical.txt"
    local high="$OUTPUT_DIR/params-high.txt"
    local med="$OUTPUT_DIR/params-medium.txt"
    local low="$OUTPUT_DIR/params-low.txt"
    local unknown="$OUTPUT_DIR/params-uncategorized.txt"
    touch "$crit" "$high" "$med" "$low" "$unknown"

    while IFS= read -r param; do
        [[ -z "$param" ]] && continue

        if echo "$param" | grep -qiP "^${CRITICAL_PARAMS}$" 2>/dev/null; then
            echo "$param" >> "$crit"
        elif echo "$param" | grep -qiP "^${HIGH_PARAMS}$" 2>/dev/null; then
            echo "$param" >> "$high"
        elif echo "$param" | grep -qiP "^${MEDIUM_PARAMS}$" 2>/dev/null; then
            echo "$param" >> "$med"
        elif echo "$param" | grep -qiP "^${LOW_PARAMS}$" 2>/dev/null; then
            echo "$param" >> "$low"
        else
            echo "$param" >> "$unknown"
        fi
    done < "$all_params"

    # Generate JSON summary
    local json_out="$OUTPUT_DIR/params-all.json"
    {
        echo "{"
        echo "  \"meta\": {"
        echo "    \"date\": \"$(date -Iseconds)\","
        echo "    \"total\": $total"
        echo "  },"

        echo "  \"critical\": ["
        if [[ -s "$crit" ]]; then
            sed 's/.*/"&"/' "$crit" | paste -sd',' | sed 's/,/, /g'
        fi
        echo "  ],"

        echo "  \"high\": ["
        if [[ -s "$high" ]]; then
            sed 's/.*/"&"/' "$high" | paste -sd',' | sed 's/,/, /g'
        fi
        echo "  ],"

        echo "  \"medium\": ["
        if [[ -s "$med" ]]; then
            sed 's/.*/"&"/' "$med" | paste -sd',' | sed 's/,/, /g'
        fi
        echo "  ],"

        echo "  \"low\": ["
        if [[ -s "$low" ]]; then
            sed 's/.*/"&"/' "$low" | paste -sd',' | sed 's/,/, /g'
        fi
        echo "  ],"

        echo "  \"uncategorized\": ["
        if [[ -s "$unknown" ]]; then
            sed 's/.*/"&"/' "$unknown" | paste -sd',' | sed 's/,/, /g'
        fi
        echo "  ]"
        echo "}"
    } > "$json_out"

    echo ""
    echo -e "  ${RED}${BOLD}CRITICAL${NC}       $(wc -l < "$crit") params"
    echo -e "  ${YELLOW}${BOLD}HIGH${NC}           $(wc -l < "$high") params"
    echo -e "  ${CYAN}${BOLD}MEDIUM${NC}         $(wc -l < "$med") params"
    echo -e "  ${GREEN}${BOLD}LOW${NC}            $(wc -l < "$low") params"
    echo -e "  ${MAGENTA}${BOLD}UNCATEGORIZED${NC}  $(wc -l < "$unknown") params"
}

# ── Summary Report ──
generate_report() {
    log_step "GENERATING REPORT"
    local report="$OUTPUT_DIR/param-miner-report.md"

    cat > "$report" <<-REPORT
# Parameter Mining Report
**Date:** $(date '+%Y-%m-%d %H:%M:%S %Z')
**Toolkit:** z3r0-toolkit v1.0

---

## Risk Breakdown
| Risk Level    | Count | File |
|--------------|-------|------|
| 🔴 CRITICAL  | $(wc -l < "$OUTPUT_DIR/params-critical.txt" 2>/dev/null || echo 0) | params-critical.txt |
| 🟠 HIGH      | $(wc -l < "$OUTPUT_DIR/params-high.txt" 2>/dev/null || echo 0) | params-high.txt |
| 🟡 MEDIUM    | $(wc -l < "$OUTPUT_DIR/params-medium.txt" 2>/dev/null || echo 0) | params-medium.txt |
| 🟢 LOW       | $(wc -l < "$OUTPUT_DIR/params-low.txt" 2>/dev/null || echo 0) | params-low.txt |
| ⚪ UNCAT     | $(wc -l < "$OUTPUT_DIR/params-uncategorized.txt" 2>/dev/null || echo 0) | params-uncategorized.txt |

## Critical Parameters Found
\`\`\`
$(cat "$OUTPUT_DIR/params-critical.txt" 2>/dev/null || echo "None")
\`\`\`

## High Risk Parameters Found
\`\`\`
$(cat "$OUTPUT_DIR/params-high.txt" 2>/dev/null || echo "None")
\`\`\`

---
*Full JSON: \`params-all.json\`*
REPORT

    log_ok "Report: ${BOLD}$report${NC}"
}

# ── Main ──
main() {
    banner
    parse_args "$@"
    setup_output

    local start_time=$SECONDS
    extract_from_urls
    extract_from_js
    extract_from_apis
    categorize_params
    generate_report

    local elapsed=$(( SECONDS - start_time ))
    echo ""
    log_ok "Parameter mining completed in ${BOLD}${elapsed}s${NC}"
    log_ok "Results: ${BOLD}$OUTPUT_DIR${NC}"
}

main "$@"
