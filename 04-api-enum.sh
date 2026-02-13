#!/usr/bin/env bash
# Copyright (c) 2026 z3r0_ru135
###############################################################################
# 04-api-enum.sh — API Endpoint Discovery & Auth Analysis
# Discovers versioned APIs, detects auth logic, flags missing authorization
# Part of z3r0-toolkit
###############################################################################
set -euo pipefail

# ── Colors ──
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; MAGENTA='\033[0;35m'; BOLD='\033[1m'; NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORDLISTS_CONF="$SCRIPT_DIR/config/wordlists.conf"

# ── Banner ──
banner() {
    echo -e "${MAGENTA}${BOLD}"
    echo "╔══════════════════════════════════════════════════════════╗"
    echo "║           z3r0-toolkit • 04 API ENUMERATION             ║"
    echo "╚══════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# ── Logging ──
log_info()  { echo -e "${CYAN}[INFO]${NC}  $*"; }
log_ok()    { echo -e "${GREEN}[OK]${NC}    $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
log_err()   { echo -e "${RED}[ERR]${NC}   $*"; }
log_step()  { echo -e "\n${BOLD}${MAGENTA}━━━ $* ━━━${NC}\n"; }
safe_count() { if [[ -f "$1" ]]; then wc -l < "$1"; else echo 0; fi; }

# ── Defaults ──
THREADS=20
TIMEOUT=10
OUTPUT_DIR="./api-enum-output"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
AUTH_HEADER=""
CUSTOM_WORDLIST=""

# ── Built-in API Paths ──
API_PATHS=(
    "api" "api/v1" "api/v2" "api/v3" "api/v4"
    "rest" "rest/v1" "rest/v2"
    "graphql" "graphiql" "playground"
    "swagger" "swagger.json" "swagger/v1/swagger.json" "swagger-ui" "swagger-ui.html"
    "openapi" "openapi.json" "openapi.yaml"
    "api-docs" "api/docs" "docs/api" "redoc"
    "api/health" "api/status" "api/ping" "api/info" "api/version"
    "api/config" "api/settings" "api/env" "api/debug"
    "api/users" "api/user" "api/me" "api/profile" "api/account"
    "api/admin" "api/admin/users" "api/admin/settings"
    "api/login" "api/auth" "api/authenticate" "api/signin"
    "api/token" "api/oauth" "api/oauth/token" "api/oauth/authorize"
    "api/register" "api/signup"
    "api/password" "api/reset" "api/forgot"
    "api/upload" "api/files" "api/media" "api/assets"
    "api/search" "api/query"
    "api/export" "api/import" "api/backup"
    "api/webhook" "api/webhooks" "api/callback"
    "api/keys" "api/apikeys" "api/credentials"
    "api/internal" "api/private" "api/debug"
    "api/test" "api/dev" "api/staging"
    "api/proxy" "api/gateway"
    "api/graphql" "api/gql"
    "api/v1/users" "api/v1/admin" "api/v1/auth" "api/v1/login"
    "api/v2/users" "api/v2/admin" "api/v2/auth" "api/v2/login"
    "api/v3/users" "api/v3/admin" "api/v3/auth" "api/v3/login"
    "_api" "v1" "v2" "v3"
    ".well-known/openid-configuration"
    "actuator" "actuator/health" "actuator/env" "actuator/info"
    "metrics" "healthz" "readyz"
    "wp-json" "wp-json/wp/v2" "wp-json/wp/v2/users"
    "jsonapi" "xmlrpc.php"
)

# ── Usage ──
usage() {
    cat <<EOF
${BOLD}Usage:${NC} $0 -t <target> [OPTIONS]

${BOLD}Required:${NC}
  -t, --target <url>          Target base URL (e.g., https://example.com)

${BOLD}Options:${NC}
  -l, --list <file>           File with base URLs (one per line)
  -w, --wordlist <file>       Custom API path wordlist
  -a, --auth <header>         Auth header value (e.g., "Bearer <token>")
  -c, --concurrency <n>       Concurrent requests (default: 20)
      --timeout <s>           Request timeout in seconds (default: 10)
  -o, --output <dir>          Output directory (default: ./api-enum-output)
      --methods               Test multiple HTTP methods (GET, POST, PUT, DELETE)
      --versions <range>      Version range to test (default: 1-5)
      --resume <dir>          Resume from existing output dir (skip completed phases)
  -h, --help                  Show this help
EOF
    exit 0
}

# ── Parse Args ──
TARGET=""
TARGET_LIST=""
TEST_METHODS=false
VERSION_MAX=5
RESUME_DIR=""

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -t|--target)      TARGET="$2"; shift 2;;
            -l|--list)        TARGET_LIST="$2"; shift 2;;
            -w|--wordlist)    CUSTOM_WORDLIST="$2"; shift 2;;
            -a|--auth)        AUTH_HEADER="$2"; shift 2;;
            -c|--concurrency) THREADS="$2"; shift 2;;
            --timeout)        TIMEOUT="$2"; shift 2;;
            -o|--output)      OUTPUT_DIR="$2"; shift 2;;
            --methods)        TEST_METHODS=true; shift;;
            --versions)       VERSION_MAX="$2"; shift 2;;
            --resume)         RESUME_DIR="$2"; shift 2;;
            -h|--help)        usage;;
            *)                log_err "Unknown option: $1"; usage;;
        esac
    done

    if [[ -z "$TARGET" && -z "$TARGET_LIST" && -z "$RESUME_DIR" ]]; then
        log_err "Target is required. Use -t <url> or -l <file>"
        exit 1
    fi
}

# ── Setup ──
setup_output() {
    if [[ -n "$RESUME_DIR" ]]; then
        OUTPUT_DIR="$RESUME_DIR"
        log_info "Resuming from: ${BOLD}$OUTPUT_DIR${NC}"
    else
        OUTPUT_DIR="${OUTPUT_DIR}/${TIMESTAMP}"
    fi
    mkdir -p "$OUTPUT_DIR"/{discovery,auth,report}
    log_info "Output: ${BOLD}$OUTPUT_DIR${NC}"
}

# ── Build Targets List ──
build_targets() {
    local targets_file="$OUTPUT_DIR/targets.txt"
    touch "$targets_file"

    if [[ -n "$TARGET" ]]; then
        # Strip trailing slash
        echo "${TARGET%/}" >> "$targets_file"
    fi

    if [[ -n "$TARGET_LIST" && -s "$TARGET_LIST" ]]; then
        while IFS= read -r url; do
            [[ -z "$url" || "$url" =~ ^# ]] && continue
            echo "${url%/}" >> "$targets_file"
        done < "$TARGET_LIST"
    fi

    sort -u "$targets_file" -o "$targets_file"
    log_info "Targets: $(wc -l < "$targets_file")"
}

# ── Probe Endpoint ──
probe_endpoint() {
    local url="$1"
    local method="${2:-GET}"

    local curl_opts=(
        -s -o /dev/null
        -w '%{http_code}|%{size_download}|%{time_total}|%{redirect_url}'
        --connect-timeout "$TIMEOUT"
        --max-time "$((TIMEOUT * 2))"
        -X "$method"
        -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        -H "Accept: application/json, text/html, */*"
    )

    if [[ -n "$AUTH_HEADER" ]]; then
        curl_opts+=(-H "Authorization: $AUTH_HEADER")
    fi

    local result
    result=$(curl "${curl_opts[@]}" "$url" 2>/dev/null) || echo "000|0|0|"
    echo "$result"
}

# ── Phase 1: API Discovery ──
phase_discovery() {
    log_step "PHASE 1 — API Endpoint Discovery"

    local targets_file="$OUTPUT_DIR/targets.txt"

    # Skip if already completed (resume mode)
    if [[ -n "$RESUME_DIR" && -s "$OUTPUT_DIR/discovery/raw-results.txt" ]]; then
        log_info "Discovery already completed, skipping (resume mode)"
        log_ok "Existing endpoints: $(wc -l < "$OUTPUT_DIR/discovery/all-endpoints.txt" 2>/dev/null || echo 0)"
        return
    fi
    local discovered="$OUTPUT_DIR/discovery/all-endpoints.txt"
    local discovered_json="$OUTPUT_DIR/discovery/api-endpoints.json"
    touch "$discovered"
    echo "[]" > "$discovered_json"

    # Load custom wordlist if provided
    local extra_paths=()
    if [[ -n "$CUSTOM_WORDLIST" && -s "$CUSTOM_WORDLIST" ]]; then
        while IFS= read -r path; do
            [[ -z "$path" || "$path" =~ ^# ]] && continue
            extra_paths+=("$path")
        done < "$CUSTOM_WORDLIST"
        log_info "Loaded ${#extra_paths[@]} paths from custom wordlist"
    fi

    local all_paths=("${API_PATHS[@]}" ${extra_paths[@]+"${extra_paths[@]}"})
    local total_paths=${#all_paths[@]}

    while IFS= read -r base_url; do
        log_info "Scanning: ${BOLD}$base_url${NC} (${total_paths} paths)"

        local count=0
        local found=0
        local pids=()

        for path in "${all_paths[@]}"; do
            count=$((count + 1))
            local full_url="${base_url}/${path}"

            # Run in background with controlled concurrency
            (
                local result
                result=$(probe_endpoint "$full_url" "GET")
                local code size timing redirect
                IFS='|' read -r code size timing redirect <<< "$result"

                # Interesting responses: 200, 201, 204, 301, 302, 401, 403, 405
                if [[ "$code" =~ ^(200|201|204|301|302|401|403|405|500)$ ]]; then
                    echo "$code|$size|$timing|$full_url|$redirect" \
                        >> "$OUTPUT_DIR/discovery/raw-results.txt"
                fi
            ) &
            pids+=($!)

            # Throttle
            if (( ${#pids[@]} >= THREADS )); then
                wait "${pids[@]}" 2>/dev/null || true
                pids=()
                printf "\r  Progress: %d/%d paths" "$count" "$total_paths"
            fi
        done

        wait "${pids[@]}" 2>/dev/null || true
        echo ""

    done < "$targets_file"

    # Process raw results
    if [[ -s "$OUTPUT_DIR/discovery/raw-results.txt" ]]; then
        sort -t'|' -k1,1n -u "$OUTPUT_DIR/discovery/raw-results.txt" -o "$OUTPUT_DIR/discovery/raw-results.txt"

        # Categorize
        while IFS='|' read -r code size timing url redirect; do
            echo "[$code] (${size}B, ${timing}s) $url" >> "$discovered"

            case "$code" in
                200|201|204)
                    echo "$url" >> "$OUTPUT_DIR/discovery/accessible-200.txt"
                    ;;
                401)
                    echo "$url" >> "$OUTPUT_DIR/discovery/requires-auth-401.txt"
                    ;;
                403)
                    echo "$url" >> "$OUTPUT_DIR/discovery/forbidden-403.txt"
                    ;;
                405)
                    echo "$url" >> "$OUTPUT_DIR/discovery/method-not-allowed-405.txt"
                    ;;
                301|302)
                    echo "$url -> $redirect" >> "$OUTPUT_DIR/discovery/redirects-3xx.txt"
                    ;;
                500)
                    echo "$url" >> "$OUTPUT_DIR/discovery/server-error-500.txt"
                    ;;
            esac
        done < "$OUTPUT_DIR/discovery/raw-results.txt"

        log_ok "Discovered: ${BOLD}$(wc -l < "$discovered")${NC} endpoints"
        log_info "  200 OK:       $(wc -l < "$OUTPUT_DIR/discovery/accessible-200.txt" 2>/dev/null || echo 0)"
        log_info "  401 Auth:     $(wc -l < "$OUTPUT_DIR/discovery/requires-auth-401.txt" 2>/dev/null || echo 0)"
        log_info "  403 Forbidden:$(wc -l < "$OUTPUT_DIR/discovery/forbidden-403.txt" 2>/dev/null || echo 0)"
        log_info "  405 Method:   $(wc -l < "$OUTPUT_DIR/discovery/method-not-allowed-405.txt" 2>/dev/null || echo 0)"
    else
        log_warn "No endpoints discovered"
    fi
}

# ── Phase 2: Version Detection ──
phase_versions() {
    log_step "PHASE 2 — API Version Discovery"

    local targets_file="$OUTPUT_DIR/targets.txt"
    local versions_file="$OUTPUT_DIR/discovery/versions.txt"

    # Skip if already completed (resume mode)
    if [[ -n "$RESUME_DIR" && -s "$versions_file" ]]; then
        log_info "Version scan already completed, skipping (resume mode)"
        log_ok "Existing versions: $(wc -l < "$versions_file")"
        return
    fi

    touch "$versions_file"

    local version_prefixes=("api/v" "rest/v" "v")
    local common_resources=("" "users" "status" "health" "docs" "auth" "login")

    while IFS= read -r base_url; do
        log_info "Version scan: $base_url"

        local pids=()
        local count=0
        local total=$(( ${#version_prefixes[@]} * VERSION_MAX * ${#common_resources[@]} ))

        for prefix in "${version_prefixes[@]}"; do
            for v in $(seq 1 "$VERSION_MAX"); do
                for resource in "${common_resources[@]}"; do
                    count=$((count + 1))
                    local path="${prefix}${v}"
                    [[ -n "$resource" ]] && path="${path}/${resource}"
                    local full_url="${base_url}/${path}"

                    (
                        local result
                        result=$(probe_endpoint "$full_url" "GET")
                        local code
                        IFS='|' read -r code _ _ _ <<< "$result"

                        if [[ "$code" =~ ^(200|201|204|301|302|401|403)$ ]]; then
                            echo "[$code] ${prefix}${v} => $full_url" >> "$versions_file"
                        fi
                    ) &
                    pids+=($!)

                    # Throttle concurrency
                    if (( ${#pids[@]} >= THREADS )); then
                        wait "${pids[@]}" 2>/dev/null || true
                        pids=()
                        printf "\r  Progress: %d/%d versions" "$count" "$total"
                    fi
                done
            done
        done

        wait "${pids[@]}" 2>/dev/null || true
        echo ""
    done < "$targets_file"

    if [[ -s "$versions_file" ]]; then
        sort -u "$versions_file" -o "$versions_file"
        log_ok "API versions found: ${BOLD}$(wc -l < "$versions_file")${NC}"
        cat "$versions_file" | head -20
    else
        log_warn "No versioned APIs detected"
    fi
}

# ── Phase 3: Auth Analysis ──
phase_auth_analysis() {
    log_step "PHASE 3 — Authentication & Authorization Analysis"

    local accessible="$OUTPUT_DIR/discovery/accessible-200.txt"
    local auth_report="$OUTPUT_DIR/auth/auth-analysis.txt"
    local unauth="$OUTPUT_DIR/auth/unauth-endpoints.txt"
    touch "$auth_report" "$unauth"

    if [[ ! -s "$accessible" ]]; then
        log_warn "No accessible endpoints to analyze"
        return
    fi

    log_info "Analyzing auth on $(wc -l < "$accessible") accessible endpoints..."

    while IFS= read -r url; do
        [[ -z "$url" ]] && continue

        # Test without auth header
        local no_auth_result
        no_auth_result=$(curl -s -o /dev/null -w '%{http_code}' \
            --connect-timeout "$TIMEOUT" --max-time "$((TIMEOUT * 2))" \
            -H "User-Agent: Mozilla/5.0" \
            "$url" 2>/dev/null) || no_auth_result="000"

        # Test with invalid auth
        local bad_auth_result
        bad_auth_result=$(curl -s -o /dev/null -w '%{http_code}' \
            --connect-timeout "$TIMEOUT" --max-time "$((TIMEOUT * 2))" \
            -H "User-Agent: Mozilla/5.0" \
            -H "Authorization: Bearer invalidtoken123" \
            "$url" 2>/dev/null) || bad_auth_result="000"

        # Detect auth mechanism from response headers
        local resp_headers
        resp_headers=$(curl -sI --connect-timeout "$TIMEOUT" --max-time "$((TIMEOUT * 2))" \
            -H "User-Agent: Mozilla/5.0" \
            "$url" 2>/dev/null) || resp_headers=""

        local auth_type="UNKNOWN"
        if echo "$resp_headers" | grep -qi 'www-authenticate.*bearer'; then
            auth_type="Bearer/OAuth"
        elif echo "$resp_headers" | grep -qi 'www-authenticate.*basic'; then
            auth_type="Basic Auth"
        elif echo "$resp_headers" | grep -qi 'x-api-key\|api-key'; then
            auth_type="API Key"
        elif echo "$resp_headers" | grep -qi 'set-cookie.*session'; then
            auth_type="Session Cookie"
        fi

        # Determine authorization status
        local auth_status="PROTECTED"
        local flag=""

        if [[ "$no_auth_result" =~ ^(200|201|204)$ ]]; then
            # Accessible without any auth
            if echo "$url" | grep -qiE '(health|status|ping|docs|swagger|openapi|public|version|info)'; then
                auth_status="PUBLIC (expected)"
                flag=""
            else
                auth_status="⚠ NO AUTH REQUIRED"
                flag="FLAGGED"
                echo "$url" >> "$unauth"
            fi
        elif [[ "$bad_auth_result" =~ ^(200|201|204)$ ]]; then
            auth_status="⚠ ACCEPTS INVALID TOKEN"
            flag="FLAGGED"
            echo "$url" >> "$unauth"
        fi

        echo "$auth_status | Auth: $auth_type | NoAuth: $no_auth_result | BadAuth: $bad_auth_result | $url" >> "$auth_report"

    done < "$accessible"

    if [[ -s "$unauth" ]]; then
        sort -u "$unauth" -o "$unauth"
        log_warn "Unprotected endpoints: ${BOLD}$(wc -l < "$unauth")${NC}"
    else
        log_ok "All tested endpoints appear to require auth"
    fi

    log_ok "Auth analysis: ${BOLD}$(wc -l < "$auth_report")${NC} endpoints analyzed"
}

# ── Phase 4: HTTP Method Testing ──
phase_methods() {
    if [[ "$TEST_METHODS" != true ]]; then
        return
    fi

    log_step "PHASE 4 — HTTP Method Testing"

    local accessible="$OUTPUT_DIR/discovery/accessible-200.txt"
    local methods_report="$OUTPUT_DIR/auth/methods-analysis.txt"
    touch "$methods_report"

    local methods=("GET" "POST" "PUT" "PATCH" "DELETE" "OPTIONS" "HEAD")

    if [[ ! -s "$accessible" ]]; then
        log_warn "No endpoints for method testing"
        return
    fi

    while IFS= read -r url; do
        [[ -z "$url" ]] && continue
        local method_results=""

        for method in "${methods[@]}"; do
            local result
            result=$(probe_endpoint "$url" "$method")
            local code
            IFS='|' read -r code _ _ _ <<< "$result"
            method_results="${method_results}${method}:${code} "
        done

        echo "$url | $method_results" >> "$methods_report"
    done < "$accessible"

    log_ok "Method analysis: ${BOLD}$(wc -l < "$methods_report")${NC} endpoints"
}

# ── Report ──
generate_report() {
    log_step "GENERATING REPORT"
    local report="$OUTPUT_DIR/report/api-enum-report.md"

    cat > "$report" <<-REPORT
# API Enumeration Report
**Date:** $(date '+%Y-%m-%d %H:%M:%S %Z')
**Toolkit:** z3r0-toolkit v1.0
**Target:** ${TARGET:-"Multiple targets"}

---

## Discovery Summary
| Category | Count |
|----------|-------|
| Total discovered | $(safe_count "$OUTPUT_DIR/discovery/all-endpoints.txt") |
| Accessible (200) | $(safe_count "$OUTPUT_DIR/discovery/accessible-200.txt") |
| Auth Required (401) | $(safe_count "$OUTPUT_DIR/discovery/requires-auth-401.txt") |
| Forbidden (403) | $(safe_count "$OUTPUT_DIR/discovery/forbidden-403.txt") |
| Method Not Allowed (405) | $(safe_count "$OUTPUT_DIR/discovery/method-not-allowed-405.txt") |
| Redirects (3xx) | $(safe_count "$OUTPUT_DIR/discovery/redirects-3xx.txt") |
| Server Errors (500) | $(safe_count "$OUTPUT_DIR/discovery/server-error-500.txt") |

## API Versions Detected
\`\`\`
$(cat "$OUTPUT_DIR/discovery/versions.txt" 2>/dev/null || echo "None detected")
\`\`\`

## ⚠ Unprotected Endpoints (Missing Authorization)
\`\`\`
$(cat "$OUTPUT_DIR/auth/unauth-endpoints.txt" 2>/dev/null || echo "None found — all endpoints appear protected")
\`\`\`

## Auth Analysis
\`\`\`
$(head -30 "$OUTPUT_DIR/auth/auth-analysis.txt" 2>/dev/null || echo "No data")
\`\`\`

---
*Full results in \`discovery/\` and \`auth/\` directories*
REPORT

    log_ok "Report: ${BOLD}$report${NC}"
}

# ── Main ──
main() {
    banner
    parse_args "$@"
    setup_output
    build_targets

    local start_time=$SECONDS
    phase_discovery
    phase_versions
    phase_auth_analysis
    phase_methods
    generate_report

    local elapsed=$(( SECONDS - start_time ))
    echo ""
    log_ok "API enumeration completed in ${BOLD}${elapsed}s${NC}"
    log_ok "Results: ${BOLD}$OUTPUT_DIR${NC}"
}

main "$@"
