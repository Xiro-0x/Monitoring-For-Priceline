#!/bin/bash
# ============================================================
#  Bug Bounty Recon — MULTI-TARGET & INTIGRITI COMPATIBLE
#  Usage: bash recon.sh "<targets>" <output_dir> [wordlist]
# ============================================================

INPUT="${1:-parool.nl}"
OUTPUT_DIR="${2:-./results}"
WORDLIST="${3:-/usr/share/dirb/wordlists/common.txt}"
MAX_FUZZ_HOSTS="${MAX_FUZZ_HOSTS:-5}"
BBH="${BUG_BOUNTY_HEADER:-}"

mkdir -p "$OUTPUT_DIR"

check_tool() { command -v "$1" >/dev/null 2>&1; }

count_lines() {
    if [ -f "$1" ]; then
        awk 'NF' "$1" 2>/dev/null | wc -l | tr -d ' '
    else
        echo 0
    fi
}

# ── Build the targets list ──
TARGETS_FILE="$OUTPUT_DIR/targets.txt"
if [ -f "$INPUT" ]; then
    cp "$INPUT" "$TARGETS_FILE"
else
    echo "$INPUT" | tr ',' '\n' | \
        sed 's/^ *//; s/ *$//; s|https\?://||; s|/.*||' | \
        grep -v '^$' > "$TARGETS_FILE"
fi
sed -i 's/\r//g; s/\.$//; s/^\.//' "$TARGETS_FILE" 2>/dev/null || true
tr 'A-Z' 'a-z' < "$TARGETS_FILE" | sort -u > "${TARGETS_FILE}.tmp" 2>/dev/null || true
mv "${TARGETS_FILE}.tmp" "$TARGETS_FILE" 2>/dev/null || true

N_TARGETS=$(count_lines "$TARGETS_FILE")
TARGET_LABEL=$(paste -sd, "$TARGETS_FILE" 2>/dev/null || echo "$INPUT")

# Combined regex matching ANY in-scope root: (^|\.)(a\.com|b\.com)$
TRE_ALL=$(sed 's/\./\\./g' "$TARGETS_FILE" 2>/dev/null | paste -sd'|')

# Smart Header Handling (Supports HackerOne & Intigriti)
HDR=()
if [ -n "$BBH" ]; then
    if [[ "$BBH" == *":"* ]]; then
        HDR=(-H "$BBH")
    else
        HDR=(-H "X-Intigriti-Username: $BBH")
    fi
fi

echo "🎯 Targets ($N_TARGETS): $TARGET_LABEL"
[ -n "$BBH" ] && echo "🪪 Header Configured: ${HDR[*]}" || echo "⚠️  No BUG_BOUNTY_HEADER set"
echo "⏰ Started: $(date -u)"

# ───────────────────────── PHASE 1: OSINT ─────────────────────────
echo "[1/7] OSINT..."
mkdir -p "$OUTPUT_DIR/01_osint"
touch "$OUTPUT_DIR/01_osint/ALL_OSINT.txt"

while read -r ROOT; do
    [ -z "$ROOT" ] && continue
    safe=$(echo "$ROOT" | tr '.' '_')
    echo "  └─ OSINT: $ROOT"

    if check_tool theHarvester; then
        timeout 240 theHarvester -d "$ROOT" -b all \
            -f "$OUTPUT_DIR/01_osint/harvester_${safe}" >/dev/null 2>&1 || true
    fi

    curl -s --retry 2 --max-time 60 "https://crt.sh/?q=%25.${ROOT}&output=json" | \
        jq -r '.[].name_value // empty' 2>/dev/null | \
        tr 'A-Z' 'a-z' | tr -d '\r' | sed 's/^\*\.//; s/\.$//' | \
        sort -u > "$OUTPUT_DIR/01_osint/crtsh_${safe}.txt" 2>/dev/null || true
    touch "$OUTPUT_DIR/01_osint/crtsh_${safe}.txt"

    cat > "$OUTPUT_DIR/01_osint/github_dorks_${safe}.txt" << EOF
https://github.com/search?q=%22${ROOT}%22+password&type=code
https://github.com/search?q=%22${ROOT}%22+api_key&type=code
https://github.com/search?q=%22${ROOT}%22+secret&type=code
https://github.com/search?q=%22${ROOT}%22+token&type=code
https://github.com/search?q=%22${ROOT}%22+.env&type=code
EOF
done < "$TARGETS_FILE"

cat "$OUTPUT_DIR/01_osint"/crtsh_*.txt 2>/dev/null | \
    tr 'A-Z' 'a-z' | tr -d '\r' | sed 's/^\*\.//; s/\.$//' | \
    grep -iE "(^|\.)(${TRE_ALL})$" | sort -u > "$OUTPUT_DIR/01_osint/ALL_OSINT.txt" 2>/dev/null || true
touch "$OUTPUT_DIR/01_osint/ALL_OSINT.txt"

# ───────────────────── PHASE 2: Subdomains ────────────────────────
echo "[2/7] Subdomains..."
mkdir -p "$OUTPUT_DIR/02_subdomains"

while read -r ROOT; do
    [ -z "$ROOT" ] && continue
    safe=$(echo "$ROOT" | tr '.' '_')
    echo "  └─ Enumerating: $ROOT"

    echo "$ROOT" > "$OUTPUT_DIR/02_subdomains/${safe}_apex.txt"

    if check_tool subfinder; then
        timeout 420 subfinder -d "$ROOT" -all -silent \
            -o "$OUTPUT_DIR/02_subdomains/${safe}_subfinder.txt" 2>/dev/null || true
    fi
    touch "$OUTPUT_DIR/02_subdomains/${safe}_subfinder.txt"

    if check_tool assetfinder; then
        timeout 240 assetfinder --subs-only "$ROOT" \
            > "$OUTPUT_DIR/02_subdomains/${safe}_assetfinder.txt" 2>/dev/null || true
    fi
    touch "$OUTPUT_DIR/02_subdomains/${safe}_assetfinder.txt"

    if check_tool findomain; then
        timeout 240 findomain -t "$ROOT" -q \
            -u "$OUTPUT_DIR/02_subdomains/${safe}_findomain.txt" 2>/dev/null || true
    fi
    touch "$OUTPUT_DIR/02_subdomains/${safe}_findomain.txt"
done < "$TARGETS_FILE"

# Merge and apply Out-Of-Scope Filtering for Het Parool / DPG Media
cat "$OUTPUT_DIR/02_subdomains"/*.txt "$OUTPUT_DIR/01_osint/ALL_OSINT.txt" 2>/dev/null | \
    tr 'A-Z' 'a-z' | tr -d '\r' | \
    sed 's/^\*\.//; s/\.$//; s/^\.//' | \
    grep -iE "(^|\.)(${TRE_ALL})$" | \
    grep -E '^[a-z0-9._-]+$' | \
    grep -vE "abonnement\.parool\.nl" | \
    sort -u > "$OUTPUT_DIR/02_subdomains/ALL_SUBDOMAINS.txt" 2>/dev/null || true
touch "$OUTPUT_DIR/02_subdomains/ALL_SUBDOMAINS.txt"

TOTAL_SUBS=$(count_lines "$OUTPUT_DIR/02_subdomains/ALL_SUBDOMAINS.txt")
echo "  └─ Subdomains: $TOTAL_SUBS"

# ────────────────────── PHASE 3: Live Check ───────────────────────
echo "[3/7] Live Check..."
mkdir -p "$OUTPUT_DIR/03_live"
touch "$OUTPUT_DIR/03_live/ALL_LIVE.txt" "$OUTPUT_DIR/03_live/httpx_details.txt"

if [ "$TOTAL_SUBS" -gt 0 ] && check_tool httpx; then
    timeout 1200 httpx -l "$OUTPUT_DIR/02_subdomains/ALL_SUBDOMAINS.txt" \
        "${HDR[@]}" \
        -silent -nc -threads 40 -rl 60 -timeout 8 -retries 1 \
        -status-code -title -tech-detect -ip \
        -o "$OUTPUT_DIR/03_live/httpx_details.txt" 2>/dev/null || true

    awk 'NF {print $1}' "$OUTPUT_DIR/03_live/httpx_details.txt" 2>/dev/null | \
        grep -E '^https?://' | sort -u > "$OUTPUT_DIR/03_live/ALL_LIVE.txt" 2>/dev/null || true
fi
touch "$OUTPUT_DIR/03_live/ALL_LIVE.txt"

TOTAL_LIVE=$(count_lines "$OUTPUT_DIR/03_live/ALL_LIVE.txt")
echo "  └─ Live: $TOTAL_LIVE"

sed 's|https\?://||; s|/.*||; s|:.*||' "$OUTPUT_DIR/03_live/ALL_LIVE.txt" 2>/dev/null | \
    sort -u > "$OUTPUT_DIR/03_live/LIVE_DOMAINS.txt" 2>/dev/null || true
touch "$OUTPUT_DIR/03_live/LIVE_DOMAINS.txt"

# ──────────────────── PHASE 4: Classification ─────────────────────
echo "[4/7] Classification..."
mkdir -p "$OUTPUT_DIR/04_classified"
for f in api internal prod mail cdn backup uncategorized _all; do
    touch "$OUTPUT_DIR/04_classified/${f}.txt"
done

if [ "$TOTAL_LIVE" -gt 0 ]; then
    grep -iE "api|graphql|rest|swagger|openapi" "$OUTPUT_DIR/03_live/ALL_LIVE.txt" > "$OUTPUT_DIR/04_classified/api.txt" 2>/dev/null || true
    grep -iE "dev|staging|test|internal|intranet|admin|panel|dashboard|manage|staff" "$OUTPUT_DIR/03_live/ALL_LIVE.txt" > "$OUTPUT_DIR/04_classified/internal.txt" 2>/dev/null || true
    grep -iE "www|app|web|portal|prod|secure|login|account|user|client" "$OUTPUT_DIR/03_live/ALL_LIVE.txt" > "$OUTPUT_DIR/04_classified/prod.txt" 2>/dev/null || true
    grep -iE "mail|email|smtp|pop|imap|webmail|mx|exchange" "$OUTPUT_DIR/03_live/ALL_LIVE.txt" > "$OUTPUT_DIR/04_classified/mail.txt" 2>/dev/null || true
    grep -iE "cdn|static|assets|images|img|css|js|media|files|storage|s3|bucket" "$OUTPUT_DIR/03_live/ALL_LIVE.txt" > "$OUTPUT_DIR/04_classified/cdn.txt" 2>/dev/null || true
    grep -iE "old|backup|bak|archive|legacy|v1|v2|version|temp|tmp|clone|mirror" "$OUTPUT_DIR/03_live/ALL_LIVE.txt" > "$OUTPUT_DIR/04_classified/backup.txt" 2>/dev/null || true

    cat "$OUTPUT_DIR/04_classified"/{api,internal,prod,mail,cdn,backup}.txt 2>/dev/null | sort -u > "$OUTPUT_DIR/04_classified/_all.txt" 2>/dev/null || true
    comm -23 <(sort "$OUTPUT_DIR/03_live/ALL_LIVE.txt" 2>/dev/null) \
             <(sort "$OUTPUT_DIR/04_classified/_all.txt" 2>/dev/null) \
             > "$OUTPUT_DIR/04_classified/uncategorized.txt" 2>/dev/null || true
fi

# ────────────────────── PHASE 5: Parameters ───────────────────────
echo "[5/7] Parameters..."
mkdir -p "$OUTPUT_DIR/05_params"
touch "$OUTPUT_DIR/05_params/wayback.txt" "$OUTPUT_DIR/05_params/gau.txt" \
      "$OUTPUT_DIR/05_params/katana.txt" "$OUTPUT_DIR/05_params/ALL_PARAMS.txt"

if [ "$TOTAL_LIVE" -gt 0 ]; then
    if check_tool waybackurls; then
        cat "$OUTPUT_DIR/03_live/LIVE_DOMAINS.txt" | timeout 900 waybackurls 2>/dev/null | \
            grep -E '[?&]' | sort -u > "$OUTPUT_DIR/05_params/wayback.txt" 2>/dev/null || true
    fi

    if check_tool gau; then
        cat "$OUTPUT_DIR/03_live/LIVE_DOMAINS.txt" | timeout 900 gau --threads 5 2>/dev/null | \
            grep -E '[?&]' | sort -u > "$OUTPUT_DIR/05_params/gau.txt" 2>/dev/null || true
    fi

    if check_tool katana; then
        timeout 900 katana -list "$OUTPUT_DIR/03_live/ALL_LIVE.txt" \
            "${HDR[@]}" \
            -silent -nc -jc -d 2 -c 15 -rl 20 -timeout 10 \
            -o "$OUTPUT_DIR/05_params/katana.txt" 2>/dev/null || true
    fi

    cat "$OUTPUT_DIR/05_params"/{wayback,gau,katana}.txt 2>/dev/null | tr -d '\r' | \
        grep -iE "^https?://([^/]*\.)?(${TRE_ALL})([/:?&#]|$)" | \
        sort -u > "$OUTPUT_DIR/05_params/ALL_PARAMS.txt" 2>/dev/null || true
fi
touch "$OUTPUT_DIR/05_params/ALL_PARAMS.txt"

TOTAL_PARAMS=$(count_lines "$OUTPUT_DIR/05_params/ALL_PARAMS.txt")
echo "  └─ Params: $TOTAL_PARAMS"

# ────────────────────── PHASE 6: Files & JS ───────────────────────
echo "[6/7] Files & JS..."
mkdir -p "$OUTPUT_DIR/06_files/ffuf" "$OUTPUT_DIR/06_files/js" "$OUTPUT_DIR/06_files/gf"
touch "$OUTPUT_DIR/06_files/js/all_js.txt" "$OUTPUT_DIR/06_files/all_files.txt" \
      "$OUTPUT_DIR/06_files/all_dirs.txt" "$OUTPUT_DIR/06_files/interesting_dirs.txt"

if [ "$TOTAL_LIVE" -gt 0 ]; then
    grep -hiE '\.js([?#].*)?$' "$OUTPUT_DIR/05_params"/*.txt 2>/dev/null | \
        sort -u > "$OUTPUT_DIR/06_files/js/all_js.txt" 2>/dev/null || true

    if check_tool subjs; then
        cat "$OUTPUT_DIR/03_live/LIVE_DOMAINS.txt" | timeout 300 subjs 2>/dev/null | \
            sort -u >> "$OUTPUT_DIR/06_files/js/all_js.txt" 2>/dev/null || true
    fi
    grep -iE "^https?://([^/]*\.)?(${TRE_ALL})" "$OUTPUT_DIR/06_files/js/all_js.txt" 2>/dev/null | \
        sort -u -o "$OUTPUT_DIR/06_files/js/all_js.txt" 2>/dev/null || true

    TRIM_LIST="/tmp/bb_wordlist.txt"
    if [ -f "$WORDLIST" ]; then
        head -2500 "$WORDLIST" > "$TRIM_LIST" 2>/dev/null || true
    fi

    if check_tool ffuf && [ -s "$TRIM_LIST" ]; then
        head -"$MAX_FUZZ_HOSTS" "$OUTPUT_DIR/03_live/ALL_LIVE.txt" 2>/dev/null | while read -r url; do
            [ -z "$url" ] && continue
            domain=$(echo "$url" | sed 's|https\?://||; s|/.*||' | tr '.' '_')

            timeout 420 ffuf -u "${url%/}/FUZZ" -w "$TRIM_LIST":FUZZ \
                "${HDR[@]}" \
                -e ".php,.html,.txt,.bak,.json,.env,.zip" \
                -mc 200,204,301,302,307,401,403 \
                -t 20 -rate 30 -timeout 8 -ac -s \
                -o "$OUTPUT_DIR/06_files/ffuf/ffuf_${domain}.json" 2>/dev/null || true

            timeout 420 ffuf -u "${url%/}/FUZZ/" -w "$TRIM_LIST":FUZZ \
                "${HDR[@]}" \
                -mc 200,204,301,302,307,401,403 \
                -t 20 -rate 30 -timeout 8 -ac -s \
                -o "$OUTPUT_DIR/06_files/ffuf/dirs_${domain}.json" 2>/dev/null || true
        done
    else
        echo "  [!] ffuf or wordlist not found, skipping fuzzing"
    fi

    for f in "$OUTPUT_DIR/06_files/ffuf"/ffuf_*.json; do
        if [ -f "$f" ]; then
            jq -r '.results[]?.url // empty' "$f" 2>/dev/null >> "$OUTPUT_DIR/06_files/all_files.txt" || true
        fi
    done

    for f in "$OUTPUT_DIR/06_files/ffuf"/dirs_*.json; do
        if [ -f "$f" ]; then
            jq -r '.results[]?.url // empty' "$f" 2>/dev/null >> "$OUTPUT_DIR/06_files/all_dirs.txt" || true
        fi
    done

    sort -u "$OUTPUT_DIR/06_files/all_files.txt" -o "$OUTPUT_DIR/06_files/all_files.txt" 2>/dev/null || true
    sort -u "$OUTPUT_DIR/06_files/all_dirs.txt" -o "$OUTPUT_DIR/06_files/all_dirs.txt" 2>/dev/null || true

    grep -iE "admin|api|backup|config|debug|env|git|internal|login|test|upload|swagger|actuator|phpmyadmin|\.env|\.git|server-status" \
        "$OUTPUT_DIR/06_files/all_dirs.txt" 2>/dev/null > "$OUTPUT_DIR/06_files/interesting_dirs.txt" || true
fi

TOTAL_JS=$(count_lines "$OUTPUT_DIR/06_files/js/all_js.txt")
TOTAL_DIRS=$(count_lines "$OUTPUT_DIR/06_files/interesting_dirs.txt")
echo "  └─ JS: $TOTAL_JS"
echo "  └─ Interesting Dirs: $TOTAL_DIRS"

if check_tool gf; then
    for pattern in xss sqli ssrf redirect rce lfi ssti; do
        cat "$OUTPUT_DIR/05_params/ALL_PARAMS.txt" 2>/dev/null | gf "$pattern" 2>/dev/null | \
            sort -u > "$OUTPUT_DIR/06_files/gf/${pattern}.txt" 2>/dev/null || true
        touch "$OUTPUT_DIR/06_files/gf/${pattern}.txt"
    done
else
    for pattern in xss sqli ssrf redirect rce lfi ssti; do
        touch "$OUTPUT_DIR/06_files/gf/${pattern}.txt"
    done
fi

# ──────────────────── PHASE 7: Fingerprinting ─────────────────────
echo "[7/7] Fingerprinting..."
mkdir -p "$OUTPUT_DIR/07_fingerprint"
touch "$OUTPUT_DIR/07_fingerprint/waf.txt" "$OUTPUT_DIR/07_fingerprint/nuclei_tech.txt" \
      "$OUTPUT_DIR/07_fingerprint/nuclei_exposures.txt"

if [ "$TOTAL_LIVE" -gt 0 ]; then
    if check_tool wafw00f; then
        head -10 "$OUTPUT_DIR/03_live/ALL_LIVE.txt" 2>/dev/null | while read -r url; do
            [ -z "$url" ] && continue
            timeout 60 wafw00f "$url" 2>/dev/null >> "$OUTPUT_DIR/07_fingerprint/waf.txt" || true
        done
    fi

    if check_tool nuclei; then
        NT="$HOME/nuclei-templates"
        TECH_T="$NT/http/technologies"; [ -d "$TECH_T" ] || TECH_T="$NT/technologies"
        EXP_T="$NT/http/exposures";     [ -d "$EXP_T" ]  || EXP_T="$NT/exposures"

        if [ -d "$TECH_T" ]; then
            timeout 1200 nuclei -l "$OUTPUT_DIR/03_live/ALL_LIVE.txt" \
                "${HDR[@]}" -t "$TECH_T" \
                -silent -nc -rl 20 -c 15 -timeout 5 -retries 1 \
                -o "$OUTPUT_DIR/07_fingerprint/nuclei_tech.txt" 2>/dev/null || true
        else
            timeout 1200 nuclei -l "$OUTPUT_DIR/03_live/ALL_LIVE.txt" \
                "${HDR[@]}" -tags tech \
                -silent -nc -rl 20 -c 15 -timeout 5 -retries 1 \
                -o "$OUTPUT_DIR/07_fingerprint/nuclei_tech.txt" 2>/dev/null || true
        fi

        if [ -d "$EXP_T" ]; then
            timeout 1200 nuclei -l "$OUTPUT_DIR/03_live/ALL_LIVE.txt" \
                "${HDR[@]}" -t "$EXP_T" \
                -severity critical,high,medium \
                -silent -nc -rl 20 -c 15 -timeout 5 -retries 1 \
                -o "$OUTPUT_DIR/07_fingerprint/nuclei_exposures.txt" 2>/dev/null || true
        else
            timeout 1200 nuclei -l "$OUTPUT_DIR/03_live/ALL_LIVE.txt" \
                "${HDR[@]}" -tags exposure,config,token,keys \
                -severity critical,high,medium \
                -silent -nc -rl 20 -c 15 -timeout 5 -retries 1 \
                -o "$OUTPUT_DIR/07_fingerprint/nuclei_exposures.txt" 2>/dev/null || true
        fi
    fi
fi

TOTAL_WAF=$(grep -c "is behind" "$OUTPUT_DIR/07_fingerprint/waf.txt" 2>/dev/null || true)
TOTAL_WAF=${TOTAL_WAF:-0}
echo "  └─ WAF: $TOTAL_WAF"

# ─────────────────────────── REPORT ───────────────────────────────
echo "[+] Generating report..."
cat > "$OUTPUT_DIR/FINAL_REPORT.txt" << EOF
================================================================================
    BUG BOUNTY RECON REPORT
    Targets: $TARGET_LABEL
    Header: ${HDR[*]:-none}
    Time: $(date -u)
================================================================================
[SUMMARY]
- Root domains: $N_TARGETS
- Subdomains: $TOTAL_SUBS
- Live URLs: $TOTAL_LIVE
- Parameters: $TOTAL_PARAMS
- JS Files: $TOTAL_JS
- Interesting Dirs: $TOTAL_DIRS
- WAF Detected: $TOTAL_WAF

[CLASSIFIED]
- API: $(count_lines "$OUTPUT_DIR/04_classified/api.txt")
- Internal: $(count_lines "$OUTPUT_DIR/04_classified/internal.txt")
- Production: $(count_lines "$OUTPUT_DIR/04_classified/prod.txt")
- Mail: $(count_lines "$OUTPUT_DIR/04_classified/mail.txt")
- CDN: $(count_lines "$OUTPUT_DIR/04_classified/cdn.txt")
- Backup: $(count_lines "$OUTPUT_DIR/04_classified/backup.txt")

[GF PATTERNS]
- XSS: $(count_lines "$OUTPUT_DIR/06_files/gf/xss.txt")
- SQLi: $(count_lines "$OUTPUT_DIR/06_files/gf/sqli.txt")
- SSRF: $(count_lines "$OUTPUT_DIR/06_files/gf/ssrf.txt")
- Redirect: $(count_lines "$OUTPUT_DIR/06_files/gf/redirect.txt")
- RCE: $(count_lines "$OUTPUT_DIR/06_files/gf/rce.txt")
- LFI: $(count_lines "$OUTPUT_DIR/06_files/gf/lfi.txt")
- SSTI: $(count_lines "$OUTPUT_DIR/06_files/gf/ssti.txt")

[NUCLEI]
- Tech: $(count_lines "$OUTPUT_DIR/07_fingerprint/nuclei_tech.txt")
- Exposures: $(count_lines "$OUTPUT_DIR/07_fingerprint/nuclei_exposures.txt")
================================================================================
EOF

echo "✅ DONE: $OUTPUT_DIR/FINAL_REPORT.txt"
ls -la "$OUTPUT_DIR" 2>/dev/null || true

exit 0
