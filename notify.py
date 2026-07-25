#!/usr/bin/env python3
"""
FSR Recon — Discord notifier (stdlib only, no pip deps).

Sends:
  1. Main embed with all counts (+ new-subdomain preview, + nuclei preview)
  2. FINAL_REPORT.txt attached as a file (if present and < 8 MB)
  3. A red @here alert if nuclei found exposures

Never crashes the workflow: any failure prints a warning and exits 0.
"""
import argparse
import json
import os
import sys
import uuid
import urllib.request

UA = "FSR-Bot/2.0"
MAX_FILE = 8 * 1024 * 1024  # Discord free-tier upload limit


def _req(url, data, headers, timeout=25):
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status in (200, 204)
    except Exception as e:
        print(f"[!] Discord POST failed: {e}")
        return False


def post_json(url, payload):
    return _req(
        url,
        json.dumps(payload).encode("utf-8"),
        {"Content-Type": "application/json", "User-Agent": UA},
    )


def post_with_file(url, payload, filepath):
    """multipart/form-data: payload_json + files[0]"""
    boundary = uuid.uuid4().hex
    filename = os.path.basename(filepath)
    with open(filepath, "rb") as f:
        filedata = f.read()

    body = b"".join([
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="payload_json"\r\n'
        f"Content-Type: application/json\r\n\r\n".encode(),
        json.dumps(payload).encode("utf-8") + b"\r\n",
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="files[0]"; filename="{filename}"\r\n'
        f"Content-Type: text/plain\r\n\r\n".encode(),
        filedata + b"\r\n",
        f"--{boundary}--\r\n".encode(),
    ])
    return _req(
        url, body,
        {"Content-Type": f"multipart/form-data; boundary={boundary}", "User-Agent": UA},
        timeout=40,
    )


def read_count(filepath):
    try:
        with open(filepath, "r", errors="ignore") as f:
            return sum(1 for line in f if line.strip())
    except Exception:
        return 0


def read_grep_count(filepath, needle):
    """Count lines containing a substring (e.g. real WAF detections only)."""
    try:
        with open(filepath, "r", errors="ignore") as f:
            return sum(1 for line in f if needle in line)
    except Exception:
        return 0


def read_lines(filepath, limit=10):
    try:
        with open(filepath, "r", errors="ignore") as f:
            return [l.strip() for l in f if l.strip()][:limit]
    except Exception:
        return []


def clip(text, n=1000):
    return text if len(text) <= n else text[: n - 3] + "..."


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--webhook", required=True)
    p.add_argument("--target", required=True)
    p.add_argument("--output", required=True)
    p.add_argument("--run-url", required=True)
    p.add_argument("--status", required=True)
    p.add_argument("--report", default=None)
    args = p.parse_args()

    if not args.webhook.startswith("http"):
        print("[!] Invalid webhook URL — skipping notification")
        return

    out = args.output

    subs = read_count(f"{out}/02_subdomains/ALL_SUBDOMAINS.txt")
    live = read_count(f"{out}/03_live/ALL_LIVE.txt")
    params = read_count(f"{out}/05_params/ALL_PARAMS.txt")
    js_files = read_count(f"{out}/06_files/js/all_js.txt")
    dirs = read_count(f"{out}/06_files/interesting_dirs.txt")
    waf = read_grep_count(f"{out}/07_fingerprint/waf.txt", "is behind")
    tech = read_count(f"{out}/07_fingerprint/nuclei_tech.txt")
    exposures = read_count(f"{out}/07_fingerprint/nuclei_exposures.txt")

    # ── diff against previous run ──
    new_subs_list = []
    old_path = "last_subs.txt"
    cur_path = f"{out}/02_subdomains/ALL_SUBDOMAINS.txt"
    if os.path.exists(old_path) and os.path.exists(cur_path):
        with open(old_path, errors="ignore") as f:
            old = {l.strip() for l in f if l.strip()}
        with open(cur_path, errors="ignore") as f:
            cur = {l.strip() for l in f if l.strip()}
        new_subs_list = sorted(cur - old)
    new_subs = len(new_subs_list)

    color = {"success": 0x2ECC71, "failure": 0xE74C3C, "cancelled": 0xF39C12}.get(
        args.status.lower(), 0x5865F2
    )

    content = None
    if new_subs > 0:
        content = f"🚨 @everyone **{new_subs}** new subdomain(s) on `{args.target}`!"

    fields = [
        {"name": "📊 Subdomains", "value": f"```{subs}```", "inline": True},
        {"name": "🟢 Live", "value": f"```{live}```", "inline": True},
        {"name": "🔗 Params", "value": f"```{params}```", "inline": True},
        {"name": "📁 JS", "value": f"```{js_files}```", "inline": True},
        {"name": "🚪 Dirs", "value": f"```{dirs}```", "inline": True},
        {"name": "🛡️ WAF", "value": f"```{waf}```", "inline": True},
        {"name": "🔍 Tech", "value": f"```{tech}```", "inline": True},
        {"name": "✨ New subs", "value": f"```{new_subs}```", "inline": True},
        {"name": "⚠️ Exposures", "value": f"```{exposures}```", "inline": True},
    ]

    if new_subs_list:
        fields.append({
            "name": "🆕 New subdomains (preview)",
            "value": clip("```\n" + "\n".join(new_subs_list[:10]) + "\n```"),
            "inline": False,
        })

    exp_preview = read_lines(f"{out}/07_fingerprint/nuclei_exposures.txt", 5)
    if exp_preview:
        fields.append({
            "name": "⚠️ Exposures (preview)",
            "value": clip("```\n" + "\n".join(exp_preview) + "\n```"),
            "inline": False,
        })

    fields.append({
        "name": "📥 Full results",
        "value": f"[Open run & artifacts]({args.run_url})",
        "inline": False,
    })

    embed = {
        "title": f"🎯 Recon: {args.target}",
        "url": args.run_url,
        "color": color,
        "footer": {
            "text": f"Status: {args.status.upper()} | Run #{os.environ.get('GITHUB_RUN_NUMBER', 'N/A')}"
        },
        "fields": fields,
    }

    payload = {
        "username": "FSR Recon Bot",
        "content": content,
        "embeds": [embed],
    }

    # attach the report file if we have one and it fits
    sent = False
    if args.report and os.path.isfile(args.report) and os.path.getsize(args.report) < MAX_FILE:
        sent = post_with_file(args.webhook, payload, args.report)
    if not sent:
        sent = post_json(args.webhook, payload)
    print("[+] Main notification sent" if sent else "[-] Main notification failed")

    # separate red alert for exposures
    if exposures > 0:
        post_json(args.webhook, {
            "username": "FSR Alert",
            "content": f"🚨 @here **{exposures}** exposure(s) found on `{args.target}` — check artifacts!",
        })


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"[!] Fatal error in notify.py: {e}")
    sys.exit(0)
