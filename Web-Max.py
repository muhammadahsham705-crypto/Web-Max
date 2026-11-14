#!/usr/bin/env python3
import sys
import json
import urllib.request
import urllib.error
import ssl
import time
import socket
import re

# Force a global socket timeout so requests never hang indefinitely
socket.setdefaulttimeout(5)

# ====================================
# Terminal Colors
# ====================================
R = "\033[31m" # Red
G = "\033[32m" # Green
Y = "\033[33m" # Yellow
B = "\033[34m" # Blue
M = "\033[35m" # Magenta
C = "\033[36m" # Cyan
W = "\033[37m" # White
GRAY = "\033[90m"
BOLD = "\033[1m"
RESET = "\033[0m"

# ====================================
# Exact Security Header Validation Rules
# ====================================
SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "severity": "CRITICAL",
        "weight": 3,
        "desc": "Enforces secure HTTPS transport.",
        "validator": lambda val: "max-age=" in val and int(re.search(r'max-age=(\d+)', val).group(1)) >= 31536000 if re.search(r'max-age=(\d+)', val) else False,
        "fail_reason": "Missing, disabled, or max-age < 1 year.",
        "fix": "Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains"
    },
    "Content-Security-Policy": {
        "severity": "CRITICAL",
        "weight": 3,
        "desc": "Mitigates Cross-Site Scripting (XSS) and injection vectors.",
        "validator": lambda val: "unsafe-inline" not in val and "unsafe-eval" not in val and "*" not in val,
        "fail_reason": "Insecure config (contains unsafe-inline/eval/wildcard).",
        "fix": "Implement a robust CSP header (e.g., Content-Security-Policy: default-src 'self')."
    },
    "X-Frame-Options": {
        "severity": "HIGH",
        "weight": 2,
        "desc": "Protects against UI redress / clickjacking.",
        "validator": lambda val: val.upper() in ["DENY", "SAMEORIGIN"],
        "fail_reason": "Value is not strictly DENY or SAMEORIGIN.",
        "fix": "Add header: X-Frame-Options: DENY or SAMEORIGIN"
    },
    "X-Content-Type-Options": {
        "severity": "HIGH",
        "weight": 2,
        "desc": "Prevents MIME-type sniffing exploits.",
        "validator": lambda val: "nosniff" in val.lower(),
        "fail_reason": "Does not enforce 'nosniff'.",
        "fix": "Add header: X-Content-Type-Options: nosniff"
    },
    "Referrer-Policy": {
        "severity": "MEDIUM",
        "weight": 1,
        "desc": "Controls sensitive URL leakages in HTTP referrers.",
        "validator": lambda val: any(p in val.lower() for p in ["no-referrer", "strict-origin", "same-origin"]),
        "fail_reason": "Permits excessive parameter leakage.",
        "fix": "Set Referrer-Policy: strict-origin-when-cross-origin"
    },
    "Permissions-Policy": {
        "severity": "MEDIUM",
        "weight": 1,
        "desc": "Restricts sensitive browser API access (camera, mic, geo).",
        "validator": lambda val: len(val.strip()) > 0 and "=" in val,
        "fail_reason": "Unconfigured or invalid policy string.",
        "fix": "Define explicit Permissions-Policy (e.g., camera=(), microphone=())."
    }
}

def type_text(text, delay=0.008):
    """Prints text with a smooth typing animation effect."""
    for char in text:
        print(char, end="", flush=True)
        time.sleep(delay)
    print()

# ====================================
# Dedicated Web-Max Banner
# ====================================
BANNER = f"""{C}
 ██╗    ██╗███████╗██████╗         ███╗   ███╗ █████╗ ██╗  ██╗
 ██║    ██║██╔════╝██╔══██╗        ████╗ ████║██╔══██╗╚██╗██╔╝
 ██║ █╗ ██║█████╗  ██████╔╝█████╗  ██╔████╔██║███████║ ╚███╔╝ 
 ██║███╗██║██╔══╝  ██╔══██╗╚════╝  ██║╚██╔╝██║██╔══██║ ██╔██╗ 
 ╚███╔███╔╝███████╗██████╔╝        ██║ ╚═╝ ██║██║  ██║██╔╝ ██╗
  ╚══╝╚══╝ ╚══════╝╚═════╝         ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝{RESET}"""

def banner():
    print(BANNER)
    type_text(G + "       [+] Advanced Website Flaw Finder & Remediator (Exact Edition)" + RESET, 0.005)
    type_text(Y + "       [+] Universal Domain, Subdomain & IP Support" + RESET, 0.005)
    type_text(C + "       " + "═" * 63 + RESET + "\n", 0.002)

def audit_target(url):
    url = url.strip()
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url

    type_text(f"\n{Y}[*]{W} Connecting to target: {C}{url}{RESET}", 0.01)
    
    findings = []
    earned_points = 0
    total_points = sum(meta["weight"] for meta in SECURITY_HEADERS.values())
    critical_count = 0
    passed_count = 0

    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'WebMax-Auditor/2.0'})
        
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        type_text(f"{GRAY}[~] Sending request and awaiting exact header analysis...{RESET}", 0.005)
        
        with urllib.request.urlopen(req, context=context, timeout=5) as res:
            headers = {k.title(): v for k, v in res.headers.items()}
            final_url = res.url
            status_code = res.status
            type_text(f"{G}[+]{W} Connection established! Status Code: {G}{status_code}{RESET}", 0.01)

            # Check HTTP protocol
            if not final_url.startswith("https://"):
                critical_count += 1
                findings.append({
                    "flaw": "Insecure HTTP Protocol",
                    "sev": "CRITICAL",
                    "desc": "Data transmitted in cleartext over unencrypted HTTP.",
                    "fix": "Force HTTPS redirection and enable HSTS across your domain configuration."
                })

            # Rigorous header inspection loop
            for header, meta in SECURITY_HEADERS.items():
                if header in headers:
                    val = headers[header]
                    try:
                        is_secure = meta["validator"](val)
                    except Exception:
                        is_secure = False

                    if is_secure:
                        earned_points += meta["weight"]
                        passed_count += 1
                    else:
                        if meta["severity"] == "CRITICAL":
                            critical_count += 1
                        
                        # Shorten long values cleanly
                        val_snippet = (val[:35] + '...') if len(val) > 35 else val
                        findings.append({
                            "flaw": f"Insecure Value: {header}",
                            "sev": meta["severity"],
                            "desc": f"{meta['fail_reason']} Value: [{val_snippet}]",
                            "fix": meta["fix"]
                        })
                else:
                    if meta["severity"] == "CRITICAL":
                        critical_count += 1
                    findings.append({
                        "flaw": f"Missing Header: {header}",
                        "sev": meta["severity"],
                        "desc": meta["desc"],
                        "fix": meta["fix"]
                    })

            # Check Server Version Disclosure
            if "Server" in headers:
                server_val = (headers['Server'][:30] + '...') if len(headers['Server']) > 30 else headers['Server']
                findings.append({
                    "flaw": "Server Version Disclosure",
                    "sev": "LOW",
                    "desc": f"Reveals backend server details: {server_val}",
                    "fix": "Hide or remove the Server response header in your web server configuration."
                })

    except urllib.error.HTTPError as e:
        type_text(f"{Y}[!]{W} Target returned HTTP Error Code: {Y}{e.code}{RESET}", 0.01)
        return
    except socket.timeout:
        type_text(f"{R}[!]{W} Connection timed out.{RESET}", 0.01)
        return
    except Exception as e:
        type_text(f"{R}[!]{W} Connection failed: {e}{RESET}", 0.01)
        return

    type_text(f"\n{C}" + "="*65, 0.002)
    type_text(f"             WEB-MAX EXACT AUDIT & REMEDIATION REPORT             ", 0.005)
    type_text("="*65 + RESET, 0.002)

    if not findings:
        type_text(f"\n{G}[+]{W} Zero vulnerabilities found! Flawless security posture.\n", 0.01)
    else:
        type_text(f"\n{R}[!]{W} Total Flaws Detected: {R}{len(findings)}{RESET}\n", 0.01)
        for i, f_item in enumerate(findings, 1):
            sev_col = R if f_item["sev"] == "CRITICAL" else (Y if f_item["sev"] == "HIGH" or f_item["sev"] == "MEDIUM" else B)
            type_text(f"{W}[{i}] Flaw Name : {sev_col}{f_item['flaw']} [{f_item['sev']}]{RESET}", 0.01)
            type_text(f"    {C}Details : {W}{f_item['desc']}{RESET}", 0.008)
            type_text(f"    {G}Solution: {W}{f_item['fix']}{RESET}", 0.008)
            type_text(f"    " + "─" * 58, 0.002)

    type_text(f"\n{Y}[*]{W} Press Enter to return to Web-Max menu...", 0.01)
    input()

def main():
    while True:
        banner()
        type_text(f"{W}  Select an option from the menu:\n{RESET}", 0.01)
        type_text(f"  {C}[{G}01{C}]{W} Start Website Flaw Audit & Remediation", 0.01)
        type_text(f"  {C}[{G}02{C}]{W} About Web-Max Framework", 0.01)
        type_text(f"  {C}[{G}03{C}]{W} Exit Web-Max\n", 0.01)

        choice = input(f"{C}web-max{W} > {RESET}").strip()

        if choice == "1" or choice == "01":
            target = input(f"\n{Y}[?]{W} Enter target (e.g., example.org, site.io): {RESET}").strip()
            if target:
                audit_target(target)
        elif choice == "2" or choice == "02":
            type_text(f"\n{B}[Info]{W} Web-Max is an advanced web security auditing framework built to scan", 0.01)
            type_text(f"       any target URL or domain with exact validation for missing headers,", 0.01)
            type_text(f"       weak configurations, and protocol flaws, providing instant remediation fixes.{RESET}", 0.01)
            type_text(f"\n{Y}[*] Press Enter to continue...{RESET}", 0.01)
            input()
        elif choice == "3" or choice == "03":
            type_text(f"\n{R}[-*]{W} Exiting Web-Max. Stay secure!\n", 0.01)
            sys.exit(0)
        else:
            type_text(f"\n{R}[!]{W} Invalid option selected. Try again.{RESET}", 0.01)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        type_text(f"\n\n{R}[-*]{W} Program interrupted by user. Exiting...{RESET}\n", 0.01)
        sys.exit(0)
