#!/usr/init/env python3
import sys
import json
import urllib.request
import urllib.error
import ssl
import time
import socket

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
RESET = "\033[0m"

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
    type_text(G + "       [+] Advanced Website Flaw Finder & Remediator" + RESET, 0.005)
    type_text(Y + "       [+] Universal Domain, Subdomain & IP Support" + RESET, 0.005)
    type_text(C + "       " + "═" * 63 + RESET + "\n", 0.002)

def audit_target(url):
    url = url.strip()
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url

    type_text(f"\n{Y}[*]{W} Connecting to target: {C}{url}{RESET}", 0.01)
    
    findings = []
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'WebMax-Auditor/2.0'})
        
        # Unverified SSL context to ensure custom/preview domains work
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        type_text(f"{GRAY}[~] Sending request and awaiting response...{RESET}", 0.005)
        
        with urllib.request.urlopen(req, context=context, timeout=5) as res:
            headers = dict(res.headers)
            final_url = res.url
            type_text(f"{G}[+]{W} Connection established! Status Code: {G}{res.status}{RESET}", 0.01)

            if not final_url.startswith("https://"):
                findings.append({
                    "flaw": "Insecure HTTP Protocol",
                    "sev": "HIGH",
                    "desc": "Data transmitted in cleartext, exposing it to man-in-the-middle sniffing.",
                    "fix": "Force HTTPS redirection and enable HSTS across your domain configuration."
                })

            if "Strict-Transport-Security" not in headers:
                findings.append({
                    "flaw": "Missing HSTS Header",
                    "sev": "MEDIUM",
                    "desc": "Browser does not enforce secure connections on subsequent visits.",
                    "fix": "Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains"
                })

            if "Content-Security-Policy" not in headers:
                findings.append({
                    "flaw": "Missing Content Security Policy (CSP)",
                    "sev": "HIGH",
                    "desc": "No script restriction policy, making the app vulnerable to XSS injection.",
                    "fix": "Implement a robust CSP header (e.g., Content-Security-Policy: default-src 'self')."
                })

            if "X-Frame-Options" not in headers:
                findings.append({
                    "flaw": "Missing X-Frame-Options Header",
                    "sev": "MEDIUM",
                    "desc": "Website can be embedded in an iframe, allowing clickjacking attacks.",
                    "fix": "Add header: X-Frame-Options: DENY or SAMEORIGIN"
                })

            if "Server" in headers:
                findings.append({
                    "flaw": "Server Version Disclosure",
                    "sev": "LOW",
                    "desc": f"Reveals backend server details: {headers['Server']}",
                    "fix": "Hide or remove the Server response header in your web server configuration."
                })

    except urllib.error.HTTPError as e:
        type_text(f"{Y}[!]{W} Target returned HTTP Error Code: {Y}{e.code}{RESET} (Note: Protected/Auth walls may block scans)", 0.01)
        return
    except socket.timeout:
        type_text(f"{R}[!]{W} Connection timed out. The server took too long or blocked the request.{RESET}", 0.01)
        return
    except Exception as e:
        type_text(f"{R}[!]{W} Connection failed: {e}{RESET}", 0.01)
        return

    type_text(f"\n{C}" + "="*65, 0.002)
    type_text(f"                 WEB-MAX AUDIT & REMEDIATION REPORT                ", 0.005)
    type_text("="*65 + RESET, 0.002)

    if not findings:
        type_text(f"\n{G}[+]{W} No critical header vulnerabilities found! Clean security posture.\n", 0.01)
    else:
        type_text(f"\n{R}[!]{W} Total Vulnerabilities Detected: {R}{len(findings)}{RESET}\n", 0.01)
        for i, f_item in enumerate(findings, 1):
            sev_col = R if f_item["sev"] == "HIGH" else (Y if f_item["sev"] == "MEDIUM" else B)
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
            type_text(f"\n{B}[Info]{W} Web-Max is an advanced web security auditing tool built to scan", 0.01)
            type_text(f"       any target URL or domain for missing headers, protocol flaws,", 0.01)
            type_text(f"       and configuration errors, providing instant developer remediation fixes.{RESET}", 0.01)
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