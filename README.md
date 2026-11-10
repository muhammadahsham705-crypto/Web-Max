**Web-Max (v2.0)🛡️**

Web-Max is a terminal-based web security auditing and remediation tool built in Python. Unlike basic tools that only verify whether a header exists, Web-Max performs deep semantic validation to inspect exact header values (such as verifying HSTS `max-age` thresholds or checking CSP for `unsafe-inline` directives).
**________________________________________________________________________________________________________________________________________**

**✨ What's New in v2.0:**

**Exact Semantic Inspection:**                                                                                                                         
Checks header values, not just presence.

**Weighted Scoring System:**                                                                                                                       
Automatically calculates safety margins based on risk impact.

**Critical Severity Penalty Caps:**                                                                                                                
Enforces strict score caps when critical security vectors are exposed.

**Direct Flaw Reporting:**                                                                                                                         
Clean terminal output displaying specific vulnerabilities and actionable developer solutions without cluttered UI elements.
**________________________________________________________________________________________________________________________________________**

**🚀 Installation & Usage:**

**1. Fresh Clone (New Installation):**

*To download and run Web-Max for the first time:*
```bash
# Clone the repository
git clone https://github.com/your-username/Web-Max.git

# Navigate into the project directory
cd Web-Max

# Run Web-Max
python3 Web-Max.py
```
**________________________________________________________________________________________________________________________________________**

**2. Updating an Existing Installation:**

If you already cloned Web-Max previously, update to the latest version by pulling the latest changes:
```bash
# Navigate to your Web-Max folder
cd Web-Max

# Pull the latest code update
git pull

# Run the updated tool
python3 Web-Max.py
```
**________________________________________________________________________________________________________________________________________**

**📜 License:**
**This project is released under the MIT License. Free to use and audit**
