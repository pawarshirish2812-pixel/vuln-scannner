import re
import requests # type: ignore

SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
WEB_PORTS = (80, 443, 8080, 8443)

# Risky ports ka knowledge base
RISKY_PORTS = {
    21: {
        "name": "FTP Service Exposed",
        "severity": "High",
        "description": "FTP sends credentials and data in plain text, "
                       "so an attacker on the network can sniff them.",
        "mitigation": "Disable FTP and use SFTP/FTPS. Restrict access "
                      "with a firewall.",
    },
    23: {
        "name": "Telnet Service Exposed",
        "severity": "Critical",
        "description": "Telnet is an unencrypted remote login protocol. "
                       "Passwords and commands can be intercepted easily.",
        "mitigation": "Disable Telnet and use SSH instead.",
    },
    110: {
        "name": "POP3 Unencrypted Mail Service",
        "severity": "Medium",
        "description": "POP3 transmits email credentials in plain text.",
        "mitigation": "Use POP3S (port 995) or disable POP3.",
    },
    143: {
        "name": "IMAP Unencrypted Mail Service",
        "severity": "Medium",
        "description": "IMAP transmits email credentials in plain text.",
        "mitigation": "Use IMAPS (port 993) or disable IMAP.",
    },
    445: {
        "name": "SMB Service Exposed",
        "severity": "High",
        "description": "SMB exposed to the network is a common target "
                       "for ransomware and worms (e.g. EternalBlue).",
        "mitigation": "Block port 445 at the firewall and patch the system.",
    },
    3306: {
        "name": "MySQL Database Exposed",
        "severity": "High",
        "description": "A database port reachable from outside allows "
                       "brute-force and exploitation attempts.",
        "mitigation": "Bind MySQL to localhost or restrict access "
                      "using firewall rules.",
    },
    3389: {
        "name": "RDP Service Exposed",
        "severity": "High",
        "description": "Exposed Remote Desktop is a frequent target of "
                       "brute-force attacks and ransomware.",
        "mitigation": "Place RDP behind a VPN, enable NLA and use "
                      "strong passwords with MFA.",
    },
}

# Security headers jo hone chahiye
HEADER_CHECKS = [
    ("Content-Security-Policy", "Missing Content-Security-Policy Header",
     "Medium",
     "Without CSP, the browser has no rules limiting scripts, "
     "making Cross-Site Scripting (XSS) attacks easier.",
     "Add a Content-Security-Policy header restricting trusted "
     "script and resource sources."),
    ("X-Frame-Options", "Missing X-Frame-Options Header",
     "Medium",
     "The page can be embedded in an iframe on another site, "
     "enabling clickjacking attacks.",
     "Add 'X-Frame-Options: DENY' or 'SAMEORIGIN'."),
    ("X-Content-Type-Options", "Missing X-Content-Type-Options Header",
     "Low",
     "Browsers may MIME-sniff responses and execute files "
     "as a different type than intended.",
     "Add 'X-Content-Type-Options: nosniff'."),
    ("Strict-Transport-Security", "Missing HSTS Header",
     "Medium",
     "Browsers are not forced to use HTTPS, which allows "
     "downgrade and man-in-the-middle attacks.",
     "Add 'Strict-Transport-Security: max-age=31536000; "
     "includeSubDomains'."),
]


def make_finding(name, severity, port, description, mitigation):
    return {
        "name": name,
        "severity": severity,
        "port": port,
        "description": description,
        "mitigation": mitigation,
    }


def check_risky_ports(open_ports):
    """Open ports ko RISKY_PORTS list se match karta hai."""
    findings = []
    for r in open_ports:
        info = RISKY_PORTS.get(r["port"])
        if info:
            findings.append(make_finding(
                info["name"], info["severity"], r["port"],
                info["description"], info["mitigation"]))
    return findings


def check_banners(open_ports):
    """Banner mein purane software versions dhundhta hai."""
    findings = []
    for r in open_ports:
        banner = r["banner"]

        m = re.search(r"OpenSSH_(\d+)\.", banner)
        if m and int(m.group(1)) < 7:
            findings.append(make_finding(
                "Outdated OpenSSH Version", "Medium", r["port"],
                f"Detected an old OpenSSH version ({banner[:60]}) "
                "with publicly known vulnerabilities.",
                "Upgrade OpenSSH to the latest stable version."))

        if "vsFTPd 2.3.4" in banner:
            findings.append(make_finding(
                "vsFTPd 2.3.4 Backdoor", "Critical", r["port"],
                "vsFTPd 2.3.4 contains a known backdoor allowing "
                "remote command execution.",
                "Remove this version immediately and install a "
                "trusted, updated FTP server."))
    return findings


def check_http_headers(target, port):
    """Web server ke security headers check karta hai."""
    scheme = "https" if port in (443, 8443) else "http"
    default_port = (80, 443)
    url = f"{scheme}://{target}" + ("" if port in default_port else f":{port}")

    try:
        resp = requests.get(url, timeout=5,
                            headers={"User-Agent": "SimpleVulnScanner/1.0"})
    except requests.RequestException:
        print(f"[!] HTTP check fail hua: {url}")
        return []

    findings = []
    for header, name, severity, desc, fix in HEADER_CHECKS:
        # HSTS sirf HTTPS pe relevant hai
        if header == "Strict-Transport-Security" and scheme != "https":
            continue
        if header not in resp.headers:
            findings.append(make_finding(name, severity, port, desc, fix))

    # Server header se version leak
    server = resp.headers.get("Server", "")
    if re.search(r"\d", server):
        findings.append(make_finding(
            "Server Version Disclosure", "Low", port,
            f"The Server header reveals software details: '{server}'. "
            "Attackers can use this to find matching exploits.",
            "Hide or genericize the Server header in the web server config."))

    if re.search(r"Apache/2\.[0-2]\.", server):
        findings.append(make_finding(
            "Outdated Apache Version", "Medium", port,
            f"The server runs an old Apache version ({server}) "
            "that no longer receives security updates.",
            "Upgrade to the latest Apache 2.4.x release."))

    return findings


def sort_findings(findings):
    """Critical se Low tak sort karta hai."""
    return sorted(findings, key=lambda f: SEVERITY_ORDER.get(f["severity"], 9))