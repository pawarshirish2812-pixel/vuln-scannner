import argparse
import socket
from concurrent.futures import ThreadPoolExecutor
from vulns import (check_risky_ports, check_banners,
                   check_http_headers, sort_findings, WEB_PORTS)
from report import build_report, save_report

# Common ports ke naam
COMMON_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    3306: "MySQL", 3389: "RDP", 8080: "HTTP-Alt",
}


def parse_args():
    parser = argparse.ArgumentParser(
        description="Simple CLI Vulnerability Scanner"
    )
    parser.add_argument("-t", "--target", required=True,
                        help="Target host or IP (e.g. scanme.nmap.org)")
    parser.add_argument("-p", "--ports", default="1-1024",
                        help="Ports: range (1-1024) ya list (22,80,443)")
    parser.add_argument("-o", "--output", default="report.json",
                        help="Output file name (.json or .csv)")
    return parser.parse_args()


def parse_ports(port_str):
    """'1-100' ya '22,80,443' ko list of ints mein badalta hai."""
    ports = []
    for part in port_str.split(","):
        if "-" in part:
            start, end = part.split("-")
            ports.extend(range(int(start), int(end) + 1))
        else:
            ports.append(int(part))
    # sirf valid ports rakho (1 se 65535)
    return [p for p in ports if 1 <= p <= 65535]


def scan_port(target_ip, port, timeout=1):
    """Ek port check karta hai. Open ho to dict wapas deta hai, warna None."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        if s.connect_ex((target_ip, port)) != 0:
            s.close()
            return None

        # Port open hai, ab banner grab karne ki koshish
        banner = ""
        try:
            if port in (80, 8080):
                s.send(b"HEAD / HTTP/1.0\r\n\r\n")
            s.settimeout(2)
            banner = s.recv(1024).decode(errors="ignore").strip()
        except Exception:
            pass
        s.close()

        return {
            "port": port,
            "service": COMMON_SERVICES.get(port, "unknown"),
            "banner": banner.split("\n")[0][:100],  # pehli line, max 100 chars
        }
    except Exception:
        return None


def scan_ports(target_ip, ports):
    """Saare ports ko 100 threads se ek saath scan karta hai."""
    with ThreadPoolExecutor(max_workers=100) as executor:
        results = executor.map(lambda p: scan_port(target_ip, p), ports)
    return sorted([r for r in results if r], key=lambda r: r["port"])


import argparse
import socket
from concurrent.futures import ThreadPoolExecutor

from vulns import (check_risky_ports, check_banners,
                   check_http_headers, sort_findings, WEB_PORTS)

# Common ports ke naam
COMMON_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    3306: "MySQL", 3389: "RDP", 8080: "HTTP-Alt",
}


def parse_args():
    parser = argparse.ArgumentParser(
        description="Simple CLI Vulnerability Scanner"
    )
    parser.add_argument("-t", "--target", required=True,
                        help="Target host or IP (e.g. scanme.nmap.org)")
    parser.add_argument("-p", "--ports", default="1-1024",
                        help="Ports: range (1-1024) ya list (22,80,443)")
    parser.add_argument("-o", "--output", default="report.json",
                        help="Output file name (.json or .csv)")
    return parser.parse_args()


def parse_ports(port_str):
    """'1-100' ya '22,80,443' ko list of ints mein badalta hai."""
    ports = []
    for part in port_str.split(","):
        if "-" in part:
            start, end = part.split("-")
            ports.extend(range(int(start), int(end) + 1))
        else:
            ports.append(int(part))
    return [p for p in ports if 1 <= p <= 65535]


def scan_port(target_ip, port, timeout=1):
    """Ek port check karta hai. Open ho to dict wapas deta hai, warna None."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        if s.connect_ex((target_ip, port)) != 0:
            s.close()
            return None

        banner = ""
        try:
            if port in (80, 8080):
                s.send(b"HEAD / HTTP/1.0\r\n\r\n")
            s.settimeout(2)
            banner = s.recv(1024).decode(errors="ignore").strip()
        except Exception:
            pass
        s.close()

        return {
            "port": port,
            "service": COMMON_SERVICES.get(port, "unknown"),
            "banner": banner.split("\n")[0][:100],
        }
    except Exception:
        return None


def scan_ports(target_ip, ports):
    """Saare ports ko 100 threads se ek saath scan karta hai."""
    with ThreadPoolExecutor(max_workers=100) as executor:
        results = executor.map(lambda p: scan_port(target_ip, p), ports)
    return sorted([r for r in results if r], key=lambda r: r["port"])


def main():
    args = parse_args()

    # Output file ka format pehle hi check kar lo
    if not args.output.lower().endswith((".json", ".csv")):
        print("[!] Output file .json ya .csv honi chahiye")
        return

    try:
        target_ip = socket.gethostbyname(args.target)
    except socket.gaierror:
        print(f"[!] Target resolve nahi hua: {args.target}")
        return

    ports = parse_ports(args.ports)
    print(f"[*] Target : {args.target} ({target_ip})")
    print(f"[*] Ports  : {args.ports} ({len(ports)} ports)")
    print("[*] Scanning shuru...\n")

    open_ports = scan_ports(target_ip, ports)

    if open_ports:
        print(f"{'PORT':<8}{'SERVICE':<12}BANNER")
        print("-" * 50)
        for r in open_ports:
            print(f"{r['port']:<8}{r['service']:<12}{r['banner']}")
    print(f"\n[+] Total open ports: {len(open_ports)}")

    # Vulnerability analysis
    print("\n[*] Vulnerabilities analyse ho rahi hain...\n")
    findings = []
    findings += check_risky_ports(open_ports)
    findings += check_banners(open_ports)
    for r in open_ports:
        if r["port"] in WEB_PORTS:
            findings += check_http_headers(args.target, r["port"])
    findings = sort_findings(findings)

    for i, f in enumerate(findings, 1):
        print(f"[{i}] {f['name']}  (Port {f['port']})")
        print(f"    Severity   : {f['severity']}")
        print(f"    Description: {f['description']}")
        print(f"    Mitigation : {f['mitigation']}\n")
    print(f"[+] Total findings: {len(findings)}")

    # Report save karo
    report = build_report(args.target, target_ip, open_ports, findings)
    save_report(args.output, report)
    print(f"[+] Report saved: {args.output}")

if __name__ == "__main__":
    main()