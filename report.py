import csv
import json
import os
from datetime import datetime


def build_report(target, target_ip, open_ports, findings):
    """Poora scan result ek dictionary mein pack karta hai."""
    return {
        "target": target,
        "target_ip": target_ip,
        "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "open_ports": open_ports,
        "total_findings": len(findings),
        "findings": findings,
    }


def save_report(path, report):
    """File ke extension ke hisaab se JSON ya CSV mein save karta hai."""
    ext = os.path.splitext(path)[1].lower()

    if ext == ".json":
        with open(path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=4)

    elif ext == ".csv":
        fields = ["Target", "Scan Time", "Vulnerability Name", "Severity",
                  "Port", "Description", "Recommended Mitigation"]
        with open(path, "w", newline="", encoding="utf-8-sig") as f:
            writer = csv.writer(f)
            writer.writerow(fields)
            for item in report["findings"]:
                writer.writerow([
                    report["target"], report["scan_time"],
                    item["name"], item["severity"], item["port"],
                    item["description"], item["mitigation"],
                ])
    else:
        raise ValueError("Output file .json ya .csv hona chahiye")