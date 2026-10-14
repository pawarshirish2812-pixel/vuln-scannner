import argparse


def parse_args():
    parser = argparse.ArgumentParser(
        description="Simple CLI Vulnerability Scanner"
    )
    parser.add_argument(
        "-t", "--target",
        required=True,
        help="Target host or IP (e.g. scanme.nmap.org)"
    )
    parser.add_argument(
        "-p", "--ports",
        default="1-1024",
        help="Port range to scan, e.g. 1-1024"
    )
    parser.add_argument(
        "-o", "--output",
        default="report.json",
        help="Output file name (.json or .csv)"
    )
    return parser.parse_args()


def main():
    args = parse_args()
    print(f"[*] Target : {args.target}")
    print(f"[*] Ports  : {args.ports}")
    print(f"[*] Output : {args.output}")


if __name__ == "__main__":
    main()