"""
SentinelAPI - Production CI/CD Gatekeeper & CLI Security Runner
Executes automated API security audits and enforces CI/CD build gates.

Exit Codes:
  0 = Passed (no blocking findings)
  1 = Failed (critical/high security finding detected exceeding threshold)
  2 = Scanner / Network / Configuration Error
"""

import sys
import argparse
import requests
import json
import time

from backend.scanner_engine import APISecurityAuditor

# ANSI Color codes for clean terminal output
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"


def print_banner():
    print(f"\n{CYAN}{BOLD}================================================================={RESET}")
    print(f"{CYAN}{BOLD}           SENTINEL-API : OPENAPI SECURITY TEST SUITE             {RESET}")
    print(f"{CYAN}{BOLD}          CI/CD GATEKEEPER & DIFFERENTIAL BOLA AUDITOR            {RESET}")
    print(f"{CYAN}{BOLD}================================================================={RESET}\n")


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="SentinelAPI - Dynamic OpenAPI Security Testing & CI/CD Gatekeeper",
        add_help=True
    )
    parser.add_argument("target_url", nargs="?", default="http://127.0.0.1:8001", help="Target API Base URL")
    parser.add_argument("--spec-url", default=None, help="Custom OpenAPI JSON/YAML URL (default: <target>/openapi.json)")
    parser.add_argument(
        "--fail-on",
        choices=["critical", "high", "medium", "any", "none"],
        default="high",
        help="Failure threshold for non-zero exit code (default: high)"
    )
    parser.add_argument("--json", action="store_true", help="Output machine-readable JSON result only")
    parser.add_argument("--timeout", type=float, default=3.5, help="HTTP request timeout in seconds (default: 3.5)")
    return parser.parse_args()


def main():
    args = parse_arguments()
    target_url = args.target_url.rstrip("/")
    spec_url = args.spec_url or f"{target_url}/openapi.json"

    if not args.json:
        print_banner()
        print(f"[*] Target Base URL: {BOLD}{target_url}{RESET}")
        print(f"[*] Ingesting OpenAPI Specification from {spec_url} ...")

    # Fetch OpenAPI Spec
    try:
        r = requests.get(spec_url, timeout=5)
        if r.status_code != 200:
            if args.json:
                print(json.dumps({"error": f"Failed to fetch specification from {spec_url}", "status_code": r.status_code}))
            else:
                print(f"{RED}[-] Failed to load openapi.json (HTTP {r.status_code}){RESET}")
            sys.exit(2)
        spec = r.json()
    except Exception as e:
        if args.json:
            print(json.dumps({"error": str(e), "target_url": target_url}))
        else:
            print(f"{RED}[-] Error connecting to target API: {e}{RESET}")
        sys.exit(2)

    title = spec.get("info", {}).get("title", "Target API")
    version = spec.get("info", {}).get("version", "1.0.0")

    if not args.json:
        print(f"{GREEN}[+] Loaded Spec: {title} (v{version}){RESET}")
        print(f"[*] Dispatching Differential Quad-Probe Authorization Engine...\n")

    # Run in-process auditor
    try:
        auditor = APISecurityAuditor(target_base_url=target_url, openapi_spec=spec, timeout=args.timeout)
        data = auditor.run_audit()
    except Exception as e:
        if args.json:
            print(json.dumps({"error": f"Scanner runtime error: {e}"}))
        else:
            print(f"{RED}[-] Scanner runtime error: {e}{RESET}")
        sys.exit(2)

    if args.json:
        print(json.dumps(data, indent=2))
    else:
        summary = data.get("summary", {})
        findings = data.get("findings", [])
        duration = summary.get("duration_seconds", summary.get("duration", 0.0))
        score = summary.get("score", 0)
        grade = summary.get("grade", "F")
        counts = summary.get("counts", {})

        print(f"{BOLD}--- AUDIT RESULTS ---{RESET}")
        print(f"Endpoints Scanned: {summary.get('endpoints_tested', 0)} in {duration}s")
        score_color = RED if score < 50 else (YELLOW if score < 80 else GREEN)
        print(f"Overall Score:     {score_color}{BOLD}{score} / 100 (Grade {grade}){RESET}")
        print(
            f"Total Issues:      {BOLD}{len(findings)}{RESET} "
            f"(Critical: {counts.get('CRITICAL', 0)}, High: {counts.get('HIGH', 0)}, Medium: {counts.get('MEDIUM', 0)})\n"
        )

        if findings:
            print(f"{BOLD}{'SEVERITY':<12} {'METHOD':<8} {'ENDPOINT':<38} {'FINDING'}{RESET}")
            print("-" * 80)
            for f in findings:
                sev = f.get('severity', 'LOW')
                color = RED if sev == "CRITICAL" else (YELLOW if sev == "HIGH" else BLUE)
                print(f"{color}{BOLD}{sev:<12}{RESET} {f.get('method', 'GET'):<8} {f.get('endpoint', ''):<38} {f.get('title', '')[:40]}")

        print("\n" + "=" * 80)
        print(f"{GREEN}[+] Full Web Dashboard: http://127.0.0.1:8000{RESET}")
        print("=" * 80 + "\n")

    # Evaluate CI Gatekeeper Threshold
    counts = data.get("summary", {}).get("counts", {})
    criticals = counts.get("CRITICAL", 0)
    highs = counts.get("HIGH", 0)
    mediums = counts.get("MEDIUM", 0)
    total = len(data.get("findings", []))

    fail = False
    if args.fail_on == "critical" and criticals > 0:
        fail = True
    elif args.fail_on == "high" and (criticals > 0 or highs > 0):
        fail = True
    elif args.fail_on == "medium" and (criticals > 0 or highs > 0 or mediums > 0):
        fail = True
    elif args.fail_on == "any" and total > 0:
        fail = True

    if fail:
        if not args.json:
            print(f"{RED}{BOLD}[!] CI/CD GATEKEEPER TRIGGERED: Build FAILED due to policy threshold violation ({args.fail_on}).{RESET}\n")
        sys.exit(1)
    else:
        if not args.json:
            print(f"{GREEN}{BOLD}[PASS] CI/CD GATEKEEPER: Build PASSED. All security constraints satisfied.{RESET}\n")
        sys.exit(0)


if __name__ == "__main__":
    main()
