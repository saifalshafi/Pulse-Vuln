import argparse
import ipaddress
import threading
import itertools
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore, Style, init

from scanner_app.core.port_scanner import PortScanner
from scanner_app.core.host_discovery import HostDiscovery
from scanner_app.intelligence.cve_mapper import CVEMapper
from scanner_app.intelligence.risk_engine import RiskEngine
from scanner_app.checks.misconfig_engine import MisconfigurationEngine
from scanner_app.reporting.report_generator import generate_json

init(autoreset=True)

BANNER = f"""{Fore.CYAN}
██████╗ ██╗   ██╗██╗     ███████╗███████╗
██╔══██╗██║   ██║██║     ██╔════╝██╔════╝
██████╔╝██║   ██║██║     █████╗  ███████╗
██╔═══╝ ██║   ██║██║     ██╔══╝  ╚════██║
██║     ╚██████╔╝███████╗███████╗███████║
╚═╝      ╚═════╝ ╚══════╝╚══════╝╚══════╝
{Style.RESET_ALL}
"""

spinner_running = False


# ==========================================================
# Animated Loading
# ==========================================================

def animated_loading():
    spinner = itertools.cycle(["|", "/", "-", "\\"])
    while spinner_running:
        print(
            f"\r{Fore.CYAN}Scanning network... {next(spinner)}{Style.RESET_ALL}",
            end="",
            flush=True
        )
        time.sleep(0.1)


# ==========================================================
# Target Parsing
# ==========================================================

def parse_targets(target):
    try:
        network = ipaddress.ip_network(target, strict=False)
        return [str(ip) for ip in network.hosts()]
    except:
        return [target]


# ==========================================================
# Scan Host
# ==========================================================

def scan_host(host, full_scan=False):

    if not HostDiscovery.is_alive(host):
        return host, None

    open_ports = PortScanner.scan(host, full_scan=full_scan)

    if not open_ports:
        return host, None

    mapper = CVEMapper()
    all_cves = []

    for port, info in open_ports.items():
        version = info.get("version")
        if version:
            found = mapper.search(version)
            if found:
                all_cves.extend(found)

    misconfigs = MisconfigurationEngine.run(host, open_ports.keys())

    return host, {
        "ports": open_ports,
        "cves": all_cves,
        "misconfigurations": misconfigs
    }


# ==========================================================
# Pretty Output
# ==========================================================

def print_host_results(host, data):

    print(f"\n{Fore.BLUE}[*] Host: {host}{Style.RESET_ALL}")

    for port, info in sorted(data["ports"].items()):
        print(
            f"    {Fore.GREEN}[OPEN]{Style.RESET_ALL} "
            f"Port {str(port).ljust(5)} | {info['service']} "
            f"| {info['version']}"
        )

    if data["misconfigurations"]:
        print(f"\n    {Fore.MAGENTA}Misconfigurations:{Style.RESET_ALL}")
        for issue in data["misconfigurations"]:
            color = Fore.RED if issue["risk"] == "HIGH" else Fore.YELLOW
            print(f"      └─ {color}{issue['title']} ({issue['risk']}){Style.RESET_ALL}")

    if data["cves"]:
        print(f"\n    {Fore.RED}CVEs:{Style.RESET_ALL}")
        for cve in data["cves"]:
            sev_color = (
                Fore.RED if cve["severity"] in ["HIGH", "CRITICAL"]
                else Fore.YELLOW
            )
            print(
                f"      └─ {sev_color}{cve['cve_id']} "
                f"| {cve['severity']} "
                f"| Score: {cve['score']}{Style.RESET_ALL}"
            )


# ==========================================================
# Main
# ==========================================================

def main():

    global spinner_running

    print(BANNER)
    print(f"{Fore.CYAN}PULSE - Enterprise Vulnerability Intelligence Engine{Style.RESET_ALL}")
    print("=" * 70)

    parser = argparse.ArgumentParser(description="PULSE Vulnerability Scanner")
    parser.add_argument("target", help="Target IP or CIDR")
    parser.add_argument("--json", action="store_true", help="Export JSON report")
    parser.add_argument("--full", action="store_true", help="Full 1-65535 port scan")
    args = parser.parse_args()

    targets = parse_targets(args.target)
    results = {}

    print(f"\nStarting Scan on {len(targets)} target(s)...")

    # Start Spinner
    spinner_running = True
    t = threading.Thread(target=animated_loading)
    t.start()

    with ThreadPoolExecutor(max_workers=30) as executor:
        futures = [
            executor.submit(scan_host, target, args.full)
            for target in targets
        ]

        for future in as_completed(futures):
            host, result = future.result()
            if result:
                results[host] = result

    # Stop Spinner
    spinner_running = False
    t.join()
    print("\r" + " " * 50, end="\r")

    # Print Results
    for host, data in results.items():
        print_host_results(host, data)

    total_score = RiskEngine.calculate(results)
    risk_level = RiskEngine.classify(total_score)

    print("\n" + "=" * 70)
    print(f"{Fore.CYAN}SCAN SUMMARY{Style.RESET_ALL}")
    print("=" * 70)
    print(f"Hosts with Findings : {len(results)}")
    print(f"Total CVEs Found    : {sum(len(v['cves']) for v in results.values())}")
    print(f"Overall Risk Score  : {Fore.RED}{total_score}{Style.RESET_ALL}")
    print(
        f"Overall Risk Level  : "
        f"{Fore.RED if risk_level in ['HIGH','CRITICAL'] else Fore.YELLOW}"
        f"{risk_level}{Style.RESET_ALL}"
    )
    print("=" * 70)

    if args.json:
        generate_json(results)
        print(f"{Fore.GREEN}[+] JSON report generated.{Style.RESET_ALL}")

    print(f"{Fore.GREEN}[✓] Scan Completed Successfully.{Style.RESET_ALL}")


if __name__ == "__main__":
    main()
