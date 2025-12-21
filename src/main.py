import argparse
from concurrent.futures import ThreadPoolExecutor
from scanner_engine import ScannerEngine
from network_utils import NetworkUtils

def main():
    parser = argparse.ArgumentParser(description="Port Scanner")
    parser.add_argument("-t", "--target", help="Target IP or domain", required=True)
    parser.add_argument("-p", "--ports", help="Ports e.g. 22,80,443", default="22,80,443")
    args = parser.parse_args()

    # Validation
    target = args.target if NetworkUtils.validate_ip(args.target) else NetworkUtils.resolve_host(args.target)
    if not target:
        print("[-] Error: Invalid target.")
        return

    scanner = ScannerEngine(target)

    print(f"[*] Starting scan for: {target}")
    if not scanner.is_host_alive():
        print("[!] Host does not respond to ping, but continuing port scan...")

    ports = [int(p) for p in args.ports.split(",")]

    # Multi-threading - significantly speeds up the scanning process
    with ThreadPoolExecutor(max_workers=20) as executor:
        results = list(executor.map(scanner.syn_scan, ports))

    print("\n--- RESULTS ---")
    for port, status in zip(ports, results):
        service = scanner.get_service_name(port)
        print(f" Port {port} ({service}): {status}")

if __name__ == "__main__":
    main()