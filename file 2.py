# vulnerability_scanner.py

import socket
from datetime import datetime

# Common ports to scan
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    135: "RPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    8080: "HTTP-Proxy"
}

# Ports considered risky
RISKY_PORTS = {
    21: "FTP is insecure (uses plain text passwords)",
    23: "Telnet is insecure (no encryption)",
    445: "SMB can be vulnerable to attacks",
    3389: "RDP exposed to internet can be risky"
}

def scan_port(target, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)

        result = sock.connect_ex((target, port))

        if result == 0:
            try:
                banner = sock.recv(1024).decode().strip()
            except:
                banner = "No banner available"

            return True, banner
        else:
            return False, None

    except:
        return False, None

    finally:
        sock.close()

def generate_report(target, results):
    filename = f"vulnerability_report_{target}.txt"

    with open(filename, "w") as file:
        file.write("========== Vulnerability Scan Report ==========\n")
        file.write(f"Target: {target}\n")
        file.write(f"Scan Time: {datetime.now()}\n\n")

        for port, service, banner, risk in results:
            file.write(f"Port: {port}\n")
            file.write(f"Service: {service}\n")
            file.write(f"Banner: {banner}\n")

            if risk:
                file.write(f"WARNING: {risk}\n")

            file.write("-" * 40 + "\n")

    print(f"\n[+] Report saved as: {filename}")

def main():
    print("===== Simple Vulnerability Scanner =====")

    target = input("Enter target IP or domain: ")

    print(f"\nScanning target: {target}")
    print("-" * 50)

    results = []

    for port, service in COMMON_PORTS.items():
        is_open, banner = scan_port(target, port)

        if is_open:
            print(f"[OPEN] Port {port} ({service})")

            risk = RISKY_PORTS.get(port, None)

            if risk:
                print(f"  [!] Risk: {risk}")

            if banner:
                print(f"  Banner: {banner}")

            results.append((port, service, banner, risk))

    if results:
        generate_report(target, results)
    else:
        print("\nNo open common ports found.")

if __name__ == "__main__":
    main()