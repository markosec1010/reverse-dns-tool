import socket
import dns.resolver
import argparse
import ipaddress
import requests

# Replace with your own ViewDNS API key if you want to use the API
API_KEY = "YOUR_API_KEY_HERE"

def is_valid_ip(ip):
    """Check if an IP address is valid (IPv4 or IPv6)."""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def forward_lookup(domain):
    """Perform forward DNS lookup (domain -> IP)."""
    try:
        ip = socket.gethostbyname(domain)
        print(f"[Forward] IP address for {domain}: {ip}")
    except socket.gaierror:
        print(f"[Forward] Cannot resolve IP for: {domain}")

def reverse_lookup(ip):
    """Perform reverse DNS lookup (IP -> domain)."""
    try:
        host = socket.gethostbyaddr(ip)
        print(f"[Reverse] Hostname for {ip}: {host[0]}")
        return host
    except socket.herror:
        print(f"[Reverse] Cannot find hostname for: {ip}")
        return None

def advanced_dns(domain):
    """Fetch A and MX DNS records for a domain."""
    try:
        a_records = dns.resolver.resolve(domain, 'A')
        print(f"[Advanced] A records for {domain}:")
        for rdata in a_records:
            print("  ", rdata.to_text())
    except:
        print("[Advanced] No A records found")

    try:
        mx_records = dns.resolver.resolve(domain, 'MX')
        print(f"[Advanced] MX records for {domain}:")
        for rdata in mx_records:
            print("  ", rdata.exchange)
    except:
        print("[Advanced] No MX records found")

def get_websites_on_server(ip):
    """Use ViewDNS API to list other websites on the same server."""
    url = f"https://api.viewdns.info/reverseip/?host={ip}&apikey={API_KEY}&output=json"
    try:
        response = requests.get(url, timeout=10)
        if response.ok:
            data = response.json()
            if "response" in data and "domains" in data["response"]:
                return data["response"]["domains"]
    except:
        pass
    return []

def main():
    """Parse command-line arguments and execute reverse lookup."""
    parser = argparse.ArgumentParser(description="Perform IP reverse lookup.")
    parser.add_argument("ips", nargs="+", help="IP address(es) to perform reverse lookup on.")
    parser.add_argument("--all", "-a", action="store_true", help="Show all websites on the same server.")
    args = parser.parse_args()

    for ip in args.ips:
        if not is_valid_ip(ip):
            print(f"[-] Invalid IP address: {ip}")
            continue

        host = reverse_lookup(ip)
        if host:
            print(f"[+] IP: {ip}, Domain: {host[0]}")
            if args.all:
                websites = get_websites_on_server(ip)
                if websites:
                    print("Other websites on the same server:")
                    for site in websites:
                        print(" -", site)
                else:
                    print("[-] No other websites found on the same server.")
        else:
            print(f"[-] No domain found for IP: {ip}")

if __name__ == "__main__":
    # Forward DNS lookup
    domain = input("Enter domain for DNS lookup (or press Enter to skip): ").strip()
    if domain:
        forward_lookup(domain)
        advanced_dns(domain)

    # Reverse DNS via CLI arguments
    main()

    # Optional reverse lookup
    ip_input = input("Enter IP for reverse lookup (Press Enter to skip): ").strip()
    if ip_input:
        reverse_lookup(ip_input)
