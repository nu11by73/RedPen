import socket
import struct
import json
import sys
import requests
import dns.resolver
from rich.console import Console
from rich.table import Table

console = Console()

# Cloudflare's published IP ranges
CF_IPV4 = [
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22",
    "103.31.4.0/22", "141.101.64.0/18", "108.162.192.0/18",
    "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22",
    "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
]

CF_IPV6 = [
    "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32",
    "2405:b500::/32", "2405:8100::/32", "2a06:98c0::/29",
    "2c0f:f248::/32",
]


def ip_to_int(ip):
    return struct.unpack("!I", socket.inet_aton(ip))[0]


def cidr_to_range(cidr):
    ip, prefix = cidr.split("/")
    prefix = int(prefix)
    ip_int = ip_to_int(ip)
    mask = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
    return ip_int & mask, ip_int | ~mask & 0xFFFFFFFF


def is_cloudflare_ip(ip):
    try:
        ip_int = ip_to_int(ip)
        for cidr in CF_IPV4:
            start, end = cidr_to_range(cidr)
            if start <= ip_int <= end:
                return True
    except (socket.error, struct.error):
        pass
    return False


def get_real_ip_attempts(hostname):
    """Try multiple methods to find the real IP behind Cloudflare"""
    real_ips = []

    # Method 1: Check common origin subdomains
    origin_prefixes = [
        "direct", "origin", "real", "backend", "server",
        "mail", "ftp", "cpanel", "webmail", "smtp",
        "pop", "imap", "mx", "ns1", "ns2",
        "dev", "staging", "test", "old", "legacy",
        "direct-connect", "origin-www",
    ]

    domain_parts = hostname.split(".")
    if len(domain_parts) >= 2:
        base_domain = ".".join(domain_parts[-2:])
    else:
        base_domain = hostname

    for prefix in origin_prefixes:
        try:
            target = f"{prefix}.{base_domain}"
            ip = socket.gethostbyname(target)
            if not is_cloudflare_ip(ip):
                real_ips.append({"ip": ip, "method": f"DNS: {target}", "confidence": "MEDIUM"})
        except socket.gaierror:
            pass

    # Method 2: Check MX records (mail servers often reveal origin)
    try:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ["8.8.8.8", "1.1.1.1"]
        mx_records = resolver.resolve(base_domain, "MX")
        for mx in mx_records:
            mx_host = str(mx.exchange).rstrip(".")
            try:
                mx_ip = socket.gethostbyname(mx_host)
                if not is_cloudflare_ip(mx_ip):
                    real_ips.append({"ip": mx_ip, "method": f"MX: {mx_host}", "confidence": "LOW"})
            except socket.gaierror:
                pass
    except Exception:
        pass

    # Method 3: Check SPF record for ip4: directives
    try:
        resolver = dns.resolver.Resolver()
        for txt in resolver.resolve(base_domain, "TXT"):
            txt_str = str(txt).strip('"')
            if "v=spf1" in txt_str:
                parts = txt_str.split()
                for part in parts:
                    if part.startswith("ip4:"):
                        ip = part.replace("ip4:", "").split("/")[0]
                        if not is_cloudflare_ip(ip):
                            real_ips.append({"ip": ip, "method": f"SPF: {part}", "confidence": "HIGH"})
    except Exception:
        pass

    # Method 4: Check DNS history via SecurityTrails (free limited)
    try:
        resp = requests.get(
            f"https://api.securitytrails.com/v1/history/{base_domain}/dns/a",
            headers={"APIKEY": ""},  # Add key if you have one
            timeout=10
        )
        if resp.status_code == 200:
            for record in resp.json().get("records", []):
                for val in record.get("values", []):
                    ip = val.get("ip", "")
                    if ip and not is_cloudflare_ip(ip):
                        real_ips.append({"ip": ip, "method": "DNS History", "confidence": "MEDIUM"})
    except Exception:
        pass

    # Method 5: Shodan search for SSL cert
    try:
        resp = requests.get(
            f"https://api.shodan.io/dns/domain/{base_domain}?key=",  # Add key
            timeout=10
        )
    except Exception:
        pass

    # Deduplicate
    seen = set()
    unique = []
    for entry in real_ips:
        if entry["ip"] not in seen:
            seen.add(entry["ip"])
            unique.append(entry)

    return unique


def check_from_json(json_path):
    """Load IPs from ASM tool JSON output"""
    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    ips = []
    hostnames = []

    # Extract from ASN module
    asn_data = data.get("results", {}).get("asn_ip", {})
    for entry in asn_data.get("ip_addresses", []):
        ip = entry.get("ip", "")
        host = entry.get("hostname", "")
        if ip:
            ips.append({"ip": ip, "hostname": host})
        if host:
            hostnames.append(host)

    # Extract from subdomain module
    sub_data = data.get("results", {}).get("domain_subdomain", {})
    for entry in sub_data.get("subdomains", []):
        sub = entry.get("subdomain", "")
        if sub:
            hostnames.append(sub)

    return ips, list(set(hostnames))


def check_from_list(ip_list):
    """Check a list of IPs directly"""
    results = []
    for ip in ip_list:
        ip = ip.strip()
        if ip:
            results.append({"ip": ip, "hostname": ""})
    return results, []


def main():
    console.print("\n[bold cyan]  Cloudflare Detection & Origin IP Finder[/bold cyan]\n")

    # Determine input source
    if len(sys.argv) > 1:
        source = sys.argv[1]
        if source.endswith(".json"):
            console.print(f"[yellow][*] Loading from ASM report: {source}[/yellow]")
            ips, hostnames = check_from_json(source)
        elif source.endswith(".txt"):
            console.print(f"[yellow][*] Loading from text file: {source}[/yellow]")
            with open(source, "r") as f:
                ip_list = f.readlines()
            ips, hostnames = check_from_list(ip_list)
        else:
            # Treat as comma-separated IPs or single domain
            ips, hostnames = check_from_list(source.split(","))
    else:
        console.print("[yellow]Usage:[/yellow]")
        console.print("  python cf_check.py output\\asm_target_timestamp.json")
        console.print("  python cf_check.py ips.txt")
        console.print("  python cf_check.py 1.2.3.4,5.6.7.8")
        console.print("  python cf_check.py example.com")
        return

    # Also resolve hostnames to IPs
    for host in hostnames:
        try:
            ip = socket.gethostbyname(host)
            existing = [e["ip"] for e in ips]
            if ip not in existing:
                ips.append({"ip": ip, "hostname": host})
        except socket.gaierror:
            pass

    if not ips:
        console.print("[red][-] No IPs found to check.[/red]")
        return

    # Check each IP
    cf_ips = []
    real_ips = []
    table = Table(title="Cloudflare Detection Results")
    table.add_column("IP", style="white")
    table.add_column("Hostname", style="cyan")
    table.add_column("Behind CF?", style="bold")
    table.add_column("Status", style="white")

    console.print(f"\n[yellow][*] Checking {len(ips)} IPs against Cloudflare ranges...[/yellow]\n")

    for entry in ips:
        ip = entry["ip"]
        host = entry.get("hostname", "")
        if is_cloudflare_ip(ip):
            cf_ips.append(entry)
            table.add_row(ip, host, "[bold red]YES[/bold red]", "Cloudflare proxy - not the real server")
        else:
            real_ips.append(entry)
            table.add_row(ip, host, "[bold green]NO[/bold green]", "Direct IP - potential real origin")

    console.print(table)

    # Summary
    console.print(f"\n[bold cyan]  Summary:[/bold cyan]")
    console.print(f"  Total IPs checked: {len(ips)}")
    console.print(f"  [red]Behind Cloudflare: {len(cf_ips)}[/red]")
    console.print(f"  [green]Direct/Real IPs: {len(real_ips)}[/green]")

    # Try to find origin IPs for Cloudflare-protected hosts
    cf_hostnames = set()
    for entry in cf_ips:
        host = entry.get("hostname", "")
        if host:
            cf_hostnames.add(host)

    if cf_hostnames:
        console.print(f"\n[bold yellow]  Attempting origin IP discovery for {len(cf_hostnames)} CF-protected hosts...[/bold yellow]\n")

        origin_table = Table(title="Potential Origin IPs")
        origin_table.add_column("Protected Host", style="cyan")
        origin_table.add_column("Origin IP", style="green")
        origin_table.add_column("Method", style="yellow")
        origin_table.add_column("Confidence", style="bold")

        found_any = False
        for host in cf_hostnames:
            console.print(f"  [yellow][*] Probing: {host}[/yellow]")
            origins = get_real_ip_attempts(host)
            for origin in origins:
                found_any = True
                conf = origin["confidence"]
                conf_color = "bold green" if conf == "HIGH" else "bold yellow" if conf == "MEDIUM" else "white"
                origin_table.add_row(
                    host,
                    origin["ip"],
                    origin["method"],
                    f"[{conf_color}]{conf}[/{conf_color}]"
                )

        if found_any:
            console.print(origin_table)
        else:
            console.print("  [dim]No origin IPs discovered. Target is well-configured.[/dim]")

    # Export results
    if len(sys.argv) > 2 and sys.argv[2] == "--export":
        export = {
            "cloudflare_ips": cf_ips,
            "direct_ips": real_ips,
            "origin_discoveries": []
        }
        out_path = "cf_check_results.json"
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(export, f, indent=2)
        console.print(f"\n[green][+] Exported to {out_path}[/green]")

    # Actionable next steps
    console.print(f"\n[bold cyan]  Next Steps:[/bold cyan]")
    if real_ips:
        direct = " ".join([e["ip"] for e in real_ips[:10]])
        console.print(f"  1. Scan direct IPs: nmap -sV -sC {direct}")
    if cf_ips:
        console.print(f"  2. Check censys.io / shodan.io for historical DNS records")
        console.print(f"  3. Check SecurityTrails for DNS history (reveals pre-CF IPs)")
        console.print(f"  4. Send direct HTTP requests with Host header to candidate IPs")
        console.print(f"  5. Check for info leaks in SSL certs on candidate IPs")


if __name__ == "__main__":
    main()
