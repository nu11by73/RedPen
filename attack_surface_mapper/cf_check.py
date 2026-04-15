import socket
import struct
import json
import sys
import requests
import dns.resolver
import urllib3
from rich.console import Console
from rich.table import Table

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
console = Console()


def fetch_cloudflare_ranges():
    """Fetch current CF ranges from Cloudflare directly"""
    ranges = []
    try:
        resp = requests.get("https://www.cloudflare.com/ips-v4/", timeout=10)
        if resp.status_code == 200:
            for line in resp.text.strip().split("\n"):
                line = line.strip()
                if line:
                    ranges.append(line)
    except Exception:
        pass

    # Fallback if fetch fails
    if not ranges:
        ranges = [
            "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22",
            "103.31.4.0/22", "141.101.64.0/18", "108.162.192.0/18",
            "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22",
            "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
            "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
        ]
    return ranges


def ip_to_int(ip):
    return struct.unpack("!I", socket.inet_aton(ip))[0]


def cidr_to_range(cidr):
    ip, prefix = cidr.split("/")
    prefix = int(prefix)
    ip_int = ip_to_int(ip)
    mask = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
    return ip_int & mask, ip_int | ~mask & 0xFFFFFFFF


def is_cloudflare_ip(ip, cf_ranges):
    try:
        ip_int = ip_to_int(ip)
        for cidr in cf_ranges:
            start, end = cidr_to_range(cidr)
            if start <= ip_int <= end:
                return True
    except (socket.error, struct.error):
        pass
    return False


def check_cloudflare_headers(hostname):
    """Most reliable method — check actual HTTP response headers"""
    cf_indicators = {
        "server": "cloudflare",
        "cf-ray": None,
        "cf-cache-status": None,
        "cf-request-id": None,
        "cf-connecting-ip": None,
        "cf-worker": None,
    }

    result = {
        "is_cloudflare": False,
        "evidence": [],
        "headers": {},
    }

    for scheme in ["https", "http"]:
        try:
            resp = requests.head(
                f"{scheme}://{hostname}",
                timeout=10,
                allow_redirects=True,
                verify=False,
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
            )

            headers_lower = {k.lower(): v for k, v in resp.headers.items()}
            result["headers"] = dict(resp.headers)

            # Check server header
            server = headers_lower.get("server", "").lower()
            if "cloudflare" in server:
                result["is_cloudflare"] = True
                result["evidence"].append(f"Server: {resp.headers.get('Server', '')}")

            # Check for cf-* headers
            for header_name in ["cf-ray", "cf-cache-status", "cf-request-id", "cf-worker"]:
                if header_name in headers_lower:
                    result["is_cloudflare"] = True
                    result["evidence"].append(f"{header_name}: {headers_lower[header_name]}")

            # Check for cloudflare error pages
            if resp.status_code in [403, 503]:
                try:
                    body_resp = requests.get(
                        f"{scheme}://{hostname}",
                        timeout=10,
                        allow_redirects=True,
                        verify=False,
                    )
                    if "cloudflare" in body_resp.text.lower() or "cf-browser-verification" in body_resp.text.lower():
                        result["is_cloudflare"] = True
                        result["evidence"].append("Cloudflare challenge page detected")
                except Exception:
                    pass

            if result["is_cloudflare"]:
                return result

        except Exception:
            continue

    return result


def get_real_ip_attempts(hostname):
    """Try multiple methods to find the real IP behind Cloudflare"""
    real_ips = []
    cf_ranges = fetch_cloudflare_ranges()

    domain_parts = hostname.split(".")
    if len(domain_parts) >= 2:
        base_domain = ".".join(domain_parts[-2:])
    else:
        base_domain = hostname

    # Method 1: Check common origin subdomains
    origin_prefixes = [
        "direct", "origin", "real", "backend", "server",
        "mail", "ftp", "cpanel", "webmail", "smtp",
        "pop", "imap", "mx", "ns1", "ns2",
        "dev", "staging", "test", "old", "legacy",
        "direct-connect", "origin-www", "www2",
        "panel", "admin", "ssh", "vpn", "api",
        "media", "static", "cdn", "assets",
        "app", "portal", "crm", "erp",
    ]

    console.print(f"  [yellow][*] Checking {len(origin_prefixes)} subdomain variants...[/yellow]")

    for prefix in origin_prefixes:
        try:
            target = f"{prefix}.{base_domain}"
            ip = socket.gethostbyname(target)
            if not is_cloudflare_ip(ip, cf_ranges):
                # Verify this IP actually serves the right content
                is_real = False
                try:
                    resp = requests.head(
                        f"https://{ip}",
                        headers={"Host": base_domain},
                        timeout=5,
                        verify=False,
                        allow_redirects=False,
                    )
                    if resp.status_code < 500:
                        is_real = True
                except Exception:
                    pass

                confidence = "HIGH" if is_real else "MEDIUM"
                real_ips.append({"ip": ip, "method": f"DNS: {target}", "confidence": confidence})
                console.print(f"    [green][+] {target} -> {ip} (not CF, confidence: {confidence})[/green]")
        except socket.gaierror:
            pass

    # Method 2: Check MX records
    console.print(f"  [yellow][*] Checking MX records...[/yellow]")
    try:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ["8.8.8.8", "1.1.1.1"]
        mx_records = resolver.resolve(base_domain, "MX")
        for mx in mx_records:
            mx_host = str(mx.exchange).rstrip(".")
            try:
                mx_ip = socket.gethostbyname(mx_host)
                if not is_cloudflare_ip(mx_ip, cf_ranges):
                    real_ips.append({"ip": mx_ip, "method": f"MX: {mx_host}", "confidence": "MEDIUM"})
                    console.print(f"    [green][+] MX {mx_host} -> {mx_ip}[/green]")
            except socket.gaierror:
                pass
    except Exception:
        pass

    # Method 3: Check SPF record for ip4: directives
    console.print(f"  [yellow][*] Checking SPF records...[/yellow]")
    try:
        resolver = dns.resolver.Resolver()
        for txt in resolver.resolve(base_domain, "TXT"):
            txt_str = str(txt).strip('"')
            if "v=spf1" in txt_str:
                import re
                ip4_matches = re.findall(r'ip4:(\d+\.\d+\.\d+\.\d+)', txt_str)
                for ip in ip4_matches:
                    if not is_cloudflare_ip(ip, cf_ranges):
                        real_ips.append({"ip": ip, "method": f"SPF record", "confidence": "HIGH"})
                        console.print(f"    [green][+] SPF -> {ip}[/green]")
                # Also check ip4 CIDRs
                cidr_matches = re.findall(r'ip4:(\d+\.\d+\.\d+\.\d+/\d+)', txt_str)
                for cidr in cidr_matches:
                    base_ip = cidr.split("/")[0]
                    if not is_cloudflare_ip(base_ip, cf_ranges):
                        real_ips.append({"ip": cidr, "method": f"SPF record (range)", "confidence": "HIGH"})
                        console.print(f"    [green][+] SPF -> {cidr}[/green]")
    except Exception:
        pass

    # Method 4: Check TXT records for other IPs
    console.print(f"  [yellow][*] Checking TXT records...[/yellow]")
    try:
        resolver = dns.resolver.Resolver()
        for txt in resolver.resolve(base_domain, "TXT"):
            txt_str = str(txt).strip('"')
            import re
            ips = re.findall(r'(\d+\.\d+\.\d+\.\d+)', txt_str)
            for ip in ips:
                if not is_cloudflare_ip(ip, cf_ranges) and ip not in [r["ip"] for r in real_ips]:
                    real_ips.append({"ip": ip, "method": "TXT record", "confidence": "LOW"})
    except Exception:
        pass

    # Method 5: Check NS records — sometimes nameservers are on same infra
    console.print(f"  [yellow][*] Checking NS records...[/yellow]")
    try:
        resolver = dns.resolver.Resolver()
        for ns in resolver.resolve(base_domain, "NS"):
            ns_host = str(ns).rstrip(".")
            if base_domain in ns_host:
                try:
                    ns_ip = socket.gethostbyname(ns_host)
                    if not is_cloudflare_ip(ns_ip, cf_ranges):
                        real_ips.append({"ip": ns_ip, "method": f"NS: {ns_host}", "confidence": "LOW"})
                except socket.gaierror:
                    pass
    except Exception:
        pass

    # Method 6: Check historical IPs via DNS history APIs
    console.print(f"  [yellow][*] Checking DNS history...[/yellow]")
    try:
        resp = requests.get(
            f"https://api.securitytrails.com/v1/history/{base_domain}/dns/a",
            headers={"APIKEY": ""},
            timeout=10,
        )
        if resp.status_code == 200:
            for record in resp.json().get("records", []):
                for val in record.get("values", []):
                    ip = val.get("ip", "")
                    if ip and not is_cloudflare_ip(ip, cf_ranges):
                        real_ips.append({"ip": ip, "method": "DNS History (SecurityTrails)", "confidence": "MEDIUM"})
                        console.print(f"    [green][+] Historical -> {ip}[/green]")
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

    asn_data = data.get("results", {}).get("asn_ip", {})
    for entry in asn_data.get("ip_addresses", []):
        ip = entry.get("ip", "")
        host = entry.get("hostname", "")
        if ip:
            ips.append({"ip": ip, "hostname": host})
        if host:
            hostnames.append(host)

    sub_data = data.get("results", {}).get("domain_subdomain", {})
    for entry in sub_data.get("subdomains", []):
        sub = entry.get("subdomain", "")
        if sub:
            hostnames.append(sub)

    return ips, list(set(hostnames))


def main():
    console.print("\n[bold cyan]  Cloudflare Detection & Origin IP Finder v2.0[/bold cyan]\n")

    if len(sys.argv) < 2:
        console.print("[yellow]Usage:[/yellow]")
        console.print("  python cf_check.py example.com")
        console.print("  python cf_check.py example.com,sub.example.com")
        console.print("  python cf_check.py targets.txt")
        console.print("  python cf_check.py output/asm_report.json")
        console.print("  python cf_check.py example.com --export")
        return

    source = sys.argv[1]

    # Determine input type
    hostnames = []
    if source.endswith(".json"):
        console.print(f"[yellow][*] Loading from ASM report: {source}[/yellow]")
        _, hostnames = check_from_json(source)
    elif source.endswith(".txt"):
        console.print(f"[yellow][*] Loading from text file: {source}[/yellow]")
        with open(source, "r") as f:
            for line in f:
                line = line.strip()
                if line:
                    hostnames.append(line)
    else:
        hostnames = [h.strip() for h in source.split(",") if h.strip()]

    if not hostnames:
        console.print("[red][-] No targets found.[/red]")
        return

    # Fetch current CF ranges
    console.print("[yellow][*] Fetching current Cloudflare IP ranges...[/yellow]")
    cf_ranges = fetch_cloudflare_ranges()
    console.print(f"  [green][+] Loaded {len(cf_ranges)} Cloudflare CIDR ranges[/green]\n")

    # Results
    cf_hosts = []
    non_cf_hosts = []
    failed_hosts = []

    # Detection table
    table = Table(title="Cloudflare Detection Results")
    table.add_column("Hostname", style="white", max_width=40)
    table.add_column("IP", style="cyan")
    table.add_column("Behind CF?", style="bold")
    table.add_column("Detection Method", style="white")
    table.add_column("Evidence", style="dim")

    console.print(f"[yellow][*] Scanning {len(hostnames)} targets...[/yellow]\n")

    for host in hostnames:
        # Resolve IP
        try:
            ip = socket.gethostbyname(host)
        except socket.gaierror:
            failed_hosts.append(host)
            table.add_row(host, "UNRESOLVABLE", "[dim]N/A[/dim]", "DNS failed", "")
            continue

        ip_is_cf = is_cloudflare_ip(ip, cf_ranges)

        # Check HTTP headers (most reliable)
        header_result = check_cloudflare_headers(host)
        header_is_cf = header_result["is_cloudflare"]
        evidence = ", ".join(header_result["evidence"][:3]) if header_result["evidence"] else ""

        # Combined verdict
        is_cf = ip_is_cf or header_is_cf

        if ip_is_cf and header_is_cf:
            method = "IP Range + Headers"
        elif header_is_cf:
            method = "Headers Only"
        elif ip_is_cf:
            method = "IP Range Only"
        else:
            method = "Not Cloudflare"

        if is_cf:
            cf_hosts.append({"hostname": host, "ip": ip, "method": method, "evidence": evidence})
            table.add_row(host, ip, "[bold red]YES[/bold red]", method, evidence[:60])
        else:
            non_cf_hosts.append({"hostname": host, "ip": ip})
            table.add_row(host, ip, "[bold green]NO[/bold green]", "Direct", "")

    console.print(table)

    # Summary
    console.print(f"\n[bold cyan]  Summary:[/bold cyan]")
    console.print(f"  Total scanned:     {len(hostnames)}")
    console.print(f"  [red]Behind Cloudflare:  {len(cf_hosts)}[/red]")
    console.print(f"  [green]Direct (no CF):     {len(non_cf_hosts)}[/green]")
    if failed_hosts:
        console.print(f"  [dim]Failed to resolve:  {len(failed_hosts)}[/dim]")

    # Origin discovery for CF-protected hosts
    if cf_hosts:
        console.print(f"\n[bold yellow]  Attempting origin IP discovery for {len(cf_hosts)} CF-protected hosts...[/bold yellow]\n")

        origin_table = Table(title="Potential Origin IPs (Real Server Behind Cloudflare)")
        origin_table.add_column("Protected Host", style="cyan")
        origin_table.add_column("Origin IP", style="green")
        origin_table.add_column("Method", style="yellow")
        origin_table.add_column("Confidence", style="bold")

        all_origins = {}
        found_any = False

        for entry in cf_hosts:
            host = entry["hostname"]
            console.print(f"  [yellow][*] Probing: {host}[/yellow]")
            origins = get_real_ip_attempts(host)
            all_origins[host] = origins

            for origin in origins:
                found_any = True
                conf = origin["confidence"]
                if conf == "HIGH":
                    conf_color = "bold green"
                elif conf == "MEDIUM":
                    conf_color = "bold yellow"
                else:
                    conf_color = "white"
                origin_table.add_row(
                    host,
                    origin["ip"],
                    origin["method"],
                    f"[{conf_color}]{conf}[/{conf_color}]",
                )

        if found_any:
            console.print("")
            console.print(origin_table)

            # Verify origins
            console.print(f"\n[bold yellow]  Verifying origin IPs serve the correct content...[/bold yellow]\n")
            for host, origins in all_origins.items():
                for origin in origins:
                    try:
                        resp = requests.get(
                            f"https://{origin['ip']}",
                            headers={"Host": host},
                            timeout=8,
                            verify=False,
                            allow_redirects=False,
                        )
                        status = resp.status_code
                        server = resp.headers.get("Server", "unknown")
                        title = ""
                        if "<title>" in resp.text.lower():
                            import re
                            m = re.search(r"<title>(.*?)</title>", resp.text, re.I)
                            if m:
                                title = m.group(1)[:50]

                        if status < 500:
                            console.print(f"    [green][+] {origin['ip']} ({host}): HTTP {status} | Server: {server} | Title: {title}[/green]")
                            origin["verified"] = True
                        else:
                            console.print(f"    [dim][-] {origin['ip']}: HTTP {status}[/dim]")
                            origin["verified"] = False
                    except Exception:
                        console.print(f"    [dim][-] {origin['ip']}: Connection failed[/dim]")
                        origin["verified"] = False
        else:
            console.print("\n  [dim]No origin IPs discovered. Target is well-configured.[/dim]")

    # Direct IPs
    if non_cf_hosts:
        console.print(f"\n[bold green]  Direct (non-CF) hosts — scan these directly:[/bold green]")
        for entry in non_cf_hosts:
            console.print(f"    {entry['hostname']} -> {entry['ip']}")

    # Export
    if "--export" in sys.argv:
        export = {
            "cloudflare_hosts": cf_hosts,
            "direct_hosts": non_cf_hosts,
            "failed_hosts": failed_hosts,
            "origin_discoveries": all_origins if cf_hosts else {},
        }
        out_path = "cf_check_results.json"
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(export, f, indent=2, default=str)
        console.print(f"\n[green][+] Exported to {out_path}[/green]")

    # Next steps
    console.print(f"\n[bold cyan]  Next Steps:[/bold cyan]")
    if non_cf_hosts:
        direct_ips = " ".join([e["ip"] for e in non_cf_hosts[:10]])
        console.print(f"  1. Scan direct IPs:  nmap -sV -sC {direct_ips}")
    if cf_hosts:
        console.print(f"  2. Check censys.io for SSL certs matching these domains")
        console.print(f"  3. Check shodan.io with: ssl.cert.subject.CN:\"target.com\"")
        console.print(f"  4. Try SecurityTrails.com for full DNS history (free account)")
        console.print(f"  5. For verified origins, test direct access: curl -H \"Host: target.com\" https://<origin_ip>/")
        console.print(f"  6. Check if origin restricts to CF IPs only (properly configured = blocked)")


if __name__ == "__main__":
    main()