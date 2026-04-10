import requests
import socket
import json
import time
from ipwhois import IPWhois
from rich.console import Console

console = Console()


class ASNIPEnumerator:
    def __init__(self, config):
        self.config = config
        self.results = {
            "asn_info": [], "ip_addresses": [], "ip_ranges": [],
            "reverse_dns": {}, "open_ports": {}, "iot_devices": [],
            "next_steps": [], "shadow_it_flags": [],
        }

    def run(self, target_domain, company_name=None):
        console.print(f"\n[bold cyan]{'='*60}[/bold cyan]")
        console.print(f"[bold cyan]  Module 1: ASN & IP Enumeration - {target_domain}[/bold cyan]")
        console.print(f"[bold cyan]{'='*60}[/bold cyan]\n")
        self._resolve_domain(target_domain)
        primary_ips = [i["ip"] for i in self.results["ip_addresses"]]
        self._whois_lookup(primary_ips)
        self._bgp_asn_lookup(target_domain, company_name)
        self._shodan_host_search(primary_ips)
        self._shodan_org_search(company_name)
        self._reverse_dns_sweep(primary_ips)
        self._generate_next_steps()
        return self.results

    def _resolve_domain(self, domain):
        console.print("[yellow][*] Resolving domain to IPs...[/yellow]")
        ips = set()
        try:
            results = socket.getaddrinfo(domain, None)
            for r in results:
                ip = r[4][0]
                if ip not in ips:
                    ips.add(ip)
                    self.results["ip_addresses"].append({"ip": ip, "source": "DNS A/AAAA", "hostname": domain})
                    console.print(f"  [green][+] {domain} -> {ip}[/green]")
        except socket.gaierror as e:
            console.print(f"  [red][-] DNS resolution failed: {e}[/red]")
        common_subs = ["www", "mail", "ns1", "ns2", "ftp", "webmail", "smtp", "pop", "imap"]
        for sub in common_subs:
            try:
                hostname = f"{sub}.{domain}"
                results = socket.getaddrinfo(hostname, None)
                for r in results:
                    ip = r[4][0]
                    if ip not in ips:
                        ips.add(ip)
                        self.results["ip_addresses"].append({"ip": ip, "source": f"DNS ({hostname})", "hostname": hostname})
                        console.print(f"  [green][+] {hostname} -> {ip}[/green]")
            except socket.gaierror:
                pass

    def _whois_lookup(self, ips):
        console.print("[yellow][*] Performing WHOIS lookups...[/yellow]")
        seen_asns = set()
        for ip in ips[:self.config["MAX_IPS_TO_SCAN"]]:
            try:
                obj = IPWhois(ip)
                result = obj.lookup_rdap(asn_methods=["whois", "dns", "http"])
                asn = result.get("asn", "Unknown")
                asn_desc = result.get("asn_description", "Unknown")
                asn_cidr = result.get("asn_cidr", "Unknown")
                network_name = result.get("network", {}).get("name", "Unknown")
                if asn not in seen_asns:
                    seen_asns.add(asn)
                    self.results["asn_info"].append({"asn": asn, "description": asn_desc, "cidr": asn_cidr, "network_name": network_name, "ip": ip})
                    self.results["ip_ranges"].append(asn_cidr)
                    console.print(f"  [green][+] ASN{asn} - {asn_desc} ({asn_cidr})[/green]")
            except Exception as e:
                console.print(f"  [red][-] WHOIS failed for {ip}: {e}[/red]")

    def _bgp_asn_lookup(self, domain, company_name=None):
        console.print("[yellow][*] Querying BGP/ASN databases...[/yellow]")
        try:
            search_term = company_name if company_name else domain.split(".")[0]
            url = f"https://api.bgpview.io/search?query_term={search_term}"
            resp = requests.get(url, timeout=self.config["REQUEST_TIMEOUT"])
            if resp.status_code == 200:
                data = resp.json().get("data", {})
                for asn_entry in data.get("asns", []):
                    asn_num = asn_entry.get("asn")
                    asn_name = asn_entry.get("name", "Unknown")
                    try:
                        prefix_url = f"https://api.bgpview.io/asn/{asn_num}/prefixes"
                        prefix_resp = requests.get(prefix_url, timeout=self.config["REQUEST_TIMEOUT"])
                        if prefix_resp.status_code == 200:
                            for prefix in prefix_resp.json().get("data", {}).get("ipv4_prefixes", []):
                                cidr = prefix.get("prefix", "")
                                if cidr and cidr not in self.results["ip_ranges"]:
                                    self.results["ip_ranges"].append(cidr)
                                    console.print(f"  [green][+] ASN{asn_num} prefix: {cidr}[/green]")
                    except Exception:
                        pass
                    existing = [a["asn"] for a in self.results["asn_info"]]
                    if str(asn_num) not in existing:
                        self.results["asn_info"].append({"asn": str(asn_num), "description": asn_name, "source": "BGPView"})
                        console.print(f"  [green][+] BGPView: ASN{asn_num} - {asn_name}[/green]")
        except Exception as e:
            console.print(f"  [red][-] BGPView failed: {e}[/red]")

    def _shodan_host_search(self, ips):
        console.print("[yellow][*] Querying Shodan for host info...[/yellow]")
        api_key = self.config.get("SHODAN_API_KEY", "")
        if not api_key:
            console.print("  [red][-] Shodan API key not configured.[/red]")
            return
        for ip in ips[:self.config["MAX_IPS_TO_SCAN"]]:
            try:
                url = f"https://api.shodan.io/shodan/host/{ip}?key={api_key}"
                resp = requests.get(url, timeout=self.config["REQUEST_TIMEOUT"])
                if resp.status_code == 200:
                    data = resp.json()
                    ports = data.get("ports", [])
                    vulns = data.get("vulns", [])
                    self.results["open_ports"][ip] = {"ports": ports, "os": data.get("os", "Unknown"), "hostnames": data.get("hostnames", []), "vulns": vulns, "services": []}
                    console.print(f"  [green][+] {ip}: Ports {ports}[/green]")
                    if vulns:
                        console.print(f"      [bold red][!] Vulns: {vulns}[/bold red]")
                    for svc in data.get("data", []):
                        port = svc.get("port")
                        product = svc.get("product", "")
                        banner = svc.get("data", "")[:200]
                        self.results["open_ports"][ip]["services"].append({"port": port, "product": product, "banner": banner})
                        iot_kw = ["camera", "webcam", "dvr", "nvr", "printer", "ups", "scada", "plc", "mqtt", "modbus"]
                        for kw in iot_kw:
                            if kw in product.lower() or kw in banner.lower():
                                self.results["iot_devices"].append({"ip": ip, "port": port, "type": kw, "product": product})
                                console.print(f"      [bold yellow][!] IoT: {kw} on port {port}[/bold yellow]")
                                self.results["shadow_it_flags"].append({"type": "IoT Device Exposed", "asset": f"{ip}:{port}", "reason": f"IoT device ({kw}) detected. Likely deployed outside IT governance."})
                                break
                time.sleep(self.config["REQUEST_DELAY"])
            except Exception as e:
                console.print(f"  [red][-] Shodan failed for {ip}: {e}[/red]")

    def _shodan_org_search(self, company_name=None):
        if not company_name:
            return
        api_key = self.config.get("SHODAN_API_KEY", "")
        if not api_key:
            return
        console.print(f"[yellow][*] Shodan org search: {company_name}[/yellow]")
        try:
            url = f"https://api.shodan.io/shodan/host/search?key={api_key}&query=org:\"{company_name}\"&facets=port"
            resp = requests.get(url, timeout=self.config["REQUEST_TIMEOUT"])
            if resp.status_code == 200:
                data = resp.json()
                console.print(f"  [green][+] Found {data.get('total', 0)} hosts[/green]")
                for match in data.get("matches", [])[:20]:
                    ip = match.get("ip_str")
                    existing = [i["ip"] for i in self.results["ip_addresses"]]
                    if ip and ip not in existing:
                        self.results["ip_addresses"].append({"ip": ip, "source": "Shodan Org", "port": match.get("port"), "product": match.get("product", "")})
                        self.results["shadow_it_flags"].append({"type": "Unregistered IP in Org", "asset": ip, "reason": f"Found in Shodan under org but not in DNS. May be shadow IT."})
        except Exception as e:
            console.print(f"  [red][-] Shodan org search failed: {e}[/red]")

    def _reverse_dns_sweep(self, ips):
        console.print("[yellow][*] Reverse DNS lookups...[/yellow]")
        for ip in ips:
            try:
                hostname, _, _ = socket.gethostbyaddr(ip)
                self.results["reverse_dns"][ip] = hostname
                console.print(f"  [green][+] {ip} -> {hostname}[/green]")
            except socket.herror:
                self.results["reverse_dns"][ip] = "No PTR"
            except Exception:
                pass

    def _generate_next_steps(self):
        steps = []
        if self.results["iot_devices"]:
            steps.append({"action": "IoT Device Assessment", "description": f"Found {len(self.results['iot_devices'])} IoT devices. Verify authorization and segmentation.", "priority": "HIGH"})
        vuln_hosts = [ip for ip, d in self.results["open_ports"].items() if d.get("vulns")]
        if vuln_hosts:
            steps.append({"action": "Vulnerability Verification", "description": f"{len(vuln_hosts)} hosts have CVEs. Verify with Nessus/OpenVAS.", "command": f"nmap -sV --script=vulners {' '.join(vuln_hosts[:5])}", "priority": "CRITICAL"})
        steps.append({"action": "Full Port Scan", "description": f"Scan {len(self.results['ip_ranges'])} IP ranges comprehensively.", "command": f"nmap -sS -sV -p- --min-rate=1000 {' '.join(self.results['ip_ranges'][:3])}", "priority": "HIGH"})
        steps.append({"action": "ASN Verification", "description": f"Verify {len(self.results['asn_info'])} ASNs against IT inventory.", "priority": "MEDIUM"})
        self.results["next_steps"] = steps
