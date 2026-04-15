import requests
import dns.resolver
import dns.zone
import dns.query
import socket
import time
import re
from rich.console import Console
from modules.google_dorking import GoogleDorker
from concurrent.futures import ThreadPoolExecutor, as_completed


console = Console()


class DomainSubdomainEnumerator:
    def __init__(self, config):
        self.config = config
        self.results = {"subdomains": [], "dns_records": {}, "zone_transfer": [], "whois_info": {}, "email_security": {}, "next_steps": [], "shadow_it_flags": []}
        self.discovered_subs = set()

    def run(self, target_domain, company_name=None):
        console.print(f"\n[bold cyan]{'='*60}[/bold cyan]")
        console.print(f"[bold cyan]  Module 2: Domain & Subdomain Enumeration - {target_domain}[/bold cyan]")
        console.print(f"[bold cyan]{'='*60}[/bold cyan]\n")
        self._dns_records(target_domain)
        self._zone_transfer(target_domain)
        self._crtsh(target_domain)
        self._vt_subdomains(target_domain)
        self._bruteforce(target_domain)
        self._email_security(target_domain)
        self._whois(target_domain)
        self._shadow_it_subs()
        self._next_steps()
        return self.results

    def _dns_records(self, domain):
        console.print("[yellow][*] Enumerating DNS records...[/yellow]")
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ["8.8.8.8", "1.1.1.1"]
        for rtype in ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "SRV", "CAA"]:
            try:
                answers = resolver.resolve(domain, rtype)
                records = [str(r) for r in answers]
                self.results["dns_records"][rtype] = records
                for r in records:
                    console.print(f"  [green][+] {rtype}: {r}[/green]")
            except Exception:
                pass

    def _zone_transfer(self, domain):
        console.print("[yellow][*] Attempting zone transfer...[/yellow]")
        try:
            for ns in dns.resolver.resolve(domain, "NS"):
                ns_host = str(ns).rstrip(".")
                try:
                    zone = dns.zone.from_xfr(dns.query.xfr(ns_host, domain, timeout=10))
                    console.print(f"  [bold red][!!!] ZONE TRANSFER SUCCESS on {ns_host}![/bold red]")
                    for name, node in zone.nodes.items():
                        sub = str(name) + "." + domain if str(name) != "@" else domain
                        self.results["zone_transfer"].append(sub)
                        self._add_sub(sub, "Zone Transfer")
                    self.results["shadow_it_flags"].append({"type": "DNS Zone Transfer Allowed", "asset": ns_host, "reason": "Exposes ALL DNS records. Critical misconfiguration."})
                except Exception:
                    console.print(f"  [dim][-] Zone transfer failed on {ns_host}[/dim]")
        except Exception:
            pass

    def _crtsh(self, domain):
        console.print("[yellow][*] Querying crt.sh CT logs...[/yellow]")
        for attempt in range(3):
            try:
                resp = requests.get(
                    f"https://crt.sh/?q=%.{domain}&output=json",
                    timeout=60,
                    headers={"User-Agent": "Mozilla/5.0"}
                )
                if resp.status_code == 200:
                    for entry in resp.json():
                        for name in entry.get("name_value", "").split("\n"):
                            name = name.strip().lower()
                            if name.endswith(domain) and "*" not in name:
                                self._add_sub(name, "crt.sh")
                    console.print(f"  [green][+] crt.sh: {len(self.discovered_subs)} subdomains[/green]")
                    return
            except Exception as e:
                console.print(f"  [yellow][!] crt.sh attempt {attempt+1}/3 failed: {e}[/yellow]")
                time.sleep(3)

        console.print("[yellow][*] Falling back to CertSpotter...[/yellow]")
        try:
            resp = requests.get(
                f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names",
                timeout=30
            )
            if resp.status_code == 200:
                for entry in resp.json():
                    for name in entry.get("dns_names", []):
                        name = name.strip().lower()
                        if name.endswith(domain) and "*" not in name:
                            self._add_sub(name, "CertSpotter")
                console.print(f"  [green][+] CertSpotter: {len(self.discovered_subs)} subdomains[/green]")
        except Exception as e:
            console.print(f"  [red][-] CertSpotter also failed: {e}[/red]")

    def _vt_subdomains(self, domain):
        api_key = self.config.get("VIRUSTOTAL_API_KEY", "")
        if not api_key:
            return
        console.print("[yellow][*] Querying VirusTotal...[/yellow]")
        try:
            resp = requests.get(
                f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains?limit=40",
                headers={"x-apikey": api_key},
                timeout=15
            )
            if resp.status_code == 200:
                for item in resp.json().get("data", []):
                    self._add_sub(item.get("id", ""), "VirusTotal")
        except Exception:
            pass

    def _bruteforce(self, domain):
        console.print("[yellow][*] Brute-forcing common subdomains...[/yellow]")
        common = [
            "www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2",
            "smtp", "secure", "vpn", "m", "shop", "ftp", "test", "portal",
            "support", "dev", "web", "admin", "store", "cdn", "api", "app",
            "staging", "demo", "beta", "sandbox", "internal", "intranet", "git",
            "gitlab", "jenkins", "ci", "jira", "confluence", "wiki", "docs",
            "status", "monitor", "grafana", "kibana", "docker", "k8s", "registry",
            "backup", "db", "database", "mysql", "redis", "qa", "uat", "preprod",
            "prod", "legacy", "old", "temp"
        ]
        for sub in common:
            full = f"{sub}.{domain}"
            try:
                socket.gethostbyname(full)
                self._add_sub(full, "Brute Force")
                console.print(f"  [green][+] Found: {full}[/green]")
            except socket.gaierror:
                pass

    def _email_security(self, domain):
        console.print("[yellow][*] Checking email security...[/yellow]")
        resolver = dns.resolver.Resolver()
        try:
            for r in resolver.resolve(domain, "TXT"):
                if "v=spf1" in str(r):
                    self.results["email_security"]["spf"] = str(r).strip('"')
                    console.print(f"  [green][+] SPF: {str(r)}[/green]")
        except Exception:
            self.results["email_security"]["spf"] = "NOT FOUND"
            console.print("  [bold red][!] SPF NOT FOUND[/bold red]")
        try:
            for r in resolver.resolve(f"_dmarc.{domain}", "TXT"):
                self.results["email_security"]["dmarc"] = str(r).strip('"')
                console.print(f"  [green][+] DMARC: {str(r)}[/green]")
        except Exception:
            self.results["email_security"]["dmarc"] = "NOT FOUND"
            console.print("  [bold red][!] DMARC NOT FOUND[/bold red]")
            self.results["shadow_it_flags"].append({"type": "Missing Email Security", "asset": domain, "reason": "No DMARC. Vulnerable to email spoofing."})

    def _whois(self, domain):
        console.print("[yellow][*] WHOIS lookup...[/yellow]")
        try:
            import whois
            w = whois.whois(domain)
            self.results["whois_info"] = {
                "registrar": str(w.registrar or "Unknown"),
                "creation_date": str(w.creation_date),
                "expiration_date": str(w.expiration_date),
                "name_servers": w.name_servers or []
            }
            console.print(f"  [green][+] Registrar: {w.registrar}[/green]")
        except Exception as e:
            console.print(f"  [red][-] WHOIS failed: {e}[/red]")

    def _add_sub(self, subdomain, source):
        subdomain = subdomain.strip().lower()
        if subdomain and subdomain not in self.discovered_subs:
            self.discovered_subs.add(subdomain)
            self.results["subdomains"].append({"subdomain": subdomain, "source": source})

    def _shadow_it_subs(self):
        shadow_kw = [
            "dev", "test", "staging", "temp", "tmp", "demo", "sandbox", "lab",
            "poc", "trial", "beta", "alpha", "personal", "my", "old", "legacy",
            "backup", "debug"
        ]
        for sub_data in self.results["subdomains"]:
            sub = sub_data["subdomain"]
            for kw in shadow_kw:
                if kw in sub.split(".")[0]:
                    self.results["shadow_it_flags"].append({
                        "type": "Suspicious Subdomain",
                        "asset": sub,
                        "reason": f"Contains '{kw}', suggesting dev/test/personal environment outside IT management."
                    })
                    break

    def _next_steps(self):
        steps = []
        if self.results["zone_transfer"]:
            steps.append({"action": "Fix Zone Transfer", "description": "CRITICAL: Restrict AXFR to authorized secondary DNS only.", "priority": "CRITICAL"})
        if self.results["email_security"].get("dmarc") == "NOT FOUND":
            steps.append({"action": "Implement DMARC", "description": "Start with p=none, escalate to p=reject.", "priority": "HIGH"})
        steps.append({"action": "Subdomain Verification", "description": f"Verify {len(self.results['subdomains'])} subdomains against IT inventory.", "priority": "HIGH"})
        steps.append({"action": "HTTP Probing", "description": "Probe all subdomains for live web services.", "command": "httpx -l subdomains.txt -status-code -title -tech-detect", "priority": "HIGH"})
        self.results["next_steps"] = steps