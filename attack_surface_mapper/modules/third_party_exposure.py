import requests
import re
import dns.resolver
from rich.console import Console

console = Console()


class ThirdPartyExposureScanner:
    def __init__(self, config):
        self.config = config
        self.results = {"third_party_services": [], "analytics_tracking": [], "saas_services": [], "supply_chain_risks": [], "next_steps": [], "shadow_it_flags": []}

    def run(self, target_domain, subdomains=None, technology_data=None):
        console.print(f"\n[bold cyan]{'='*60}[/bold cyan]")
        console.print(f"[bold cyan]  Module 8: Third-Party Exposure - {target_domain}[/bold cyan]")
        console.print(f"[bold cyan]{'='*60}[/bold cyan]\n")
        self._third_party(target_domain)
        self._saas(target_domain)
        self._supply_chain(target_domain)
        self._next_steps()
        return self.results

    def _third_party(self, domain):
        console.print("[yellow][*] Analyzing third-party resources...[/yellow]")
        try:
            resp = requests.get(f"https://{domain}", timeout=15, verify=False, headers={"User-Agent": self.config["USER_AGENT"]})
            if resp.status_code == 200:
                from bs4 import BeautifulSoup
                soup = BeautifulSoup(resp.text, "html.parser")
                for script in soup.find_all("script", src=True):
                    src = script["src"]
                    if src.startswith("//"):
                        src = f"https:{src}"
                    elif src.startswith("/"):
                        continue
                    if domain not in src:
                        m = re.search(r'https?://([^/]+)', src)
                        if m:
                            self.results["third_party_services"].append({"type": "JavaScript", "domain": m.group(1), "url": src})
                            console.print(f"  [green][+] Third-party JS: {m.group(1)}[/green]")
                analytics = {"Google Analytics": [r'google-analytics\.com', r'googletagmanager\.com'], "Facebook Pixel": [r'facebook\.net'], "HubSpot": [r'hubspot\.com']}
                for svc, pats in analytics.items():
                    for p in pats:
                        if re.search(p, resp.text, re.I):
                            self.results["analytics_tracking"].append({"service": svc})
                            console.print(f"  [cyan][*] Analytics: {svc}[/cyan]")
                            break
        except Exception as e:
            console.print(f"  [red][-] Failed: {e}[/red]")

    def _saas(self, domain):
        console.print("[yellow][*] Detecting SaaS via DNS TXT...[/yellow]")
        try:
            resolver = dns.resolver.Resolver()
            for record in resolver.resolve(domain, "TXT"):
                txt = str(record).strip('"')
                saas_map = {"google-site-verification": "Google Workspace", "MS=": "Microsoft 365", "atlassian-domain-verification": "Atlassian", "docusign": "DocuSign"}
                for ind, svc in saas_map.items():
                    if ind.lower() in txt.lower():
                        self.results["saas_services"].append({"service": svc, "source": "DNS TXT"})
                        console.print(f"  [green][+] SaaS: {svc}[/green]")
                        self.results["shadow_it_flags"].append({"type": "SaaS Service", "asset": svc, "reason": f"Verify '{svc}' is approved."})
        except Exception:
            pass

    def _supply_chain(self, domain):
        console.print("[yellow][*] Checking JS supply chain...[/yellow]")
        try:
            resp = requests.get(f"https://{domain}", timeout=15, verify=False, headers={"User-Agent": self.config["USER_AGENT"]})
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(resp.text, "html.parser")
            for script in soup.find_all("script", src=True):
                src = script.get("src", "")
                integrity = script.get("integrity", "")
                if src and not src.startswith("/") and domain not in src and not integrity:
                    self.results["supply_chain_risks"].append({"type": "Missing SRI", "resource": src})
                    console.print(f"  [yellow][!] No SRI: {src}[/yellow]")
        except Exception:
            pass

    def _next_steps(self):
        steps = []
        if self.results["supply_chain_risks"]:
            steps.append({"action": "Add SRI Hashes", "description": f"{len(self.results['supply_chain_risks'])} scripts lack SRI.", "priority": "HIGH"})
        if self.results["saas_services"]:
            steps.append({"action": "SaaS Inventory", "description": f"Verify {len(self.results['saas_services'])} SaaS services.", "priority": "HIGH"})
        steps.append({"action": "Vendor Risk Assessment", "description": "Request SOC 2/ISO 27001 from vendors.", "priority": "HIGH"})
        self.results["next_steps"] = steps
