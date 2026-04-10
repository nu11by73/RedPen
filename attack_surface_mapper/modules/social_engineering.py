import requests
import re
from rich.console import Console

console = Console()


class SocialEngineeringRecon:
    def __init__(self, config):
        self.config = config
        self.results = {"email_addresses": [], "email_format": "", "employees": [], "data_breaches": [], "phishing_targets": [], "credential_leaks": [], "next_steps": [], "shadow_it_flags": []}

    def run(self, target_domain, company_name=None):
        console.print(f"\n[bold cyan]{'='*60}[/bold cyan]")
        console.print(f"[bold cyan]  Module 7: Social Engineering Recon - {target_domain}[/bold cyan]")
        console.print(f"[bold cyan]{'='*60}[/bold cyan]\n")
        self._hunter(target_domain)
        self._breaches(target_domain)
        self._phishing_targets()
        self._next_steps(target_domain)
        return self.results

    def _hunter(self, domain):
        console.print("[yellow][*] Hunter.io email search...[/yellow]")
        api_key = self.config.get("HUNTER_API_KEY", "")
        if not api_key:
            console.print("  [red][-] Hunter.io API key not set.[/red]")
            return
        try:
            resp = requests.get(f"https://api.hunter.io/v2/domain-search?domain={domain}&api_key={api_key}&limit=100", timeout=15)
            if resp.status_code == 200:
                data = resp.json().get("data", {})
                self.results["email_format"] = data.get("pattern", "Unknown")
                for e in data.get("emails", []):
                    self.results["email_addresses"].append({"email": e.get("value", ""), "type": e.get("type", ""), "confidence": e.get("confidence", 0), "first_name": e.get("first_name", ""), "last_name": e.get("last_name", ""), "position": e.get("position", "")})
                    self.results["employees"].append({"name": f"{e.get('first_name', '')} {e.get('last_name', '')}".strip(), "email": e.get("value", ""), "position": e.get("position", "")})
                console.print(f"  [green][+] Found {len(data.get('emails', []))} emails[/green]")
        except Exception as e:
            console.print(f"  [red][-] Hunter.io failed: {e}[/red]")

    def _breaches(self, domain):
        console.print("[yellow][*] Checking breach exposure...[/yellow]")
        api_key = self.config.get("HIBP_API_KEY", "")
        if not api_key:
            console.print("  [red][-] HIBP API key not set.[/red]")
            return
        try:
            resp = requests.get("https://haveibeenpwned.com/api/v3/breaches", headers={"hibp-api-key": api_key}, timeout=15)
            if resp.status_code == 200:
                for b in resp.json():
                    if domain.lower() in str(b.get("Domain", "")).lower():
                        self.results["data_breaches"].append({"name": b.get("Name"), "date": b.get("BreachDate"), "count": b.get("PwnCount"), "data_classes": b.get("DataClasses", [])})
                        console.print(f"  [bold red][!] BREACH: {b['Name']} ({b['BreachDate']})[/bold red]")
        except Exception:
            pass

    def _phishing_targets(self):
        console.print("[yellow][*] Identifying phishing targets...[/yellow]")
        hvp = ["ceo", "cfo", "cto", "ciso", "director", "vp", "manager", "admin"]
        for emp in self.results["employees"]:
            pos = emp.get("position", "").lower()
            if any(h in pos for h in hvp):
                self.results["phishing_targets"].append(emp)
                console.print(f"  [yellow][!] HVT: {emp['name']} - {emp.get('position')}[/yellow]")

    def _next_steps(self, domain):
        steps = []
        if self.results["email_addresses"]:
            steps.append({"action": "Email Breach Check", "description": f"Check {len(self.results['email_addresses'])} emails against breach DBs.", "priority": "HIGH"})
        if self.results["data_breaches"]:
            steps.append({"action": "Credential Stuffing Test", "description": f"{len(self.results['data_breaches'])} breaches found.", "priority": "CRITICAL"})
        if self.results["phishing_targets"]:
            steps.append({"action": "Phishing Simulation", "description": f"Target {len(self.results['phishing_targets'])} high-value employees.", "priority": "HIGH"})
        steps.append({"action": "MFA Verification", "description": "Verify MFA on all remote access.", "priority": "CRITICAL"})
        steps.append({"action": "Dark Web Monitoring", "description": f"Monitor {domain} on dark web.", "priority": "HIGH"})
        self.results["next_steps"] = steps
