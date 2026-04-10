import requests
import socket
from rich.console import Console

console = Console()


class PhysicalAssetScanner:
    def __init__(self, config):
        self.config = config
        self.results = {"exposed_devices": [], "mobile_apps": [], "byod_indicators": [], "next_steps": [], "shadow_it_flags": []}

    def run(self, target_domain, company_name=None, ip_data=None, shodan_data=None):
        console.print(f"\n[bold cyan]{'='*60}[/bold cyan]")
        console.print(f"[bold cyan]  Module 9: Physical Attack Points - {target_domain}[/bold cyan]")
        console.print(f"[bold cyan]{'='*60}[/bold cyan]\n")
        self._mobile_apps(company_name or target_domain.split(".")[0])
        self._exposed_devices(target_domain, shodan_data)
        self._byod(target_domain)
        self._next_steps()
        return self.results

    def _mobile_apps(self, company):
        console.print("[yellow][*] Checking mobile apps...[/yellow]")
        try:
            resp = requests.get(f"https://itunes.apple.com/search?term={requests.utils.quote(company)}&entity=software&limit=10", timeout=10)
            if resp.status_code == 200:
                for app in resp.json().get("results", []):
                    self.results["mobile_apps"].append({"platform": "iOS", "name": app.get("trackName"), "developer": app.get("sellerName"), "bundle_id": app.get("bundleId")})
                    console.print(f"  [green][+] iOS: {app.get('trackName')}[/green]")
        except Exception:
            pass

    def _exposed_devices(self, domain, shodan_data=None):
        console.print("[yellow][*] Checking exposed devices...[/yellow]")
        device_types = {"printer": "Printer", "camera": "Camera", "voip": "Phone", "nas": "NAS", "ups": "UPS"}
        if shodan_data:
            for ip, data in shodan_data.items():
                for svc in data.get("services", []):
                    banner = (svc.get("banner", "") + svc.get("product", "")).lower()
                    for kw, dtype in device_types.items():
                        if kw in banner:
                            self.results["exposed_devices"].append({"type": dtype, "ip": ip, "port": svc.get("port")})
                            console.print(f"  [red][!] Exposed {dtype}: {ip}:{svc.get('port')}[/red]")
                            self.results["shadow_it_flags"].append({"type": f"Exposed {dtype}", "asset": f"{ip}:{svc.get('port')}", "reason": "Physical device on internet."})
        for prefix in ["printer", "camera", "nas", "voip"]:
            try:
                ip = socket.gethostbyname(f"{prefix}.{domain}")
                self.results["exposed_devices"].append({"type": prefix, "hostname": f"{prefix}.{domain}", "ip": ip})
                console.print(f"  [yellow][!] {prefix}.{domain} -> {ip}[/yellow]")
            except Exception:
                pass

    def _byod(self, domain):
        console.print("[yellow][*] Checking MDM/BYOD...[/yellow]")
        for prefix in ["mdm", "intune", "jamf", "airwatch", "workspace"]:
            try:
                ip = socket.gethostbyname(f"{prefix}.{domain}")
                self.results["byod_indicators"].append({"type": "MDM", "hostname": f"{prefix}.{domain}", "ip": ip})
                console.print(f"  [green][+] MDM: {prefix}.{domain}[/green]")
            except Exception:
                pass

    def _next_steps(self):
        steps = []
        if self.results["exposed_devices"]:
            steps.append({"action": "Secure Devices", "description": f"{len(self.results['exposed_devices'])} devices exposed.", "priority": "CRITICAL"})
        if self.results["mobile_apps"]:
            steps.append({"action": "Mobile App Testing", "description": f"MAST on {len(self.results['mobile_apps'])} apps.", "priority": "HIGH"})
        steps.append({"action": "Wireless Audit", "description": "On-site wireless assessment.", "priority": "HIGH"})
        steps.append({"action": "Asset Inventory", "description": "Compare discovered vs inventory.", "priority": "HIGH"})
        self.results["next_steps"] = steps
