import requests
import dns.resolver
import socket
import re
from rich.console import Console

console = Console()


class InternalInfraScanner:
    def __init__(self, config):
        self.config = config
        self.results = {"vpn_endpoints": [], "remote_access": [], "legacy_systems": [], "network_devices_exposed": [], "internal_leaks": [], "next_steps": [], "shadow_it_flags": []}

    def run(self, target_domain, subdomains=None, ip_data=None):
        console.print(f"\n[bold cyan]{'='*60}[/bold cyan]")
        console.print(f"[bold cyan]  Module 6: Internal Infrastructure - {target_domain}[/bold cyan]")
        console.print(f"[bold cyan]{'='*60}[/bold cyan]\n")
        self._vpn(target_domain)
        self._remote(target_domain)
        self._legacy(target_domain, subdomains)
        self._network_devices(target_domain)
        self._internal_leaks(target_domain, subdomains)
        self._next_steps()
        return self.results

    def _vpn(self, domain):
        console.print("[yellow][*] Finding VPN endpoints...[/yellow]")
        for prefix in ["vpn", "ssl-vpn", "sslvpn", "remote", "gateway", "anyconnect", "globalprotect"]:
            target = f"{prefix}.{domain}"
            try:
                ip = socket.gethostbyname(target)
                self.results["vpn_endpoints"].append({"hostname": target, "ip": ip})
                console.print(f"  [green][+] VPN: {target} -> {ip}[/green]")
            except socket.gaierror:
                pass

    def _remote(self, domain):
        console.print("[yellow][*] Finding remote access...[/yellow]")
        for prefix, svc in {"rdp": "RDP", "rdweb": "RD Web", "citrix": "Citrix", "owa": "OWA", "webmail": "Webmail", "bastion": "Bastion"}.items():
            target = f"{prefix}.{domain}"
            try:
                ip = socket.gethostbyname(target)
                self.results["remote_access"].append({"hostname": target, "ip": ip, "service": svc})
                console.print(f"  [green][+] {svc}: {target} -> {ip}[/green]")
            except socket.gaierror:
                pass

    def _legacy(self, domain, subdomains=None):
        console.print("[yellow][*] Detecting legacy systems...[/yellow]")
        legacy = {"IIS/6": "Windows 2003 (EOL)", "IIS/7": "Windows 2008 (EOL)", "Apache/2.2": "Apache 2.2 (EOL)", "PHP/5": "PHP 5 (EOL)"}
        targets = [domain]
        if subdomains:
            for sub in subdomains[:20]:
                s = sub.get("subdomain", "") if isinstance(sub, dict) else sub
                if s:
                    targets.append(s)
        for t in targets:
            try:
                resp = requests.get(f"https://{t}", timeout=10, verify=False)
                server = resp.headers.get("Server", "") + resp.headers.get("X-Powered-By", "")
                for pat, desc in legacy.items():
                    if pat.lower() in server.lower():
                        self.results["legacy_systems"].append({"hostname": t, "indicator": pat, "description": desc})
                        console.print(f"  [bold red][!] Legacy: {t} - {desc}[/bold red]")
                        self.results["shadow_it_flags"].append({"type": "Legacy/EOL System", "asset": t, "reason": f"Running {desc}."})
            except Exception:
                continue

    def _network_devices(self, domain):
        console.print("[yellow][*] Checking network devices...[/yellow]")
        for prefix in ["fw", "firewall", "router", "switch", "mgmt", "waf", "proxy", "lb"]:
            target = f"{prefix}.{domain}"
            try:
                ip = socket.gethostbyname(target)
                self.results["network_devices_exposed"].append({"hostname": target, "ip": ip})
                console.print(f"  [yellow][!] Network device: {target} -> {ip}[/yellow]")
                self.results["shadow_it_flags"].append({"type": "Exposed Network Device", "asset": target, "reason": "Network device resolves publicly."})
            except socket.gaierror:
                pass

    def _internal_leaks(self, domain, subdomains=None):
        console.print("[yellow][*] Checking internal leaks...[/yellow]")
        targets = [domain]
        if subdomains:
            for sub in subdomains[:10]:
                s = sub.get("subdomain", "") if isinstance(sub, dict) else sub
                if s:
                    targets.append(s)
        patterns = [(r'10\.\d{1,3}\.\d{1,3}\.\d{1,3}', "RFC1918 10.x"), (r'192\.168\.\d{1,3}\.\d{1,3}', "RFC1918 192.168.x")]
        for t in targets:
            try:
                resp = requests.get(f"https://{t}", timeout=10, verify=False)
                for pat, desc in patterns:
                    matches = list(set(re.findall(pat, resp.text + str(resp.headers))))
                    if matches:
                        self.results["internal_leaks"].append({"hostname": t, "type": desc, "values": matches[:5]})
                        console.print(f"  [yellow][!] Leak on {t}: {desc}[/yellow]")
            except Exception:
                continue

    def _next_steps(self):
        steps = []
        if self.results["vpn_endpoints"]:
            steps.append({"action": "VPN Security Assessment", "description": f"Test {len(self.results['vpn_endpoints'])} VPN endpoints.", "priority": "HIGH"})
        if self.results["legacy_systems"]:
            steps.append({"action": "Legacy Remediation", "description": f"{len(self.results['legacy_systems'])} EOL systems.", "priority": "CRITICAL"})
        if self.results["network_devices_exposed"]:
            steps.append({"action": "Restrict Network Devices", "description": "Remove public DNS for management interfaces.", "priority": "CRITICAL"})
        steps.append({"action": "Segmentation Review", "description": "Review lateral movement controls.", "priority": "HIGH"})
        self.results["next_steps"] = steps
