import requests
import dns.resolver
import socket
import re
from rich.console import Console
from concurrent.futures import ThreadPoolExecutor, as_completed

console = Console()


class InternalInfraScanner:
    def __init__(self, config):
        self.config = config
        self.results = {"vpn_endpoints": [], "remote_access": [], "legacy_systems": [], "network_devices_exposed": [], "internal_leaks": [], "next_steps": [], "shadow_it_flags": []}

    def run(self, target_domain, subdomains=None, ip_data=None):
        console.print(f"\n[bold cyan]{'='*60}[/bold cyan]")
        console.print(f"[bold cyan]  Module 6: Internal Infrastructure - {target_domain}[/bold cyan]")
        console.print(f"[bold cyan]{'='*60}[/bold cyan]\n")
        self._resolve_all_prefixes(target_domain)
        self._legacy(target_domain, subdomains)
        self._internal_leaks(target_domain, subdomains)
        self._next_steps()
        return self.results

    def _resolve_all_prefixes(self, domain):
        """Batch all infrastructure DNS lookups into one threaded operation."""
        console.print("[yellow][*] Resolving infrastructure prefixes (threaded)...[/yellow]")

        prefix_map = {
            "vpn": "vpn", "ssl-vpn": "vpn", "sslvpn": "vpn",
            "remote": "vpn", "gateway": "vpn", "anyconnect": "vpn",
            "globalprotect": "vpn",
            "rdp": "remote_access", "rdweb": "remote_access",
            "citrix": "remote_access", "owa": "remote_access",
            "webmail": "remote_access", "bastion": "remote_access",
            "fw": "network", "firewall": "network", "router": "network",
            "switch": "network", "mgmt": "network", "waf": "network",
            "proxy": "network", "lb": "network",
        }
        service_names = {
            "rdp": "RDP", "rdweb": "RD Web", "citrix": "Citrix",
            "owa": "OWA", "webmail": "Webmail", "bastion": "Bastion",
        }

        def _resolve(prefix):
            target = f"{prefix}.{domain}"
            try:
                ip = socket.gethostbyname(target)
                return (prefix, target, ip)
            except socket.gaierror:
                return None

        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = {executor.submit(_resolve, p): p for p in prefix_map}
            for future in as_completed(futures):
                result = future.result()
                if result is None:
                    continue
                prefix, hostname, ip = result
                category = prefix_map[prefix]

                if category == "vpn":
                    self.results["vpn_endpoints"].append(
                        {"hostname": hostname, "ip": ip}
                    )
                    console.print(f"  [green][+] VPN: {hostname} -> {ip}[/green]")

                elif category == "remote_access":
                    svc = service_names.get(prefix, prefix.upper())
                    self.results["remote_access"].append(
                        {"hostname": hostname, "ip": ip, "service": svc}
                    )
                    console.print(f"  [green][+] {svc}: {hostname} -> {ip}[/green]")

                elif category == "network":
                    self.results["network_devices_exposed"].append(
                        {"hostname": hostname, "ip": ip}
                    )
                    self.results["shadow_it_flags"].append({
                        "type": "Exposed Network Device",
                        "asset": hostname,
                        "reason": "Network device resolves publicly.",
                    })
                    console.print(
                        f"  [yellow][!] Network device: {hostname} -> {ip}[/yellow]"
                    )

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
        console.print("[yellow][*] Detecting legacy systems (threaded)...[/yellow]")
        legacy_sigs = {
            "IIS/6": "Windows 2003 (EOL)",
            "IIS/7": "Windows 2008 (EOL)",
            "Apache/2.2": "Apache 2.2 (EOL)",
            "PHP/5": "PHP 5 (EOL)",
        }
        targets = [domain]
        if subdomains:
            for sub in subdomains[:20]:
                s = sub.get("subdomain", "") if isinstance(sub, dict) else sub
                if s:
                    targets.append(s)

        def _check(t):
            try:
                resp = requests.get(f"https://{t}", timeout=7, verify=False)
                server = resp.headers.get("Server", "") + resp.headers.get("X-Powered-By", "")
                hits = []
                for pat, desc in legacy_sigs.items():
                    if pat.lower() in server.lower():
                        hits.append({
                            "hostname": t, "indicator": pat, "description": desc
                        })
                return hits
            except Exception:
                return []

        with ThreadPoolExecutor(max_workers=10) as executor:
            for hits in executor.map(_check, targets):
                for hit in hits:
                    self.results["legacy_systems"].append(hit)
                    console.print(
                        f"  [bold red][!] Legacy: {hit['hostname']}"
                        f" - {hit['description']}[/bold red]"
                    )
                    self.results["shadow_it_flags"].append({
                        "type": "Legacy/EOL System",
                        "asset": hit["hostname"],
                        "reason": f"Running {hit['description']}.",
                    })

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
        console.print("[yellow][*] Checking internal leaks (threaded)...[/yellow]")
        targets = [domain]
        if subdomains:
            for sub in subdomains[:10]:
                s = sub.get("subdomain", "") if isinstance(sub, dict) else sub
                if s:
                    targets.append(s)
        leak_patterns = [
            (r'10\.\d{1,3}\.\d{1,3}\.\d{1,3}', "RFC1918 10.x"),
            (r'192\.168\.\d{1,3}\.\d{1,3}', "RFC1918 192.168.x"),
        ]

        def _check(t):
            found = []
            try:
                resp = requests.get(f"https://{t}", timeout=7, verify=False)
                haystack = resp.text + str(resp.headers)
                for pat, desc in leak_patterns:
                    matches = list(set(re.findall(pat, haystack)))
                    if matches:
                        found.append({
                            "hostname": t, "type": desc, "values": matches[:5]
                        })
            except Exception:
                pass
            return found

        with ThreadPoolExecutor(max_workers=10) as executor:
            for leak_list in executor.map(_check, targets):
                for leak in leak_list:
                    self.results["internal_leaks"].append(leak)
                    console.print(
                        f"  [yellow][!] Leak on {leak['hostname']}:"
                        f" {leak['type']}[/yellow]"
                    )

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
