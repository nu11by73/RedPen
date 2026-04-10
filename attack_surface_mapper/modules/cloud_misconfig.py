import requests
import time
import dns.resolver
from rich.console import Console

console = Console()


class CloudMisconfigScanner:
    def __init__(self, config):
        self.config = config
        self.results = {"s3_buckets": [], "azure_blobs": [], "gcp_buckets": [], "cloud_services_detected": [], "kubernetes_exposed": [], "next_steps": [], "shadow_it_flags": []}

    def run(self, target_domain, company_name=None, subdomains=None):
        console.print(f"\n[bold cyan]{'='*60}[/bold cyan]")
        console.print(f"[bold cyan]  Module 5: Cloud Misconfiguration - {target_domain}[/bold cyan]")
        console.print(f"[bold cyan]{'='*60}[/bold cyan]\n")
        names = self._bucket_names(target_domain, company_name)
        self._s3(names)
        self._azure(names)
        self._gcp(names)
        self._cloud_dns(target_domain, subdomains)
        self._k8s(target_domain)
        self._next_steps()
        return self.results

    def _bucket_names(self, domain, company=None):
        base = domain.split(".")[0]
        names = set()
        mods = ["", "-dev", "-staging", "-prod", "-test", "-backup", "-data", "-assets", "-static", "-logs", "-private"]
        for m in mods:
            names.add(f"{base}{m}")
            if m:
                names.add(f"{m.lstrip('-')}-{base}")
        if company:
            cc = company.lower().replace(" ", "-")
            for m in mods:
                names.add(f"{cc}{m}")
        names.discard("")
        return list(names)

    def _s3(self, names):
        console.print("[yellow][*] Checking S3 buckets...[/yellow]")
        for b in names:
            try:
                url = f"https://{b}.s3.amazonaws.com"
                r = requests.get(url, timeout=10)
                if r.status_code == 200:
                    self.results["s3_buckets"].append({"bucket": b, "url": url, "status": "PUBLIC_READ", "severity": "CRITICAL"})
                    console.print(f"  [bold red][!!!] PUBLIC S3: {url}[/bold red]")
                    self.results["shadow_it_flags"].append({"type": "Public Cloud Storage", "asset": url, "reason": f"S3 '{b}' publicly readable."})
                elif r.status_code == 403:
                    self.results["s3_buckets"].append({"bucket": b, "url": url, "status": "EXISTS", "severity": "INFO"})
                    console.print(f"  [green][+] S3 exists (403): {b}[/green]")
            except Exception:
                continue
            time.sleep(0.3)

    def _azure(self, names):
        console.print("[yellow][*] Checking Azure Blobs...[/yellow]")
        for n in names:
            try:
                url = f"https://{n}.blob.core.windows.net/?comp=list"
                r = requests.get(url, timeout=10)
                if r.status_code == 200 and "<EnumerationResults" in r.text:
                    self.results["azure_blobs"].append({"name": n, "url": url, "status": "PUBLIC_LIST", "severity": "CRITICAL"})
                    console.print(f"  [bold red][!!!] PUBLIC AZURE: {n}[/bold red]")
                    self.results["shadow_it_flags"].append({"type": "Public Cloud Storage", "asset": url, "reason": f"Azure '{n}' publicly listable."})
            except Exception:
                continue
            time.sleep(0.3)

    def _gcp(self, names):
        console.print("[yellow][*] Checking GCP buckets...[/yellow]")
        for n in names:
            try:
                url = f"https://storage.googleapis.com/{n}"
                r = requests.get(url, timeout=10)
                if r.status_code == 200:
                    self.results["gcp_buckets"].append({"bucket": n, "url": url, "status": "PUBLIC_READ", "severity": "CRITICAL"})
                    console.print(f"  [bold red][!!!] PUBLIC GCP: {url}[/bold red]")
            except Exception:
                continue
            time.sleep(0.3)

    def _cloud_dns(self, domain, subdomains=None):
        console.print("[yellow][*] Detecting cloud via DNS...[/yellow]")
        indicators = {"amazonaws.com": "AWS", "cloudfront.net": "CloudFront", "azurewebsites.net": "Azure", "googleapis.com": "GCP", "herokuapp.com": "Heroku"}
        targets = [domain]
        if subdomains:
            for sub in subdomains[:30]:
                s = sub.get("subdomain", "") if isinstance(sub, dict) else sub
                if s:
                    targets.append(s)
        resolver = dns.resolver.Resolver()
        for t in targets:
            try:
                for r in resolver.resolve(t, "CNAME"):
                    cname = str(r).lower()
                    for ind, svc in indicators.items():
                        if ind in cname:
                            self.results["cloud_services_detected"].append({"hostname": t, "cname": cname, "service": svc})
                            console.print(f"  [green][+] {t} -> {cname} ({svc})[/green]")
            except Exception:
                continue

    def _k8s(self, domain):
        console.print("[yellow][*] Checking Kubernetes...[/yellow]")
        for path in ["/api/v1", "/healthz", "/version"]:
            try:
                url = f"https://{domain}{path}"
                r = requests.get(url, timeout=8, verify=False)
                if r.status_code == 200 and "kubernetes" in r.text.lower():
                    self.results["kubernetes_exposed"].append({"url": url})
                    console.print(f"  [bold red][!!!] K8s: {url}[/bold red]")
                    self.results["shadow_it_flags"].append({"type": "Exposed K8s", "asset": url, "reason": "Kubernetes exposed to internet."})
            except Exception:
                continue

    def _next_steps(self):
        steps = []
        public = [b for b in self.results["s3_buckets"] if b["status"] == "PUBLIC_READ"]
        public += [b for b in self.results["azure_blobs"] if b["status"] == "PUBLIC_LIST"]
        public += [b for b in self.results["gcp_buckets"] if b["status"] == "PUBLIC_READ"]
        if public:
            steps.append({"action": "Secure Cloud Storage", "description": f"{len(public)} public storage containers.", "priority": "CRITICAL"})
        if self.results["kubernetes_exposed"]:
            steps.append({"action": "Secure Kubernetes", "description": "Restrict K8s behind VPN.", "priority": "CRITICAL"})
        steps.append({"action": "CSPM Scan", "description": "Run ScoutSuite/Prowler.", "command": "prowler aws --categories internet-exposed", "priority": "HIGH"})
        self.results["next_steps"] = steps
