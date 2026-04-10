import requests
import re
import time
from rich.console import Console

console = Console()


class WebAppAPIScanner:
    def __init__(self, config):
        self.config = config
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": config["USER_AGENT"]})
        self.session.verify = False
        self.results = {"web_applications": [], "api_endpoints": [], "sensitive_files": [], "security_headers_missing": [], "technology_fingerprint": [], "open_source_code": [], "exposed_databases": [], "sql_injection_candidates": [], "next_steps": [], "shadow_it_flags": []}

    def run(self, target_domain, subdomains=None):
        console.print(f"\n[bold cyan]{'='*60}[/bold cyan]")
        console.print(f"[bold cyan]  Module 4: Web App & API Scan - {target_domain}[/bold cyan]")
        console.print(f"[bold cyan]{'='*60}[/bold cyan]\n")
        targets = [target_domain]
        if subdomains:
            for sub in subdomains[:30]:
                s = sub.get("subdomain", "") if isinstance(sub, dict) else sub
                if s and s not in targets:
                    targets.append(s)
        self._probe(targets)
        self._sensitive_files(targets)
        self._security_headers(targets)
        self._api_endpoints(targets)
        self._github_search(target_domain)
        self._exposed_dbs(target_domain, subdomains)
        self._next_steps()
        return self.results

    def _probe(self, targets):
        console.print("[yellow][*] Probing web services...[/yellow]")
        for h in targets:
            for scheme in ["https", "http"]:
                try:
                    url = f"{scheme}://{h}"
                    resp = self.session.get(url, timeout=10, allow_redirects=True)
                    title = ""
                    m = re.search(r'<title[^>]*>(.*?)</title>', resp.text, re.I | re.DOTALL)
                    if m:
                        title = m.group(1).strip()[:100]
                    self.results["web_applications"].append({"hostname": h, "url": url, "status_code": resp.status_code, "title": title, "server": resp.headers.get("Server", "")})
                    console.print(f"  [green][+] {url} [{resp.status_code}] {title}[/green]")
                    self._fingerprint(h, resp)
                    break
                except Exception:
                    continue

    def _sensitive_files(self, targets):
        console.print("[yellow][*] Checking sensitive files...[/yellow]")
        paths = {"/.env": ("Env Vars", "CRITICAL"), "/.git/HEAD": ("Git Repo", "CRITICAL"), "/.git/config": ("Git Config", "CRITICAL"), "/wp-config.php.bak": ("WP Config Backup", "CRITICAL"), "/backup.sql": ("SQL Backup", "CRITICAL"), "/.htpasswd": ("Apache Passwords", "CRITICAL"), "/phpinfo.php": ("PHP Info", "HIGH"), "/robots.txt": ("Robots.txt", "INFO"), "/swagger.json": ("Swagger", "MEDIUM"), "/graphql": ("GraphQL", "MEDIUM"), "/actuator/env": ("Spring Env", "CRITICAL"), "/docker-compose.yml": ("Docker Compose", "CRITICAL"), "/admin": ("Admin Panel", "MEDIUM"), "/wp-admin": ("WP Admin", "MEDIUM")}
        for h in targets[:15]:
            for path, (desc, sev) in paths.items():
                try:
                    url = f"https://{h}{path}"
                    resp = self.session.get(url, timeout=8, allow_redirects=False)
                    if resp.status_code == 200 and len(resp.content) > 0:
                        self.results["sensitive_files"].append({"hostname": h, "path": path, "url": url, "description": desc, "severity": sev})
                        console.print(f"  [bold red][!] [{sev}] {url} - {desc}[/bold red]")
                        if sev in ["CRITICAL", "HIGH"]:
                            self.results["shadow_it_flags"].append({"type": "Exposed Dev File", "asset": url, "reason": f"Sensitive file '{path}' exposed. Non-standard deployment."})
                except Exception:
                    continue
                time.sleep(0.2)

    def _security_headers(self, targets):
        console.print("[yellow][*] Checking security headers...[/yellow]")
        required = {"Strict-Transport-Security": "No HSTS", "Content-Security-Policy": "No CSP", "X-Frame-Options": "Clickjacking risk", "X-Content-Type-Options": "MIME sniffing risk"}
        for h in targets[:10]:
            try:
                resp = self.session.get(f"https://{h}", timeout=10)
                missing = [{"header": hdr, "issue": desc} for hdr, desc in required.items() if hdr not in resp.headers]
                if missing:
                    self.results["security_headers_missing"].append({"hostname": h, "missing_headers": missing})
                    console.print(f"  [yellow][!] {h}: Missing {len(missing)} headers[/yellow]")
            except Exception:
                continue

    def _api_endpoints(self, targets):
        console.print("[yellow][*] Discovering APIs...[/yellow]")
        api_paths = ["/api", "/api/v1", "/api/v2", "/rest", "/graphql", "/swagger.json", "/openapi.json", "/api-docs", "/v1", "/v2", "/health", "/metrics"]
        for h in targets[:10]:
            for path in api_paths:
                try:
                    url = f"https://{h}{path}"
                    resp = self.session.get(url, timeout=8, allow_redirects=False)
                    ct = resp.headers.get("Content-Type", "")
                    if resp.status_code in [200, 401, 403] and ("json" in ct or "xml" in ct or resp.status_code in [401, 403]):
                        auth = "Requires Auth" if resp.status_code in [401, 403] else "Open"
                        self.results["api_endpoints"].append({"hostname": h, "path": path, "url": url, "status_code": resp.status_code, "auth": auth})
                        console.print(f"  [green][+] API: {url} [{resp.status_code}] ({auth})[/green]")
                except Exception:
                    continue

    def _fingerprint(self, hostname, resp):
        indicators = {"WordPress": ["/wp-content/"], "React": ["__NEXT_DATA__", "_reactRoot"], "Angular": ["ng-app"], "ASP.NET": ["__VIEWSTATE"], "Spring Boot": ["actuator"], "Laravel": ["laravel_session"]}
        content = resp.text.lower() + str(resp.headers).lower()
        for tech, patterns in indicators.items():
            for p in patterns:
                if p.lower() in content:
                    self.results["technology_fingerprint"].append({"hostname": hostname, "technology": tech})
                    console.print(f"      [cyan][*] Tech: {tech}[/cyan]")
                    break

    def _github_search(self, domain):
        console.print("[yellow][*] GitHub code search...[/yellow]")
        token = self.config.get("GITHUB_TOKEN", "")
        headers = {"Accept": "application/vnd.github.v3+json"}
        if token:
            headers["Authorization"] = f"token {token}"
        for query in [f'"{domain}" password', f'"{domain}" api_key', f'"{domain}" secret']:
            try:
                resp = requests.get(f"https://api.github.com/search/code?q={query}&per_page=5", headers=headers, timeout=15)
                if resp.status_code == 200:
                    total = resp.json().get("total_count", 0)
                    if total > 0:
                        console.print(f"  [bold red][!] GitHub: '{query}' = {total} results[/bold red]")
                        for item in resp.json().get("items", [])[:3]:
                            self.results["open_source_code"].append({"query": query, "repo": item.get("repository", {}).get("full_name", ""), "file": item.get("path", ""), "url": item.get("html_url", "")})
                            self.results["shadow_it_flags"].append({"type": "Code Leak", "asset": item.get("html_url", ""), "reason": f"GitHub: '{query}' matched."})
                elif resp.status_code == 403:
                    console.print("  [red][-] GitHub rate limited.[/red]")
                    break
                time.sleep(2)
            except Exception:
                pass

    def _exposed_dbs(self, domain, subdomains):
        console.print("[yellow][*] Checking exposed databases...[/yellow]")
        db_paths = {"phpMyAdmin": ["/phpmyadmin/"], "Adminer": ["/adminer.php"]}
        targets = [domain]
        if subdomains:
            for sub in subdomains[:10]:
                s = sub.get("subdomain", "") if isinstance(sub, dict) else sub
                if s:
                    targets.append(s)
        for t in targets:
            for db, paths in db_paths.items():
                for p in paths:
                    try:
                        url = f"https://{t}{p}"
                        resp = self.session.get(url, timeout=8, allow_redirects=False)
                        if resp.status_code in [200, 301, 302, 401]:
                            self.results["exposed_databases"].append({"type": db, "url": url})
                            console.print(f"  [bold red][!] {db}: {url}[/bold red]")
                            self.results["shadow_it_flags"].append({"type": "Exposed Database", "asset": url, "reason": f"{db} publicly accessible."})
                    except Exception:
                        continue

    def _next_steps(self):
        steps = []
        if self.results["sensitive_files"]:
            steps.append({"action": "Secure Exposed Files", "description": f"{len(self.results['sensitive_files'])} sensitive files found.", "priority": "CRITICAL"})
        if self.results["open_source_code"]:
            steps.append({"action": "Rotate Leaked Secrets", "description": f"{len(self.results['open_source_code'])} code leaks found on GitHub.", "priority": "CRITICAL"})
        if self.results["exposed_databases"]:
            steps.append({"action": "Restrict DB Access", "description": f"{len(self.results['exposed_databases'])} database UIs exposed.", "priority": "CRITICAL"})
        if self.results["api_endpoints"]:
            steps.append({"action": "API Security Assessment", "description": f"Test {len(self.results['api_endpoints'])} API endpoints.", "priority": "HIGH"})
        steps.append({"action": "Full DAST Scan", "description": "Run OWASP ZAP or Burp Suite.", "command": "zap-cli quick-scan -s xss,sqli <target>", "priority": "HIGH"})
        self.results["next_steps"] = steps
