import requests
import re
import time
import json
import signal
from urllib.parse import urljoin, urlparse
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

console = Console()


class TimeoutException(Exception):
    pass


class SecretScanner:
    def __init__(self, config):
        self.config = config
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": config["USER_AGENT"]})
        self.session.verify = False
        self.results = {
            "secrets_found": [],
            "api_keys_found": [],
            "hardcoded_passwords": [],
            "exposed_tokens": [],
            "js_files_scanned": [],
            "api_endpoints_found": [],
            "env_files": [],
            "config_leaks": [],
            "next_steps": [],
            "shadow_it_flags": [],
        }
        self.scanned_urls = set()
        self.js_urls = set()
        self.dead_hosts = set()
        self.slow_hosts = set()

        # Tunable limits
        self.MAX_SUBDOMAINS = 25
        self.MAX_API_PATHS_PER_HOST = 40
        self.MAX_JS_FILES = 50
        self.MAX_SENSITIVE_PATHS_PER_HOST = 20
        self.HOST_TIMEOUT = 5
        self.HOST_FAIL_THRESHOLD = 3
        self.MODULE_TIMEOUT = 300  # 5 minute max for entire module

        self.host_fail_count = {}
        self.module_start = None

        self.secret_patterns = {
            "AWS Access Key": r'AKIA[0-9A-Z]{16}',
            "AWS Secret Key": r'(?i)aws[_\-]?secret[_\-]?access[_\-]?key[\s]*[=:]\s*["\']?([A-Za-z0-9/+=]{40})["\']?',
            "AWS MWS Key": r'amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
            "Azure Storage Key": r'(?i)(?:DefaultEndpointsProtocol|AccountKey)\s*=\s*[^\s;]{20,}',
            "Azure Client Secret": r'(?i)azure[_\-]?(?:client[_\-]?secret|tenant)[_\-]?(?:id|key)?\s*[=:]\s*["\']?([a-zA-Z0-9\-_.~]{20,})["\']?',
            "GCP API Key": r'AIza[0-9A-Za-z\-_]{35}',
            "GCP Service Account": r'"type"\s*:\s*"service_account"',
            "GCP OAuth": r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com',
            "Google OAuth Token": r'ya29\.[0-9A-Za-z\-_]+',
            "Firebase URL": r'https://[a-z0-9\-]+\.firebaseio\.com',
            "Slack Token": r'xox[bpors]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*',
            "Slack Webhook": r'https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+',
            "GitHub Token": r'gh[pousr]_[A-Za-z0-9_]{36,255}',
            "GitLab Token": r'glpat-[A-Za-z0-9\-]{20,}',
            "Stripe Secret Key": r'sk_live_[0-9a-zA-Z]{24,}',
            "Stripe Publishable Key": r'pk_live_[0-9a-zA-Z]{24,}',
            "Square Access Token": r'sq0atp-[0-9A-Za-z\-_]{22}',
            "PayPal Braintree Token": r'access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}',
            "Twilio API Key": r'SK[0-9a-fA-F]{32}',
            "Twilio Account SID": r'AC[a-zA-Z0-9_\-]{32}',
            "SendGrid API Key": r'SG\.[a-zA-Z0-9\-_]{22}\.[a-zA-Z0-9\-_]{43}',
            "Mailgun API Key": r'key-[0-9a-zA-Z]{32}',
            "Mailchimp API Key": r'[0-9a-f]{32}-us[0-9]{1,2}',
            "Shopify Token": r'shpat_[a-fA-F0-9]{32}',
            "Dropbox Token": r'(?:sl\.[A-Za-z0-9\-_]{100,})',
            "Discord Bot Token": r'[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27}',
            "Discord Webhook": r'https://discord(?:app)?\.com/api/webhooks/\d+/[\w\-]+',
            "Telegram Bot Token": r'[0-9]+:AA[0-9A-Za-z\-_]{33}',
            "Twitter Bearer Token": r'AAAAAAAAAAAAAAAAAAAAA[a-zA-Z0-9%]+',
            "Facebook Access Token": r'EAACEdEose0cBA[0-9A-Za-z]+',
            "New Relic Key": r'NRAK-[A-Z0-9]{27}',
            "Sentry DSN": r'https://[a-f0-9]{32}@[a-z0-9\-\.]+\.ingest\.sentry\.io/[0-9]+',
            "Mapbox Token": r'pk\.eyJ1[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+',
            "Basic Auth Header": r'(?i)authorization:\s*basic\s+[A-Za-z0-9+/=]{10,}',
            "Bearer Token": r'(?i)(?:authorization:\s*bearer|bearer[_\-]?token)\s*[=:]\s*["\']?([A-Za-z0-9\-_\.]{20,})["\']?',
            "JWT Token": r'eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+',
            "Generic API Key": r'(?i)(?:api[_\-]?key|apikey|api[_\-]?secret)\s*[=:]\s*["\']?([a-zA-Z0-9\-_]{16,64})["\']?',
            "Generic Secret": r'(?i)(?:secret[_\-]?key|client[_\-]?secret|app[_\-]?secret)\s*[=:]\s*["\']?([a-zA-Z0-9\-_]{16,64})["\']?',
            "Generic Token": r'(?i)(?:access[_\-]?token|auth[_\-]?token|session[_\-]?token)\s*[=:]\s*["\']?([a-zA-Z0-9\-_\.]{20,})["\']?',
            "Private Key": r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----',
            "PGP Private Key": r'-----BEGIN PGP PRIVATE KEY BLOCK-----',
            "MySQL Connection": r'(?i)mysql://[^\s<>"\']+',
            "PostgreSQL Connection": r'(?i)postgres(?:ql)?://[^\s<>"\']+',
            "MongoDB Connection": r'mongodb(?:\+srv)?://[^\s<>"\']+',
            "Redis Connection": r'redis://[^\s<>"\']+',
            "JDBC Connection": r'jdbc:[a-z]+://[^\s<>"\']+',
            "FTP Credentials": r'ftp://[^\s@]+:[^\s@]+@[^\s<>"\']+',
            "SMTP Credentials": r'(?i)smtp://[^\s@]+:[^\s@]+@[^\s<>"\']+',
            "Hardcoded Password": r'(?i)(?:password|passwd|pwd|pass)\s*[=:]\s*["\']([^"\']{6,64})["\']',
            "Database Password": r'(?i)(?:db[_\-]?password|database[_\-]?password|db[_\-]?pass)\s*[=:]\s*["\']?([^\s"\']{4,})["\']?',
            "Admin Password": r'(?i)(?:admin[_\-]?password|admin[_\-]?pass|root[_\-]?password)\s*[=:]\s*["\']?([^\s"\']{4,})["\']?',
            "Default Credentials": r'(?i)(?:admin|root|test|guest|demo)[\s]*[:/][\s]*(?:admin|root|password|test|guest|demo|12345|changeme)',
            "Internal URL": r'https?://(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|localhost)[:/][\w\-/.?=&]*',
        }

        self.api_paths = [
            "/api", "/api/v1", "/api/v2", "/api/v3",
            "/rest", "/rest/v1", "/rest/v2",
            "/graphql", "/graphiql", "/playground",
            "/swagger.json", "/swagger.yaml", "/swagger-ui.html",
            "/openapi.json", "/openapi.yaml",
            "/api-docs", "/api-docs.json",
            "/docs", "/redoc",
            "/health", "/healthz", "/healthcheck",
            "/status", "/status.json", "/server-status", "/server-info",
            "/metrics", "/prometheus/metrics",
            "/info", "/version",
            "/auth", "/auth/login", "/auth/token",
            "/oauth/token", "/oauth/authorize",
            "/login", "/token",
            "/.well-known/openid-configuration",
            "/.well-known/jwks.json",
            "/api/users", "/api/v1/users", "/api/me",
            "/admin", "/admin/api", "/console", "/dashboard",
            "/internal", "/internal/api",
            "/debug", "/debug/vars",
            "/actuator", "/actuator/env", "/actuator/health",
            "/actuator/info", "/actuator/configprops",
            "/actuator/mappings", "/actuator/heapdump",
            "/env", "/beans", "/configprops", "/mappings",
            "/telescope", "/horizon",
            "/.env", "/.env.local", "/.env.production",
            "/.env.staging", "/.env.backup",
            "/config.json", "/config.yaml",
            "/settings.json",
            "/.git/HEAD", "/.git/config",
            "/.gitignore",
            "/.svn/entries",
            "/docker-compose.yml",
            "/wp-config.php.bak", "/wp-config.php.old",
            "/application.properties", "/application.yml",
            "/appsettings.json",
            "/phpinfo.php", "/info.php",
            "/backup.sql", "/dump.sql",
            "/backup.zip", "/site.zip",
            "/robots.txt", "/sitemap.xml",
            "/.well-known/security.txt",
            "/elasticsearch/", "/_search", "/_cat/indices",
            "/solr/admin/",
            "/_all_dbs", "/_utils",
            "/phpmyadmin/", "/adminer.php",
            "/webhook", "/webhooks",
            "/graphql?query={__schema{types{name}}}",
        ]

    def _is_timed_out(self):
        """Check if module has exceeded total timeout"""
        if self.module_start and (time.time() - self.module_start) > self.MODULE_TIMEOUT:
            return True
        return False

    def _is_host_dead(self, host):
        """Check if host should be skipped"""
        base = host.split(":")[0]
        if base in self.dead_hosts or base in self.slow_hosts:
            return True
        return False

    def _record_host_fail(self, host):
        """Track failures per host, mark dead after threshold"""
        base = host.split(":")[0]
        self.host_fail_count[base] = self.host_fail_count.get(base, 0) + 1
        if self.host_fail_count[base] >= self.HOST_FAIL_THRESHOLD:
            self.dead_hosts.add(base)
            console.print(f"    [dim]Skipping {base} (too many failures)[/dim]")

    def _safe_request(self, url, method="get", timeout=None):
        """Make a request with timeout and host tracking"""
        if timeout is None:
            timeout = self.HOST_TIMEOUT

        parsed = urlparse(url)
        host = parsed.hostname or ""

        if self._is_host_dead(host):
            return None
        if self._is_timed_out():
            return None

        try:
            if method == "head":
                resp = self.session.head(url, timeout=timeout, allow_redirects=False)
            else:
                resp = self.session.get(url, timeout=timeout, allow_redirects=True)
            return resp
        except requests.exceptions.ConnectTimeout:
            self.slow_hosts.add(host)
            return None
        except requests.exceptions.ReadTimeout:
            self._record_host_fail(host)
            return None
        except requests.exceptions.ConnectionError:
            self._record_host_fail(host)
            return None
        except Exception:
            self._record_host_fail(host)
            return None

    def run(self, target_domain, subdomains=None, web_app_data=None):
        console.print(f"\n[bold cyan]{'='*60}[/bold cyan]")
        console.print(f"[bold cyan]  Module 10: Secret & API Key Scanner - {target_domain}[/bold cyan]")
        console.print(f"[bold cyan]{'='*60}[/bold cyan]\n")

        self.module_start = time.time()

        # Build target list
        targets = [target_domain]
        if subdomains:
            for sub in subdomains:
                s = sub.get("subdomain", "") if isinstance(sub, dict) else sub
                if s and s not in targets:
                    targets.append(s)

        # Limit targets
        if len(targets) > self.MAX_SUBDOMAINS:
            console.print(f"[yellow][!] Limiting to {self.MAX_SUBDOMAINS} of {len(targets)} subdomains[/yellow]")
            targets = targets[:self.MAX_SUBDOMAINS]

        console.print(f"[yellow][*] Scanning {len(targets)} targets (timeout: {self.MODULE_TIMEOUT}s)[/yellow]\n")

        # Phase 1: Probe which hosts are alive first
        live_targets = self._probe_hosts(targets)

        if not live_targets:
            console.print("[red][-] No live hosts found. Skipping secret scan.[/red]")
            self._generate_summary()
            return self.results

        # Phase 2: Scan pages for secrets
        if not self._is_timed_out():
            self._scan_pages(live_targets)

        # Phase 3: Find and scan JS files
        if not self._is_timed_out():
            self._find_js_files(live_targets)
            self._scan_js_files()

        # Phase 4: Check sensitive file paths
        if not self._is_timed_out():
            self._check_sensitive_paths(live_targets)

        # Phase 5: Discover API endpoints
        if not self._is_timed_out():
            self._discover_apis(live_targets)

        # Phase 6: Check env files
        if not self._is_timed_out():
            self._check_env_files(live_targets)

        if self._is_timed_out():
            elapsed = int(time.time() - self.module_start)
            console.print(f"\n[yellow][!] Module timeout reached ({elapsed}s). Partial results below.[/yellow]")

        self._generate_summary()
        self._next_steps()

        elapsed = int(time.time() - self.module_start)
        console.print(f"\n[cyan]  Secret scanner completed in {elapsed}s[/cyan]")
        console.print(f"[cyan]  Hosts scanned: {len(live_targets)} | Dead/skipped: {len(self.dead_hosts)} | Slow: {len(self.slow_hosts)}[/cyan]")

        return self.results

    def _probe_hosts(self, targets):
        """Quick probe to find which hosts are actually alive"""
        console.print("[yellow][*] Phase 0: Probing host availability...[/yellow]")
        live = []

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("{task.completed}/{task.total}"),
            console=console,
        ) as progress:
            task = progress.add_task("Probing hosts", total=len(targets))

            for host in targets:
                if self._is_timed_out():
                    break

                progress.update(task, description=f"Probing {host[:30]}")

                alive = False
                for scheme in ["https", "http"]:
                    try:
                        resp = self.session.head(
                            f"{scheme}://{host}",
                            timeout=3,
                            allow_redirects=False,
                        )
                        if resp.status_code < 600:
                            alive = True
                            break
                    except Exception:
                        continue

                if alive:
                    live.append(host)
                else:
                    self.dead_hosts.add(host)

                progress.advance(task)

        console.print(f"  [green][+] {len(live)} live hosts, {len(self.dead_hosts)} dead[/green]")
        return live

    def _scan_pages(self, targets):
        console.print("[yellow][*] Phase 1: Scanning web pages for secrets...[/yellow]")
        for host in targets:
            if self._is_timed_out():
                break
            for scheme in ["https", "http"]:
                url = f"{scheme}://{host}"
                if url in self.scanned_urls:
                    continue
                resp = self._safe_request(url, timeout=8)
                if resp and resp.status_code == 200:
                    self.scanned_urls.add(url)
                    self._scan_content(resp.text, url, "HTML Page")
                    self._scan_headers(resp.headers, url)
                    break

    def _find_js_files(self, targets):
        console.print("[yellow][*] Phase 2: Discovering JavaScript files...[/yellow]")
        js_patterns = [
            r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']',
            r'["\']([^"\']*\.(?:js|min\.js|bundle\.js|chunk\.js)[^"\']*)["\']',
        ]

        for host in targets[:15]:
            if self._is_timed_out():
                break
            for scheme in ["https", "http"]:
                resp = self._safe_request(f"{scheme}://{host}", timeout=8)
                if resp and resp.status_code == 200:
                    for pattern in js_patterns:
                        matches = re.findall(pattern, resp.text, re.I)
                        for js_path in matches[:20]:
                            js_url = self._resolve_url(f"{scheme}://{host}", js_path)
                            if js_url and js_url not in self.js_urls:
                                self.js_urls.add(js_url)
                                if len(self.js_urls) >= self.MAX_JS_FILES:
                                    break
                    break

        console.print(f"  [green][+] Found {len(self.js_urls)} JavaScript URLs[/green]")

    def _scan_js_files(self):
        if not self.js_urls:
            return
        console.print(f"[yellow][*] Scanning {len(self.js_urls)} JavaScript files...[/yellow]")

        scanned = 0
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("{task.completed}/{task.total}"),
            console=console,
        ) as progress:
            task = progress.add_task("Scanning JS", total=len(self.js_urls))

            for js_url in self.js_urls:
                if self._is_timed_out():
                    break

                progress.update(task, description=f"JS: {js_url[:40]}")
                resp = self._safe_request(js_url, timeout=6)

                if resp and resp.status_code == 200 and len(resp.text) > 0:
                    ct = resp.headers.get("Content-Type", "")
                    if "javascript" in ct or "text" in ct or js_url.endswith(".js"):
                        secrets_found = self._scan_content(resp.text, js_url, "JavaScript")
                        self.results["js_files_scanned"].append({
                            "url": js_url,
                            "size": len(resp.text),
                            "secrets_count": secrets_found,
                        })
                        if secrets_found > 0:
                            console.print(f"\n  [bold red][!] {js_url}: {secrets_found} secrets[/bold red]")
                        scanned += 1

                progress.advance(task)

        console.print(f"  [green][+] Scanned {scanned} JS files[/green]")

    def _check_sensitive_paths(self, targets):
        console.print("[yellow][*] Phase 3: Checking sensitive file paths...[/yellow]")
        sensitive_paths = [
            "/.env", "/.env.local", "/.env.production", "/.env.backup",
            "/.git/HEAD", "/.git/config",
            "/config.json", "/config.yaml", "/settings.json",
            "/wp-config.php.bak", "/wp-config.php.old",
            "/application.properties", "/application.yml",
            "/appsettings.json", "/appsettings.Development.json",
            "/docker-compose.yml",
            "/phpinfo.php", "/info.php",
            "/server-status", "/server-info",
            "/backup.sql", "/dump.sql",
            "/.htpasswd", "/web.config",
            "/.DS_Store", "/crossdomain.xml",
            "/.well-known/security.txt",
        ]

        for host in targets[:15]:
            if self._is_timed_out() or self._is_host_dead(host):
                continue

            checked = 0
            for path in sensitive_paths:
                if checked >= self.MAX_SENSITIVE_PATHS_PER_HOST:
                    break
                if self._is_timed_out() or self._is_host_dead(host):
                    break

                url = f"https://{host}{path}"
                resp = self._safe_request(url, timeout=5)
                checked += 1

                if resp and resp.status_code == 200 and len(resp.content) > 10:
                    if not self._is_error_page(resp.text):
                        self._scan_content(resp.text, url, f"Sensitive File ({path})")
                        self.results["config_leaks"].append({
                            "hostname": host,
                            "path": path,
                            "url": url,
                            "size": len(resp.content),
                            "content_preview": resp.text[:200].replace("\n", " "),
                        })
                        console.print(f"  [bold red][!!!] EXPOSED: {url} ({len(resp.content)} bytes)[/bold red]")
                        self.results["shadow_it_flags"].append({
                            "type": "Exposed Sensitive File",
                            "asset": url,
                            "reason": f"Sensitive file '{path}' is publicly accessible.",
                        })

    def _discover_apis(self, targets):
        console.print("[yellow][*] Phase 4: Discovering API endpoints...[/yellow]")

        total_checks = len(targets[:15]) * min(len(self.api_paths), self.MAX_API_PATHS_PER_HOST)

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("{task.completed}/{task.total}"),
            console=console,
        ) as progress:
            task = progress.add_task("API Discovery", total=total_checks)

            for host in targets[:15]:
                if self._is_timed_out() or self._is_host_dead(host):
                    progress.advance(task, min(len(self.api_paths), self.MAX_API_PATHS_PER_HOST))
                    continue

                host_found = 0
                checked = 0

                for path in self.api_paths:
                    if checked >= self.MAX_API_PATHS_PER_HOST:
                        break
                    if self._is_timed_out() or self._is_host_dead(host):
                        break

                    progress.update(task, description=f"{host[:25]}{path[:20]}")
                    url = f"https://{host}{path}"
                    resp = self._safe_request(url, timeout=5)
                    checked += 1

                    if resp:
                        ct = resp.headers.get("Content-Type", "")
                        is_api = False

                        if resp.status_code == 200:
                            if "json" in ct or "xml" in ct or "yaml" in ct:
                                is_api = True
                            elif resp.text.strip()[:1] in ("{", "["):
                                is_api = True
                            elif path in ["/.git/HEAD", "/.env"] and len(resp.text) > 0:
                                is_api = True
                        elif resp.status_code in [401, 403]:
                            is_api = True

                        if is_api:
                            auth = "Open" if resp.status_code == 200 else "Auth Required"
                            entry = {
                                "hostname": host,
                                "path": path,
                                "url": url,
                                "status_code": resp.status_code,
                                "content_type": ct,
                                "auth": auth,
                                "response_size": len(resp.content),
                            }
                            self.results["api_endpoints_found"].append(entry)
                            host_found += 1

                            color = "bold red" if auth == "Open" else "yellow"
                            console.print(f"\n  [{color}][+] {url} [{resp.status_code}] ({auth})[/{color}]")

                            if resp.status_code == 200:
                                self._scan_content(resp.text, url, "API Response")
                                try:
                                    data = resp.json()
                                    self._check_json_secrets(data, url)
                                except (json.JSONDecodeError, ValueError):
                                    pass

                    progress.advance(task)

                if host_found > 0:
                    console.print(f"  [cyan]  {host}: {host_found} endpoints[/cyan]")

    def _check_env_files(self, targets):
        console.print("[yellow][*] Phase 5: Checking environment files...[/yellow]")
        env_paths = ["/.env", "/.env.local", "/.env.production", "/.env.staging", "/.env.backup"]

        for host in targets[:15]:
            if self._is_timed_out() or self._is_host_dead(host):
                continue

            for path in env_paths:
                url = f"https://{host}{path}"
                if url in self.scanned_urls:
                    continue

                resp = self._safe_request(url, timeout=5)
                self.scanned_urls.add(url)

                if resp and resp.status_code == 200 and len(resp.text) > 5:
                    env_pattern = r'^[A-Z][A-Z0-9_]+=.+'
                    if re.search(env_pattern, resp.text, re.MULTILINE):
                        console.print(f"  [bold red][!!!] ENV FILE EXPOSED: {url}[/bold red]")
                        for line in resp.text.split("\n"):
                            line = line.strip()
                            if "=" in line and not line.startswith("#"):
                                key, _, value = line.partition("=")
                                key = key.strip()
                                value = value.strip().strip("'\"")
                                sensitive_keys = [
                                    "KEY", "SECRET", "TOKEN", "PASSWORD", "PASS",
                                    "AUTH", "CREDENTIAL", "DATABASE_URL", "DB_",
                                    "AWS_", "AZURE_", "GCP_", "STRIPE_", "TWILIO_",
                                    "SENDGRID_", "MAILGUN_", "SLACK_", "GITHUB_",
                                    "API", "PRIVATE", "ENCRYPTION",
                                ]
                                if any(sk in key.upper() for sk in sensitive_keys) and value:
                                    self.results["env_files"].append({
                                        "url": url,
                                        "key": key,
                                        "value_preview": value[:4] + "****" + value[-2:] if len(value) > 6 else "****",
                                        "severity": "CRITICAL",
                                    })
                                    console.print(f"      [bold red][!] {key} = {value[:4]}****[/bold red]")
                        self.results["shadow_it_flags"].append({
                            "type": "Exposed Environment File",
                            "asset": url,
                            "reason": "Environment file with secrets is publicly accessible.",
                        })

    def _scan_content(self, content, source_url, source_type):
        found = 0
        for name, pattern in self.secret_patterns.items():
            try:
                matches = re.findall(pattern, content)
                if matches:
                    for match in matches[:3]:
                        if isinstance(match, tuple):
                            match = match[0]
                        match_str = str(match).strip()
                        if self._is_false_positive(name, match_str):
                            continue
                        masked = self._mask_secret(match_str)
                        severity = self._get_severity(name)
                        entry = {
                            "type": name,
                            "source_url": source_url,
                            "source_type": source_type,
                            "masked_value": masked,
                            "severity": severity,
                            "context": self._get_context(content, match_str),
                        }
                        if "password" in name.lower() or "credential" in name.lower():
                            self.results["hardcoded_passwords"].append(entry)
                        elif "key" in name.lower() or "secret" in name.lower():
                            self.results["api_keys_found"].append(entry)
                        elif "token" in name.lower():
                            self.results["exposed_tokens"].append(entry)
                        else:
                            self.results["secrets_found"].append(entry)
                        found += 1
                        color = "bold red" if severity == "CRITICAL" else "red" if severity == "HIGH" else "yellow"
                        console.print(f"  [{color}][!] [{severity}] {name}: {masked} ({source_type})[/{color}]")
                        self.results["shadow_it_flags"].append({
                            "type": f"Exposed Secret ({name})",
                            "asset": source_url,
                            "reason": f"{name} found in {source_type}. Rotate immediately.",
                        })
            except re.error:
                continue
        return found

    def _scan_headers(self, headers, url):
        sensitive_headers = {
            "X-Powered-By": "Technology disclosure",
            "Server": "Server disclosure",
            "X-AspNet-Version": "ASP.NET version disclosure",
            "X-Debug-Token": "Debug token exposed",
            "X-Debug-Token-Link": "Debug link exposed",
        }
        for header, desc in sensitive_headers.items():
            if header in headers:
                val = headers[header]
                if header in ["X-Debug-Token", "X-Debug-Token-Link"]:
                    self.results["secrets_found"].append({
                        "type": f"Header: {header}",
                        "source_url": url,
                        "source_type": "HTTP Header",
                        "masked_value": val,
                        "severity": "MEDIUM",
                        "context": desc,
                    })

    def _check_json_secrets(self, data, url, depth=0):
        if depth > 3:
            return
        sensitive_fields = [
            "password", "passwd", "pwd", "secret", "token", "api_key",
            "apikey", "api_secret", "access_token", "auth_token",
            "private_key", "encryption_key",
        ]
        if isinstance(data, dict):
            for key, value in data.items():
                if any(sf in key.lower() for sf in sensitive_fields):
                    if value and str(value) not in ["", "null", "None", "***", "REDACTED"]:
                        masked = self._mask_secret(str(value))
                        self.results["secrets_found"].append({
                            "type": f"JSON Field: {key}",
                            "source_url": url,
                            "source_type": "API JSON Response",
                            "masked_value": masked,
                            "severity": "CRITICAL",
                            "context": f"Sensitive field '{key}' in API response",
                        })
                        console.print(f"  [bold red][!!!] API leaking '{key}': {masked}[/bold red]")
                if isinstance(value, (dict, list)):
                    self._check_json_secrets(value, url, depth + 1)
        elif isinstance(data, list):
            for item in data[:3]:
                if isinstance(item, (dict, list)):
                    self._check_json_secrets(item, url, depth + 1)

    def _resolve_url(self, base_url, path):
        try:
            if path.startswith("//"):
                return f"https:{path}"
            elif path.startswith("http"):
                return path
            elif path.startswith("/"):
                parsed = urlparse(base_url)
                return f"{parsed.scheme}://{parsed.netloc}{path}"
            else:
                return urljoin(base_url, path)
        except Exception:
            return None

    def _is_false_positive(self, pattern_name, match):
        if len(match) < 4:
            return True
        fp_values = [
            "undefined", "null", "none", "true", "false", "example",
            "your_", "insert_", "paste_", "enter_", "change_me",
            "xxx", "TODO", "FIXME", "placeholder", "sample",
            "test1234", "password123", "xxxxxxxx",
        ]
        if match.lower() in fp_values or any(fp in match.lower() for fp in fp_values):
            return True
        if "Key" in pattern_name and len(match) < 10:
            return True
        return False

    def _is_error_page(self, content):
        error_indicators = [
            "page not found", "404 not found", "error 404",
            "does not exist", "access denied", "forbidden",
        ]
        content_lower = content.lower()[:500]
        return any(ind in content_lower for ind in error_indicators)

    def _mask_secret(self, value):
        if len(value) <= 8:
            return value[:2] + "****"
        return value[:4] + "****" + value[-4:]

    def _get_severity(self, pattern_name):
        critical = [
            "AWS", "Azure", "GCP", "Stripe Secret", "Private Key",
            "Database", "Connection", "Hardcoded Password", "Admin Password",
            "SSH", "Vault", "Firebase", "MongoDB", "Redis", "FTP", "SMTP",
            "LDAP", "Default Credential", "PGP",
        ]
        high = [
            "GitHub Token", "Slack", "SendGrid", "Twilio", "Mailgun",
            "Discord", "Telegram", "Bearer", "JWT", "Generic Secret",
            "Generic API Key", "PayPal", "Square",
        ]
        for c in critical:
            if c.lower() in pattern_name.lower():
                return "CRITICAL"
        for h in high:
            if h.lower() in pattern_name.lower():
                return "HIGH"
        return "MEDIUM"

    def _get_context(self, content, match):
        idx = content.find(match)
        if idx == -1:
            return ""
        start = max(0, idx - 40)
        end = min(len(content), idx + len(match) + 40)
        ctx = content[start:end].replace("\n", " ").strip()
        return f"...{ctx}..."

    def _generate_summary(self):
        total = (
            len(self.results["secrets_found"])
            + len(self.results["api_keys_found"])
            + len(self.results["hardcoded_passwords"])
            + len(self.results["exposed_tokens"])
        )

        table = Table(title="Secret Scanner Summary")
        table.add_column("Category", style="cyan")
        table.add_column("Count", style="bold white")
        table.add_column("Severity", style="bold")
        table.add_row("API Keys", str(len(self.results["api_keys_found"])), "[red]CRITICAL[/red]")
        table.add_row("Hardcoded Passwords", str(len(self.results["hardcoded_passwords"])), "[red]CRITICAL[/red]")
        table.add_row("Exposed Tokens", str(len(self.results["exposed_tokens"])), "[bold red]HIGH[/bold red]")
        table.add_row("Other Secrets", str(len(self.results["secrets_found"])), "[yellow]MEDIUM[/yellow]")
        table.add_row("Config/Env Leaks", str(len(self.results["config_leaks"])), "[red]CRITICAL[/red]")
        table.add_row("Env File Secrets", str(len(self.results["env_files"])), "[red]CRITICAL[/red]")
        table.add_row("API Endpoints", str(len(self.results["api_endpoints_found"])), "[cyan]INFO[/cyan]")
        table.add_row("JS Files Scanned", str(len(self.results["js_files_scanned"])), "[cyan]INFO[/cyan]")
        table.add_row("[bold]TOTAL SECRETS[/bold]", f"[bold]{total}[/bold]", "")
        console.print(table)

    def _next_steps(self):
        steps = []
        if self.results["api_keys_found"]:
            steps.append({
                "action": "Rotate Exposed API Keys",
                "description": f"{len(self.results['api_keys_found'])} API keys found. Rotate ALL immediately.",
                "priority": "CRITICAL",
            })
        if self.results["hardcoded_passwords"]:
            steps.append({
                "action": "Change Hardcoded Passwords",
                "description": f"{len(self.results['hardcoded_passwords'])} hardcoded passwords. Remove from code, use vault.",
                "priority": "CRITICAL",
            })
        if self.results["env_files"]:
            steps.append({
                "action": "Remove Exposed Env Files",
                "description": f"{len(self.results['env_files'])} env secrets exposed. Block access and rotate.",
                "priority": "CRITICAL",
            })
        if self.results["config_leaks"]:
            steps.append({
                "action": "Secure Config Files",
                "description": f"{len(self.results['config_leaks'])} config files publicly accessible.",
                "priority": "CRITICAL",
            })
        if self.results["exposed_tokens"]:
            steps.append({
                "action": "Revoke Exposed Tokens",
                "description": f"{len(self.results['exposed_tokens'])} tokens found. Revoke and reissue.",
                "priority": "HIGH",
            })
        open_apis = [e for e in self.results["api_endpoints_found"] if e["auth"] == "Open"]
        if open_apis:
            steps.append({
                "action": "Secure Open APIs",
                "description": f"{len(open_apis)} unauthenticated API endpoints. Add auth.",
                "priority": "HIGH",
            })
        steps.append({
            "action": "Implement Secret Scanning",
            "description": "Set up pre-commit hooks with trufflehog/gitleaks.",
            "priority": "HIGH",
        })
        self.results["next_steps"] = steps