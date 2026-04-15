import requests
import re
import time
from rich.console import Console
from rich.panel import Panel

# ── Redirect & Login Page Detection (hotfix) ──

LOGIN_PAGE_INDICATORS = [
    'login', 'sign in', 'sign-in', 'signin', 'log in', 'log-in',
    'authenticate', 'auth', 'sso', 'saml', 'oauth', 'oidc',
    'username', 'password', 'forgot password', 'reset password',
    'enter your credentials', 'access denied', 'session expired',
    'single sign-on', 'identity provider', 'okta', 'azure ad',
    'adfs', 'ping', 'duo', 'mfa', 'two-factor', '2fa',
    'cas/login', 'idp/login', 'accounts/login',
]

LOGIN_URL_PATTERNS = [
    r'/login', r'/signin', r'/sign-in', r'/auth',
    r'/sso', r'/saml', r'/oauth', r'/cas/',
    r'/adfs/', r'/idp/', r'/accounts/login',
    r'/identity/', r'/connect/authorize',
]


def _check_endpoint_with_redirect_detection(url, session, timeout=10):
    """
    Check an endpoint URL with proper redirect and login page detection.
    
    Returns:
        tuple: (response_or_None, is_redirect, redirect_target, is_login_page)
    """
    try:
        # Step 1: Make request WITHOUT following redirects
        resp_no_redirect = session.get(
            url, timeout=timeout, allow_redirects=False, verify=False
        )
        
        status = resp_no_redirect.status_code
        
        # If it's a redirect (301, 302, 303, 307, 308)
        if status in (301, 302, 303, 307, 308):
            redirect_target = resp_no_redirect.headers.get('Location', '')
            
            # Check if redirecting to a login page
            redirect_lower = redirect_target.lower()
            is_login_redirect = any(
                pattern in redirect_lower 
                for pattern in ['/login', '/signin', '/auth', '/sso', '/cas/', '/adfs/', '/saml']
            )
            
            if is_login_redirect:
                return None, True, redirect_target, True
            
            # Follow the redirect to see where it goes
            try:
                resp_followed = session.get(
                    url, timeout=timeout, allow_redirects=True, verify=False
                )
                # Check if final page is a login page
                final_url = resp_followed.url.lower()
                body_lower = resp_followed.text.lower()
                
                is_login = (
                    any(p in final_url for p in LOGIN_URL_PATTERNS) or
                    _is_login_page(body_lower)
                )
                
                if is_login:
                    return None, True, resp_followed.url, True
                
                return resp_followed, True, resp_followed.url, False
                
            except Exception:
                return None, True, redirect_target, is_login_redirect
        
        # Not a redirect - check if the page itself is a login page
        if status == 200:
            body_lower = resp_no_redirect.text.lower()
            if _is_login_page(body_lower):
                return None, False, url, True
            return resp_no_redirect, False, url, False
        
        # Non-200, non-redirect
        return None, False, url, False
        
    except requests.exceptions.Timeout:
        return None, False, url, False
    except Exception as e:
        return None, False, url, False


def _is_login_page(body_lower):
    """Detect if HTML body is a login/authentication page."""
    login_score = 0
    
    # Check for login form elements
    if '<form' in body_lower:
        if any(x in body_lower for x in ['type="password"', "type='password'"]):
            login_score += 3
        if any(x in body_lower for x in ['name="username"', 'name="user"', 'name="email"',
                                           "name='username'", "name='user'", "name='email'"]):
            login_score += 2
    
    # Check for login-related text
    login_text_hits = sum(1 for ind in LOGIN_PAGE_INDICATORS if ind in body_lower)
    login_score += min(login_text_hits, 5)  # Cap at 5 to avoid over-counting
    
    # Check title
    import re as _re
    title_match = _re.search(r'<title[^>]*>([^<]+)</title>', body_lower)
    if title_match:
        title = title_match.group(1)
        if any(x in title for x in ['login', 'sign in', 'authenticate', 'sso']):
            login_score += 3
    
    return login_score >= 4



# ── Exposed Endpoint Validator (added by fix_exposed_db.py) ──

ENDPOINT_SIGNATURES = {
    'phpmyadmin': {
        'positive': ['phpmyadmin', 'pma_', 'pmahomme', 'phpmy', 'server_databases',
                      'db_structure', 'tbl_structure', 'sql.php', 'navigation.php',
                      'phpmyadmin.css', 'pma_navigation'],
        'title_patterns': [r'phpmyadmin', r'pma\s'],
        'min_length': 500,
    },
    'adminer': {
        'positive': ['adminer', 'jush', 'adminer.css', 'name="auth[driver]"',
                      'name="auth[server]"', 'name="auth[username]"',
                      'adminer-static', 'database_drivers'],
        'title_patterns': [r'adminer'],
        'min_length': 300,
    },
    'phppgadmin': {
        'positive': ['phppgadmin', 'pgadmin', 'postgresql', 'pg_database'],
        'title_patterns': [r'phppgadmin', r'pgadmin'],
        'min_length': 500,
    },
    'mysql_admin': {
        'positive': ['mysql', 'database manager', 'db manager', 'mysql_connect'],
        'title_patterns': [r'mysql.*admin', r'database.*manager'],
        'min_length': 300,
    },
    'elasticsearch': {
        'positive': ['"cluster_name"', '"cluster_uuid"', '"tagline"', 'you know, for search',
                     '"version"', '"lucene_version"'],
        'title_patterns': [],
        'min_length': 50,
    },
    'kibana': {
        'positive': ['kibana', 'kbn-xsrf', 'kbn-version', 'kibana-body',
                      'discover#/', 'dashboards', 'kbn-injected-metadata'],
        'title_patterns': [r'kibana'],
        'min_length': 500,
    },
    'grafana': {
        'positive': ['grafana', 'grafana-app', 'gr-page', 'grafana.dark.css',
                      'grafana.light.css', 'grafana_icon'],
        'title_patterns': [r'grafana'],
        'min_length': 500,
    },
    'jenkins': {
        'positive': ['jenkins', 'jenkins-hierarchical', 'hudson', 'j_acegi_security',
                      'jenkins-ci', 'jenkinsci'],
        'title_patterns': [r'jenkins', r'dashboard.*jenkins'],
        'min_length': 500,
    },
    'couchdb': {
        'positive': ['"couchdb"', '"vendor"', '"welcome"', 'apache couchdb'],
        'title_patterns': [],
        'min_length': 50,
    },
    'redis_commander': {
        'positive': ['redis-commander', 'redis commander', 'redis_commander'],
        'title_patterns': [r'redis.*commander'],
        'min_length': 200,
    },
    'mongo_express': {
        'positive': ['mongo-express', 'mongo express', 'mongodb'],
        'title_patterns': [r'mongo.*express'],
        'min_length': 200,
    },
    'wp_admin': {
        'positive': ['wp-login', 'wp-admin', 'wordpress', 'powered by wordpress'],
        'title_patterns': [r'log in.*wordpress', r'wordpress.*log in'],
        'min_length': 500,
    },
    'default': {
        'positive': [],
        'title_patterns': [],
        'min_length': 200,
    },
}

# Pages that look like 200 but are actually error/redirect/default pages
FALSE_POSITIVE_INDICATORS = [
    'page not found', '404 not found', 'not found',
    'page does not exist', 'does not exist',
    'access denied', '403 forbidden', 'forbidden',
    'unauthorized', '401 unauthorized',
    'error occurred', 'server error', 'internal server error',
    'this page is unavailable', 'page unavailable',
    'under construction', 'coming soon',
    'moved permanently', 'page has moved',
    'sorry, the page', 'we couldn\'t find',
    'no longer available', 'has been removed',
    'bad request', 'request denied',
]


def _validate_exposed_endpoint(url, response, path_key=None):
    """
    Validate that a detected endpoint is GENUINELY the tool it claims to be.
    
    Args:
        url: The full URL checked
        response: The requests.Response object
        path_key: Which tool we're checking for (e.g., 'phpmyadmin', 'adminer')
    
    Returns:
        tuple: (is_valid: bool, confidence: str, reason: str)
    """
    # ── Check 1: Status code must be 200 (not redirect, not error) ──
    if response.status_code != 200:
        return False, 'none', f'HTTP {response.status_code}'

    body = response.text
    body_lower = body.lower()
    body_len = len(body)

    # ── Check 2: Response must not be empty or tiny ──
    if body_len < 50:
        return False, 'none', f'Response too small ({body_len} bytes)'

    # ── Check 3: Check for false positive indicators (custom 404s, error pages) ──
    fp_count = sum(1 for fp in FALSE_POSITIVE_INDICATORS if fp in body_lower)
    if fp_count >= 2:
        return False, 'none', f'Appears to be error/404 page ({fp_count} indicators)'

    # Single strong FP indicator in the title
    title_match = re.search(r'<title[^>]*>([^<]+)</title>', body, re.IGNORECASE)
    page_title = title_match.group(1).strip().lower() if title_match else ''

    for fp in ['not found', '404', 'error', 'forbidden', 'denied', 'unavailable']:
        if fp in page_title:
            return False, 'none', f'Title contains "{fp}"'

    # ── Check 4: Determine which tool we're validating ──
    if not path_key:
        # Try to guess from URL
        url_lower = url.lower()
        for key in ENDPOINT_SIGNATURES:
            if key != 'default' and key.replace('_', '') in url_lower.replace('/', '').replace('-', ''):
                path_key = key
                break

    if not path_key:
        path_key = 'default'

    sigs = ENDPOINT_SIGNATURES.get(path_key, ENDPOINT_SIGNATURES['default'])

    # ── Check 5: Minimum response length ──
    if body_len < sigs['min_length']:
        return False, 'none', f'Response too small for {path_key} ({body_len} < {sigs["min_length"]})'

    # ── Check 6: Look for positive signatures ──
    positive_hits = []
    for sig in sigs['positive']:
        if sig.lower() in body_lower:
            positive_hits.append(sig)

    # ── Check 7: Check title patterns ──
    title_hits = []
    for pattern in sigs['title_patterns']:
        if re.search(pattern, page_title, re.IGNORECASE):
            title_hits.append(pattern)

    # ── Check 8: Determine confidence ──
    if len(positive_hits) >= 3 or (len(positive_hits) >= 1 and title_hits):
        return True, 'HIGH', f'Matched {len(positive_hits)} signature(s): {positive_hits[:3]}'
    elif len(positive_hits) >= 2:
        return True, 'MEDIUM', f'Matched {len(positive_hits)} signature(s): {positive_hits[:3]}'
    elif len(positive_hits) == 1:
        # Single match - could still be FP. Check if the page is mostly a normal website
        if _looks_like_normal_website(body_lower, page_title):
            return False, 'none', f'Single match "{positive_hits[0]}" but page looks like normal website'
        return True, 'LOW', f'Single match: {positive_hits[0]}'
    else:
        return False, 'none', f'No {path_key} signatures found in response'


def _looks_like_normal_website(body_lower, title):
    """Detect if a page is a normal website rather than an admin panel."""
    normal_indicators = [
        'careers', 'about us', 'contact us', 'privacy policy',
        'terms of service', 'copyright', 'all rights reserved',
        'navigation', 'main-content', 'header', 'footer',
        'subscribe', 'newsletter', 'blog', 'news',
        'sign up', 'create account', 'join us',
        'products', 'services', 'solutions',
        'meta name="description"', 'meta property="og:',
        'google-analytics', 'googletagmanager',
    ]
    hits = sum(1 for ind in normal_indicators if ind in body_lower)
    # If 3+ normal website indicators, it's probably just a website
    return hits >= 3


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
            for sub in subdomains:
                s = sub.get("subdomain", "") if isinstance(sub, dict) else sub
                if s and s not in targets:
                    targets.append(s)
        targets = self._filter_live_hosts(targets)
        self._probe(targets)
        self._sensitive_files(targets)
        self._security_headers(targets)
        self._api_endpoints(targets)
        self._github_search(target_domain)
        self._exposed_dbs(targets)
        self._next_steps()
        return self.results

    def _probe(self, targets):
     console.print("[yellow][*] Probing web services...[/yellow]")
     for h in targets:
         found = False
         for scheme in ["https", "http"]:
             try:
                 url = f"{scheme}://{h}"
                 resp = self.session.get(url, timeout=10, allow_redirects=True)
                 title = ""
                 m = re.search(r'<title[^>]*>(.*?)</title>', resp.text, re.I | re.DOTALL)
                 if m:
                    title = m.group(1).strip()[:100]
                 self.results["web_applications"].append({
                     "hostname": h, "url": url, "status_code": resp.status_code,
                     "title": title, "server": resp.headers.get("Server", ""),
                     "reachable": True,
                 })
                 console.print(f"  [green][+] {url} [{resp.status_code}] {title}[/green]")
                 self._fingerprint(h, resp)
                 found = True
                 break
             except Exception:
                 continue
         if not found:
            self.results["web_applications"].append({
                "hostname": h, "url": f"https://{h}", "status_code": 0,
                "title": "", "server": "", "reachable": False,
            })
            console.print(f"  [dim][-] {h}: unreachable[/dim]")
    def _filter_live_hosts(self, targets):
        """Pre-filter to only reachable hosts. Saves massive time downstream."""
        console.print("[yellow][*] Pre-filtering live hosts...[/yellow]")
        live = []

        def check(host):
            try:
                resp = self.session.get(f"https://{host}", timeout=5, allow_redirects=True)
                return host if resp.status_code < 500 else None
            except Exception:
                try:
                    resp = self.session.get(f"http://{host}", timeout=5, allow_redirects=True)
                    return host if resp.status_code < 500 else None
                except Exception:
                    return None

        from concurrent.futures import ThreadPoolExecutor, as_completed
        with ThreadPoolExecutor(max_workers=self.config.get("THREADS", 10)) as pool:
            futures = {pool.submit(check, h): h for h in targets}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    live.append(result)

        dead = len(targets) - len(live)
        console.print(f"  [green][+] {len(live)} live, {dead} unreachable (skipped)[/green]")

        # Track unreachable for the report
        live_set = set(live)
        self.results["unreachable_hosts"] = [h for h in targets if h not in live_set]

        return live

    def _sensitive_files(self, targets):
        console.print("[yellow][*] Checking sensitive files...[/yellow]")
        from concurrent.futures import ThreadPoolExecutor, as_completed

        paths = {
            "/.env": ("Env Vars", "CRITICAL"),
            "/.git/HEAD": ("Git Repo", "CRITICAL"),
            "/.git/config": ("Git Config", "CRITICAL"),
            "/wp-config.php.bak": ("WP Config Backup", "CRITICAL"),
            "/backup.sql": ("SQL Backup", "CRITICAL"),
            "/.htpasswd": ("Apache Passwords", "CRITICAL"),
            "/phpinfo.php": ("PHP Info", "HIGH"),
            "/robots.txt": ("Robots.txt", "INFO"),
            "/swagger.json": ("Swagger", "MEDIUM"),
            "/graphql": ("GraphQL", "MEDIUM"),
            "/actuator/env": ("Spring Env", "CRITICAL"),
            "/docker-compose.yml": ("Docker Compose", "CRITICAL"),
            "/admin": ("Admin Panel", "MEDIUM"),
            "/wp-admin": ("WP Admin", "MEDIUM"),
        }

        # Known content signatures that prove the file is real
        content_signatures = {
            "/.env": ["DB_PASSWORD", "DB_HOST", "APP_KEY", "SECRET_KEY", "API_KEY", "DATABASE_URL"],
            "/.git/HEAD": ["ref: refs/heads/"],
            "/.git/config": ["[core]", "[remote", "repositoryformatversion"],
            "/wp-config.php.bak": ["DB_NAME", "DB_USER", "DB_PASSWORD", "table_prefix"],
            "/backup.sql": ["INSERT INTO", "CREATE TABLE", "DROP TABLE", "mysqldump"],
            "/.htpasswd": [":$apr1$", ":$2y$", ":{SHA}"],
            "/phpinfo.php": ["phpinfo()", "PHP Version", "Configuration File"],
            "/robots.txt": ["User-agent:", "Disallow:", "Allow:", "Sitemap:"],
            "/swagger.json": ['"swagger"', '"openapi"', '"paths"', '"info"'],
            "/graphql": ['"data"', '"__schema"', '"queryType"'],
            "/actuator/env": ['"activeProfiles"', '"propertySources"', '"systemProperties"'],
            "/docker-compose.yml": ["version:", "services:", "image:", "volumes:"],
            "/admin": [],  # validated differently
            "/wp-admin": [],  # validated differently
        }

        # Step 1: Get baseline response for each host (request a fake path)
        baselines = {}

        def get_baseline(h):
            try:
                fake_url = f"https://{h}/.definitely_not_a_real_file_xyz123"
                resp = self.session.get(fake_url, timeout=8, allow_redirects=True)
                return h, len(resp.content), resp.status_code
            except Exception:
                return h, 0, 0

        with ThreadPoolExecutor(max_workers=self.config.get("THREADS", 10)) as pool:
            futures = [pool.submit(get_baseline, h) for h in targets]
            for future in as_completed(futures):
                host, size, status = future.result()
                baselines[host] = {"size": size, "status": status}

        def check_file(h, path, desc, sev):
            try:
                url = f"https://{h}{path}"

                # First request without following redirects
                resp = self.session.get(url, timeout=8, allow_redirects=False)
                status = resp.status_code

                # Skip actual redirects (301, 302, 303, 307, 308)
                if status in [301, 302, 303, 307, 308]:
                    return None

                # Skip non-200
                if status != 200:
                    return None

                body = resp.text if hasattr(resp, 'text') else ""
                body_len = len(resp.content)

                # Skip empty responses
                if body_len == 0:
                    return None

                # Check for JavaScript/meta redirects
                body_lower = body.lower()
                redirect_indicators = [
                    "window.location", "document.location",
                    'http-equiv="refresh"', "http-equiv='refresh'",
                    "location.href", "location.replace(",
                    "window.navigate",
                ]
                for indicator in redirect_indicators:
                    if indicator in body_lower:
                        return None

                # Check for login page indicators
                login_indicators = [
                    "login", "sign in", "signin", "log in",
                    "username", "password", "authentication required",
                    "sso", "saml", "oauth", "unauthorized",
                ]
                # If it has a form AND login keywords, it's a login page
                if "<form" in body_lower:
                    login_matches = sum(1 for kw in login_indicators if kw in body_lower)
                    if login_matches >= 2:
                        return None

                # Compare against baseline (soft 404 detection)
                baseline = baselines.get(h, {})
                baseline_size = baseline.get("size", 0)
                if baseline_size > 0 and body_len > 0:
                    # If response size is within 5% of the fake page, it's a catch-all
                    size_ratio = abs(body_len - baseline_size) / max(baseline_size, 1)
                    if size_ratio < 0.05:
                        return None

                # Check for content signatures (proves the file is real)
                sigs = content_signatures.get(path, [])
                if sigs:
                    has_signature = any(sig.lower() in body_lower for sig in sigs)
                    if not has_signature:
                        # No matching signature — likely a generic page
                        # Exception: if it's clearly not HTML, might still be real
                        ct = resp.headers.get("Content-Type", "").lower()
                        if "html" in ct or ("<html" in body_lower and "</html>" in body_lower):
                            return None

                # For /admin and /wp-admin, check it's actually an admin panel
                if path in ["/admin", "/wp-admin"]:
                    ct = resp.headers.get("Content-Type", "").lower()
                    if "html" not in ct:
                        return None
                    admin_indicators = [
                        "dashboard", "admin panel", "administration",
                        "wp-login", "wordpress", "control panel",
                        "manage", "settings",
                    ]
                    if not any(kw in body_lower for kw in admin_indicators):
                        return None

                return {
                    "hostname": h, "path": path, "url": url,
                    "description": desc, "severity": sev,
                    "content_length": body_len,
                }

            except Exception:
                return None

        tasks = [(h, p, d, s) for h in targets for p, (d, s) in paths.items()]

        with ThreadPoolExecutor(max_workers=self.config.get("THREADS", 10)) as pool:
            futures = {pool.submit(check_file, *t): t for t in tasks}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    self.results["sensitive_files"].append(result)
                    sev = result["severity"]
                    url = result["url"]
                    desc = result["description"]
                    console.print(f"  [bold red][!] [{sev}] {url} - {desc}[/bold red]")
                    if sev in ["CRITICAL", "HIGH"]:
                        self.results["shadow_it_flags"].append({
                            "type": "Exposed Dev File", "asset": url,
                            "reason": f"Sensitive file '{result['path']}' exposed.",
                        })

    def _security_headers(self, targets):
        console.print("[yellow][*] Checking security headers...[/yellow]")
        required = {"Strict-Transport-Security": "No HSTS", "Content-Security-Policy": "No CSP", "X-Frame-Options": "Clickjacking risk", "X-Content-Type-Options": "MIME sniffing risk"}
        for h in targets[:50]:
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
        from concurrent.futures import ThreadPoolExecutor, as_completed
        api_paths = [
            "/api", "/api/v1", "/api/v2", "/api/v3", "/rest", "/graphql",
            "/swagger.json", "/openapi.json", "/api-docs", "/v1", "/v2",
            "/health", "/metrics", "/status",
        ]

        def check_api(h, path):
            try:
                url = f"https://{h}{path}"
                resp, is_redirect, redirect_target, is_login = \
                    _check_endpoint_with_redirect_detection(url, self.session, timeout=8)
                if is_login or resp is None:
                    return None
                status = resp.status_code
                ct = resp.headers.get("Content-Type", "").lower()
                body = resp.text.lower() if hasattr(resp, 'text') else ""
                if status == 200:
                    is_api = False
                    if "json" in ct or "xml" in ct:
                        is_api = True
                    elif body.strip().startswith(("{", "[", "<?xml")):
                        is_api = True
                    if "<html" in body and "</html>" in body:
                        if "json" not in ct and "xml" not in ct:
                            is_api = False
                    if is_api and any(x in body for x in [
                        '"not found"', '"error"', '"page not found"',
                        '"no route"', '"cannot get"', '"invalid endpoint"',
                    ]):
                        if len(body) < 200:
                            is_api = False
                    if not is_api:
                        return None
                    auth = "Open"
                elif status in [401, 403]:
                    is_api_auth = False
                    www_auth = resp.headers.get("WWW-Authenticate", "").lower()
                    if any(x in www_auth for x in ["bearer", "basic", "api", "token"]):
                        is_api_auth = True
                    if "json" in ct:
                        is_api_auth = True
                    for hdr in ["x-ratelimit-limit", "x-api-version", "x-request-id"]:
                        if hdr in [k.lower() for k in resp.headers]:
                            is_api_auth = True
                    if not is_api_auth:
                        return None
                    auth = "Requires Auth"
                else:
                    return None
                return {
                    "hostname": h, "path": path, "url": url,
                    "status_code": status, "content_type": ct, "auth": auth,
                }
            except Exception:
                return None

        tasks = [(h, p) for h in targets for p in api_paths]

        with ThreadPoolExecutor(max_workers=self.config.get("THREADS", 10)) as pool:
            futures = {pool.submit(check_api, *t): t for t in tasks}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    self.results["api_endpoints"].append(result)
                    console.print(
                        f"  [green][+] API: {result['url']} "
                        f"[{result['status_code']}] ({result['auth']})[/green]"
                    )

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

    def _exposed_dbs(self, targets):
        console.print("[yellow][*] Checking exposed databases...[/yellow]")
        from concurrent.futures import ThreadPoolExecutor, as_completed

        db_checks = {
            "/phpmyadmin/": {
                "name": "phpMyAdmin",
                "signatures": ["phpmyadmin", "pma_", "phpmy", "sql query", "mysql"],
            },
            "/adminer.php": {
                "name": "Adminer",
                "signatures": ["adminer", "login to", "select database", "sql command"],
            },
            "/pma/": {
                "name": "phpMyAdmin",
                "signatures": ["phpmyadmin", "pma_", "phpmy"],
            },
            "/dbadmin/": {
                "name": "DB Admin",
                "signatures": ["database", "sql", "query", "table"],
            },
        }

        baselines = {}              # ← ADD THIS

        def get_baseline(h):
            try:
                fake_url = f"https://{h}/.not_a_real_db_page_xyz789"
                resp = self.session.get(fake_url, timeout=8, allow_redirects=True)
                return h, len(resp.content), resp.status_code
            except Exception:
                return h, 0, 0

        with ThreadPoolExecutor(max_workers=self.config.get("THREADS", 10)) as pool:
            futures = [pool.submit(get_baseline, h) for h in targets]
            for future in as_completed(futures):
                host, size, status = future.result()
                baselines[host] = {"size": size, "status": status}

        seen_urls = set()

        def check_db(host, path, db_info):
            try:
                url = f"https://{host}{path}"

                # Request WITHOUT following redirects
                resp = self.session.get(url, timeout=8, allow_redirects=False)
                status = resp.status_code

                # Reject redirects — real exposed DBs serve directly
                if status in [301, 302, 303, 307, 308]:
                    return None

                # Only care about 200 and 401
                # 401 only if it proves the DB tool exists
                if status == 401:
                    www_auth = resp.headers.get("WWW-Authenticate", "").lower()
                    body_lower = (resp.text or "").lower()
                    # Must have DB-related content even on 401
                    if not any(sig in body_lower or sig in www_auth for sig in db_info["signatures"]):
                        return None
                    return {
                        "type": db_info["name"],
                        "url": url,
                        "status": status,
                        "auth": "Password Protected",
                    }

                if status != 200:
                    return None

                body = resp.text if hasattr(resp, 'text') else ""
                body_lower = body.lower()
                body_len = len(resp.content)

                # Skip empty responses
                if body_len == 0:
                    return None

                # JavaScript/meta redirect detection
                redirect_indicators = [
                    "window.location", "document.location",
                    'http-equiv="refresh"', "http-equiv='refresh'",
                    "location.href", "location.replace(",
                ]
                for indicator in redirect_indicators:
                    if indicator in body_lower:
                        return None

                # Soft 404 detection — compare to baseline
                baseline = baselines.get(host, {})
                baseline_size = baseline.get("size", 0)
                if baseline_size > 0 and body_len > 0:
                    size_ratio = abs(body_len - baseline_size) / max(baseline_size, 1)
                    if size_ratio < 0.05:
                        return None

                # Must contain at least one content signature
                sig_matches = sum(1 for sig in db_info["signatures"] if sig in body_lower)
                if sig_matches == 0:
                    return None

                return {
                    "type": db_info["name"],
                    "url": url,
                    "status": status,
                    "auth": "Open" if status == 200 else "Unknown",
                }

            except Exception:
                return None

        # Build task list
        tasks = []
        for host in targets:
            for path, db_info in db_checks.items():
                tasks.append((host, path, db_info))

        # Run threaded
        with ThreadPoolExecutor(max_workers=self.config.get("THREADS", 10)) as pool:
            futures = {pool.submit(check_db, *t): t for t in tasks}
            for future in as_completed(futures):
                result = future.result()
                if result and result["url"] not in seen_urls:
                    seen_urls.add(result["url"])
                    self.results["exposed_databases"].append(result)
                    auth_note = f" ({result['auth']})" if result.get("auth") else ""
                    console.print(
                        f"  [bold red][!] {result['type']}: {result['url']}{auth_note}[/bold red]"
                    )
                    self.results["shadow_it_flags"].append({
                        "type": "Exposed Database",
                        "asset": result["url"],
                        "reason": f"{result['type']} publicly accessible{auth_note}.",
                    })

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


# ── Post-process: Filter false positive exposed endpoints ──
def filter_exposed_findings(findings, session, timeout=10):
    """Re-validate all exposed database/panel findings to remove false positives."""
    if not findings:
        return findings
    
    filtered = []
    removed = 0
    
    for finding in findings:
        ftype = finding.get('type', '').lower()
        
        # Only re-validate exposed database/panel findings
        if 'exposed' not in ftype or ('database' not in ftype and 'panel' not in ftype and 'admin' not in ftype):
            filtered.append(finding)
            continue
        
        url = finding.get('asset', finding.get('url', ''))
        if not url or not url.startswith('http'):
            filtered.append(finding)
            continue
        
        # Determine tool type
        tool_key = 'default'
        url_lower = url.lower()
        for key in ENDPOINT_SIGNATURES:
            if key != 'default' and key.replace('_', '') in url_lower.replace('/', '').replace('-', ''):
                tool_key = key
                break
        
        reason_text = finding.get('reason', '').lower()
        for key in ENDPOINT_SIGNATURES:
            if key != 'default' and key.replace('_', ' ') in reason_text:
                tool_key = key
                break
        
        try:
            resp = session.get(url, timeout=timeout, verify=False, allow_redirects=True)
            is_valid, confidence, reason = _validate_exposed_endpoint(url, resp, tool_key)
            
            if is_valid:
                finding['confidence'] = confidence
                finding['validation'] = reason
                filtered.append(finding)
            else:
                removed += 1
                print(f"  [FP Removed] {url} - {reason}")
        except Exception as e:
            # If we can't re-check, keep it but mark as unverified
            finding['confidence'] = 'UNVERIFIED'
            finding['validation'] = f'Could not re-verify: {e}'
            filtered.append(finding)
    
    if removed:
        print(f"  [+] Removed {removed} false positive exposed endpoint(s)")
    
    return filtered



# ── Wrapped endpoint checker (replaces simple GET + status check) ──
def _safe_check_endpoint(session, url, timeout=10):
    """
    Check if an endpoint URL is genuinely exposed.
    Handles redirects and login pages properly.
    
    Returns:
        tuple: (is_exposed: bool, response: Response|None, details: str)
    """
    try:
        # First request: don't follow redirects
        resp = session.get(url, timeout=timeout, allow_redirects=False, verify=False)
        
        # Redirect? Almost certainly not the real tool
        if resp.status_code in (301, 302, 303, 307, 308):
            location = resp.headers.get('Location', '')
            return False, resp, f'Redirects to {location}'
        
        # 401/403 - exists but protected (might still be interesting)
        if resp.status_code in (401, 403):
            return False, resp, f'Protected ({resp.status_code})'
        
        # 404/410 - doesn't exist
        if resp.status_code in (404, 410):
            return False, resp, f'Not found ({resp.status_code})'
        
        # 200 - need to validate content
        if resp.status_code == 200:
            body_lower = resp.text.lower()
            
            # Check if it's a login page
            if _is_login_page(body_lower):
                return False, resp, 'Login page (not the actual tool)'
            
            # Check if it's a normal website
            if _looks_like_normal_website(body_lower, ''):
                return False, resp, 'Normal website page'
            
            # Check body size
            if len(resp.text) < 50:
                return False, resp, f'Response too small ({len(resp.text)} bytes)'
            
            return True, resp, 'HTTP 200 with content'
        
        # Any other status
        return False, resp, f'HTTP {resp.status_code}'
        
    except Exception as e:
        return False, None, f'Error: {e}'



def _post_filter_exposed_endpoints(findings, session, timeout=10):
    """
    Post-process all exposed endpoint findings.
    Re-checks each one with redirect detection and content validation.
    """
    if not findings:
        return findings
    
    filtered = []
    removed = 0
    
    for finding in findings:
        ftype = str(finding.get('type', '')).lower()
        reason = str(finding.get('reason', '')).lower()
        asset = finding.get('asset', finding.get('url', ''))
        
        # Only re-check exposed database/panel/admin findings
        needs_recheck = any(kw in ftype or kw in reason for kw in [
            'exposed database', 'exposed panel', 'exposed admin',
            'phpmyadmin', 'adminer', 'phppgadmin', 'elasticsearch',
            'kibana', 'grafana', 'jenkins', 'couchdb', 'redis',
            'mongo', 'wp-admin', 'publicly accessible'
        ])
        
        if not needs_recheck or not asset.startswith('http'):
            filtered.append(finding)
            continue
        
        # Determine tool type
        tool_key = 'default'
        if 'ENDPOINT_SIGNATURES' in dir() or 'ENDPOINT_SIGNATURES' in globals():
            for key in ENDPOINT_SIGNATURES:
                if key != 'default':
                    key_clean = key.replace('_', '')
                    if key_clean in asset.lower().replace('/', '').replace('-', ''):
                        tool_key = key
                        break
                    if key.replace('_', ' ') in reason:
                        tool_key = key
                        break
        
        # Re-check with redirect detection
        is_exposed, resp, details = _safe_check_endpoint(session, asset, timeout)
        
        if not is_exposed:
            removed += 1
            print(f"  [FP REMOVED] {asset}")
            print(f"               Reason: {details}")
            continue
        
        # If we got here, it passed the redirect check. Now validate content.
        if resp and 'ENDPOINT_SIGNATURES' in dir() or 'ENDPOINT_SIGNATURES' in globals():
            try:
                is_valid, confidence, val_reason = _validate_exposed_endpoint(asset, resp, tool_key)
                if not is_valid:
                    removed += 1
                    print(f"  [FP REMOVED] {asset}")
                    print(f"               Reason: {val_reason}")
                    continue
                finding['confidence'] = confidence
                finding['validation'] = val_reason
            except Exception:
                pass
        
        filtered.append(finding)
    
    if removed > 0:
        print(f"  [+] Removed {removed} false positive exposed endpoint(s)")
    
    return filtered

