"""
Secret Scanner Module v2.1 - Fixed
Fixes: deduplication, false positives, severity classification, HTTP fallback, detailed reporting
"""

import re
import requests
import logging
import time
from urllib.parse import urljoin, urlparse
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.console import Console
from rich.panel import Panel

try:
    from bs4 import BeautifulSoup
    HAS_BS4 = True
except ImportError:
    HAS_BS4 = False

logger = logging.getLogger(__name__)

console = Console()
class SecretScanner:
    def __init__(self, config):
        self.config = config
        self.session = requests.Session()
        ua = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        if isinstance(config, dict):
            ua = config.get('USER_AGENT', ua)
            self.timeout = config.get('REQUEST_TIMEOUT', 10)
            self.max_crawl = config.get('MAX_CRAWL_PAGES', 15)
        else:
            ua = getattr(config, 'USER_AGENT', ua)
            self.timeout = getattr(config, 'REQUEST_TIMEOUT', 10)
            self.max_crawl = getattr(config, 'MAX_CRAWL_PAGES', 15)
        self.session.headers.update({'User-Agent': ua})
        self.session.verify = False
        self.visited = set()
        self.seen_secrets = OrderedDict()
        self.patterns = self._build_patterns()

    # ──────────────────────────────────────────────
    #  PATTERN DEFINITIONS
    # ──────────────────────────────────────────────

    def _build_patterns(self):
        patterns = [
            {
                'name': 'AWS Access Key ID',
                'regex': r'(?<![A-Z0-9])AKIA[0-9A-Z]{16}(?![A-Z0-9])',
                'category': 'api_keys_found',
                'severity': 'CRITICAL',
                'validate': None,
            },
            {
             'name': 'AWS Secret Access Key',
             'regex': r'(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY|SecretAccessKey|aws_secret|AWSSecretKey|secret_access_key|SECRET_KEY)\s*[:=]\s*["\']?([A-Za-z0-9/+=]{40})["\']?',
             'category': 'api_keys_found',
             'severity': 'CRITICAL',
             'validate': None,
            },
            {
                'name': 'GCP API Key',
                'regex': r'AIza[0-9A-Za-z\-_]{35}',
                'category': 'api_keys_found',
                'severity': 'MEDIUM',
                'validate': None,
            },
            {
                'name': 'Stripe Secret Key',
                'regex': r'sk_live_[0-9a-zA-Z]{24,}',
                'category': 'api_keys_found',
                'severity': 'CRITICAL',
                'validate': None,
            },
            {
                'name': 'Stripe Publishable Key',
                'regex': r'pk_live_[0-9a-zA-Z]{24,}',
                'category': 'api_keys_found',
                'severity': 'INFO',
                'validate': None,
            },
            {
                'name': 'Slack Token',
                'regex': r'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9\-]*',
                'category': 'api_keys_found',
                'severity': 'CRITICAL',
                'validate': None,
            },
            {
                'name': 'GitHub Token',
                'regex': r'gh[pousr]_[A-Za-z0-9_]{36,}',
                'category': 'api_keys_found',
                'severity': 'CRITICAL',
                'validate': None,
            },
            {
                'name': 'SendGrid API Key',
                'regex': r'SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}',
                'category': 'api_keys_found',
                'severity': 'CRITICAL',
                'validate': None,
            },
            {
                'name': 'Mailgun API Key',
                'regex': r'key-[0-9a-zA-Z]{32}',
                'category': 'api_keys_found',
                'severity': 'CRITICAL',
                'validate': None,
            },
            {
                'name': 'Firebase API Key',
                'regex': r'AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}',
                'category': 'api_keys_found',
                'severity': 'HIGH',
                'validate': None,
            },
            {
                'name': 'GCP OAuth Client ID',
                'regex': r'[0-9]{6,}-[a-z0-9]{32}\.apps\.googleusercontent\.com',
                'category': 'credentials_found',
                'severity': 'INFO',
                'validate': None,
            },
            {
                'name': 'Basic Auth in URL',
                'regex': r'https?://[^\s"\'<>{}]+:[^\s"\'<>{}]+@[a-zA-Z0-9][-a-zA-Z0-9.]+\.[a-zA-Z]{2,}',
                'category': 'credentials_found',
                'severity': 'CRITICAL',
                'validate': self._validate_basic_auth,
            },
            {
                'name': 'Private Key',
                'regex': r'-----BEGIN\s+(?:RSA\s+|EC\s+|DSA\s+|OPENSSH\s+)?PRIVATE\s+KEY-----',
                'category': 'credentials_found',
                'severity': 'CRITICAL',
                'validate': None,
            },
            {
                'name': 'Database Connection String',
                'regex': r'(?:mongodb|postgres|mysql|mssql|redis)://[^\s"\'<>]+:[^\s"\'<>]+@[^\s"\'<>]+',
                'category': 'credentials_found',
                'severity': 'CRITICAL',
                'validate': None,
            },
            {
                'name': 'Mapbox Public Token',
                'regex': r'pk\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+',
                'category': 'exposed_tokens',
                'severity': 'INFO',
                'validate': None,
            },
            {
                'name': 'Mapbox Secret Token',
                'regex': r'sk\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+',
                'category': 'exposed_tokens',
                'severity': 'CRITICAL',
                'validate': None,
            },
            {
                'name': 'Twilio Account SID',
                'regex': r'\bAC[0-9a-f]{32}\b',
                'category': 'exposed_tokens',
                'severity': 'HIGH',
                'validate': self._validate_twilio_sid,
            },
            {
                'name': 'Twilio Auth Token',
                'regex': r'(?:twilio|TWILIO)[^\n]{0,30}[0-9a-f]{32}',
                'category': 'exposed_tokens',
                'severity': 'CRITICAL',
                'validate': None,
            },
            {
                'name': 'Square Access Token',
                'regex': r'sq0atp-[0-9A-Za-z\-_]{22}',
                'category': 'exposed_tokens',
                'severity': 'CRITICAL',
                'validate': None,
            },
            {
                'name': 'Square OAuth Secret',
                'regex': r'sq0csp-[0-9A-Za-z\-_]{43}',
                'category': 'exposed_tokens',
                'severity': 'CRITICAL',
                'validate': None,
            },
            {
                'name': 'Hardcoded Password',
                'regex': r'(?:password|passwd|pwd|secret|api_key|apikey|api-key|access_token|auth_token)\s*[:=]\s*["\']([^"\']{8,64})["\']',
                'category': 'hardcoded_passwords',
                'severity': 'CRITICAL',
                'validate': self._validate_password,
                'flags': re.IGNORECASE,
            },
        ]
        # Pre-compile all regex patterns for performance
        for p in patterns:
            p['compiled'] = re.compile(p['regex'], p.get('flags', 0))
        return patterns

    # ──────────────────────────────────────────────
    #  VALIDATORS
    # ──────────────────────────────────────────────

    def _validate_basic_auth(self, match, context, url):
        matched = match.group(0)
        safe_domains = ['schema.org', 'w3.org', 'xmlns.com', 'purl.org',
                        'ogp.me', 'microformats.org', 'json-ld.org']
        for d in safe_domains:
            if d in matched:
                return False
        auth_m = re.search(r'://([^:]+):([^@]+)@', matched)
        if not auth_m:
            return False
        user, passwd = auth_m.group(1), auth_m.group(2)
        if passwd.isdigit() or len(passwd) < 4 or len(user) < 2:
            return False
        if re.search(r'content\s*=\s*["\']@', context):
            return False
        if re.search(r'twitter:|og:|meta\s+', context, re.IGNORECASE):
            if '@' in matched:
                return False
        return True

    def _validate_twilio_sid(self, match, context, url):
        matched = match.group(0)
        ctx_lower = context.lower()
        twilio_indicators = ['twilio', 'sms', 'voice', 'messaging', 'accountsid',
                             'account_sid', 'ACCOUNT_SID', 'twlo']
        if any(ind in ctx_lower for ind in twilio_indicators):
            return True
        if re.search(r'(?:class|id|style|data-[a-z]+|href|src)\s*=\s*["\'][^"\']*'
                     + re.escape(matched), context, re.IGNORECASE):
            return False
        if re.search(r'(?:color|background|border|#)[^;]*' + re.escape(matched[:8]), ctx_lower):
            return False
        return False

    def _validate_aws_secret(self, match, context, url):
        ctx = context.lower()
        indicators = ['aws', 'secret', 'access', 'key', 's3', 'iam', 'lambda',
                      'dynamodb', 'ec2', 'credential']
        return any(ind in ctx for ind in indicators)

    def _validate_password(self, match, context, url):
        if match.lastindex and match.group(1):
            val = match.group(1)
            placeholders = ['password', 'changeme', 'example', 'placeholder', 'xxx',
                            'your_', 'insert_', 'todo', 'fixme', 'none', 'null',
                            'undefined', '********', '${', '{{', 'process.env',
                            'os.environ', 'config.', 'settings.']
            if any(p in val.lower() for p in placeholders):
                return False
            if re.match(r'^[#.][a-zA-Z]', val):
                return False
            if re.match(r'^[a-zA-Z_]+$', val):
                return False
        return True

    # ──────────────────────────────────────────────
    #  UTILITIES
    # ──────────────────────────────────────────────

    def _mask_value(self, value):
        if len(value) <= 8:
            return value[:2] + '****'
        return value[:4] + '****' + value[-4:]

    def _get_context(self, text, match, radius=120):
        start = max(0, match.start() - radius)
        end = min(len(text), match.end() + radius)
        ctx = text[start:end].replace('\n', ' ').replace('\r', '').strip()
        prefix = '...' if start > 0 else ''
        suffix = '...' if end < len(text) else ''
        return f"{prefix}{ctx}{suffix}"

    def _resolve_url(self, host):
        """Find working URL for a hostname. Tries HTTPS first, falls back to HTTP."""
        for scheme in ['https', 'http']:
            url = f"{scheme}://{host}"
            try:
                resp = self.session.get(url, timeout=min(self.timeout, 5),
                                        allow_redirects=True, stream=True)
                resp.close()
                if resp.status_code < 500:
                    return url
            except requests.exceptions.SSLError:
                continue
            except requests.exceptions.ConnectionError:
                continue
            except Exception:
                continue
        return None

    def _fetch_page(self, url, _fallback=True):
        try:
            resp = self.session.get(url, timeout=self.timeout, allow_redirects=True)
            if resp.status_code == 200:
                return resp.text
        except requests.exceptions.SSLError:
            if _fallback and url.startswith('https://'):
                alt = 'http://' + url[8:]
                logger.debug(f"SSL failed for {url}, trying {alt}")
                return self._fetch_page(alt, _fallback=False)
        except requests.exceptions.ConnectionError:
            if _fallback and url.startswith('https://'):
                alt = 'http://' + url[8:]
                return self._fetch_page(alt, _fallback=False)
        except Exception as e:
            logger.debug(f"Fetch error {url}: {e}")
        return None

    def _extract_links(self, html, base_url):
        links = set()
        if HAS_BS4:
            try:
                soup = BeautifulSoup(html, 'html.parser')
                base_netloc = urlparse(base_url).netloc
                for a in soup.find_all('a', href=True):
                    full = urljoin(base_url, a['href'])
                    p = urlparse(full)
                    if p.netloc == base_netloc and p.scheme in ('http', 'https'):
                        clean = f"{p.scheme}://{p.netloc}{p.path}"
                        if p.query:
                            clean += f"?{p.query}"
                        links.add(clean)
            except Exception:
                pass
        else:
            for m in re.finditer(r'href=["\']([^"\']+)["\']', html):
                full = urljoin(base_url, m.group(1))
                p = urlparse(full)
                base_netloc = urlparse(base_url).netloc
                if p.netloc == base_netloc and p.scheme in ('http', 'https'):
                    links.add(f"{p.scheme}://{p.netloc}{p.path}")
        return links

    def _extract_js_files(self, html, base_url):
        js = set()
        for m in re.finditer(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.IGNORECASE):
            js.add(urljoin(base_url, m.group(1)))
        return js

    # ──────────────────────────────────────────────
    #  SCANNING
    # ──────────────────────────────────────────────

    def _scan_text(self, text, source_url, source_type):
        findings = []
        for pattern in self.patterns:
            for match in pattern['compiled'].finditer(text):
                matched_value = match.group(0)
                context = self._get_context(text, match)

                if pattern.get('validate'):
                    if not pattern['validate'](match, context, source_url):
                        continue

                dedup_key = (pattern['name'], matched_value.strip())

                if dedup_key in self.seen_secrets:
                    existing = self.seen_secrets[dedup_key]
                    loc_urls = {l['url'] for l in existing['locations']}
                    if source_url not in loc_urls:
                        existing['locations'].append({
                            'url': source_url,
                            'source_type': source_type,
                        })
                    continue

                finding = {
                    'type': pattern['name'],
                    'source_url': source_url,
                    'source_type': source_type,
                    'masked_value': self._mask_value(matched_value),
                    'severity': pattern['severity'],
                    'context': context,
                    'category': pattern['category'],
                    '_raw': matched_value,
                    'locations': [{'url': source_url, 'source_type': source_type}],
                }
                self.seen_secrets[dedup_key] = finding
                findings.append(finding)

        return findings

    def _check_sensitive_files(self, base_url):
        env_files = []
        config_leaks = []
        paths = {
            'env': [
                '/.env', '/.env.local', '/.env.production', '/.env.staging',
                '/.env.development', '/.env.backup',
            ],
            'config': [
                '/.git/config', '/.git/HEAD', '/.svn/entries',
                '/config.json', '/config.yaml', '/config.yml',
                '/wp-config.php.bak', '/phpinfo.php',
                '/server-status', '/server-info',
                '/.htpasswd', '/web.config', '/package.json',
                '/composer.json', '/database.yml',
            ],
        }

        all_checks = []
        for cat, path_list in paths.items():
            for p in path_list:
                all_checks.append((cat, p))

        def _check_one(cat_path):
            cat, path = cat_path
            url = base_url.rstrip('/') + path
            try:
                resp = self.session.get(
                    url, timeout=5, allow_redirects=False
                )
                if resp.status_code != 200:
                    return None
                body = resp.text.lower()
                if len(resp.text) < 50:
                    return None
                if '<html' in body and any(
                    x in body for x in
                    ['not found', '404', 'error page', 'page not found']
                ):
                    return None
                if cat == 'env' and not any(
                    x in resp.text for x in
                    ['=', 'export ', 'DB_', 'API_', 'SECRET', 'KEY']
                ):
                    return None
                return (cat, {
                    'path': path,
                    'url': url,
                    'status_code': resp.status_code,
                    'size': len(resp.text),
                    'severity': 'CRITICAL' if cat == 'env' else 'HIGH',
                })
            except Exception:
                return None

        with ThreadPoolExecutor(max_workers=10) as executor:
            for result in executor.map(_check_one, all_checks):
                if result:
                    cat, finding = result
                    if cat == 'env':
                        env_files.append(finding)
                    else:
                        config_leaks.append(finding)

        return env_files, config_leaks

    def run(self, target_domain, subdomains=None, webapp_results=None):
        console.print(f"\n[bold cyan]{'='*60}[/bold cyan]")
        console.print(f"[bold cyan]  Module 10: Secret & Credential Scanner - {target_domain}[/bold cyan]")
        console.print(f"[bold cyan]{'='*60}[/bold cyan]\n")
        
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        self.visited = set()
        self.seen_secrets = OrderedDict()
        all_findings = []
        crawled_urls = []
        js_scanned = set()
        all_env = []
        all_config = []

        # ── Build target list with dedup ──
        max_subs = self.config.get("SECRET_MAX_TARGETS", 150)
        seen_hosts = set()
        targets = []

        # Add root domain
        root = target_domain.strip().lower().rstrip('.')
        seen_hosts.add(root)
        targets.append(root)

        # Add subdomains (handle both strings and dicts)
        if subdomains:
            for sub in subdomains:
                if isinstance(sub, dict):
                    sub = sub.get('subdomain', sub.get('domain',
                          sub.get('name', sub.get('host', ''))))
                if not isinstance(sub, str):
                    try:
                        sub = str(sub)
                    except Exception:
                        continue
                sub = sub.strip().lower().rstrip('.')
                if sub and sub not in seen_hosts:
                    seen_hosts.add(sub)
                    targets.append(sub)
                if len(targets) >= max_subs + 1:
                    break

        # Extract additional URLs from webapp results
        extra_urls = []
        if webapp_results and isinstance(webapp_results, dict):
            for key in ('urls_found', 'crawled_urls', 'api_endpoints', 'endpoints'):
                urls = webapp_results.get(key, [])
                if isinstance(urls, list):
                    for u in urls:
                        if isinstance(u, str) and u.startswith('http'):
                            extra_urls.append(u)
                        elif isinstance(u, dict) and u.get('url', '').startswith('http'):
                            extra_urls.append(u['url'])

        # ── Resolve hostnames to working URLs (HTTPS → HTTP fallback) ──
        print(f"\n{'='*60}")
        print(f"  SECRET SCANNER - Resolving {len(targets)} host(s)")
        print(f"{'='*60}")

        target_urls = []
        unreachable = []

        def _resolve_one(host):
            if host.startswith('http'):
                return (host, host, 'PROVIDED')
            resolved = self._resolve_url(host)
            if resolved:
                scheme = 'HTTPS' if resolved.startswith('https') else 'HTTP'
                return (host, resolved, scheme)
            return (host, None, None)

        with ThreadPoolExecutor(max_workers=15) as executor:
            futures = [executor.submit(_resolve_one, t) for t in targets]
            for future in as_completed(futures):
                host, url, scheme = future.result()
                if url:
                    target_urls.append(url)
                    if scheme != 'PROVIDED':
                        print(f"  [+] {host} -> {url} ({scheme})")
                else:
                    unreachable.append(host)

        # Add extra URLs from webapp scanner
        seen_urls = set(target_urls)
        for u in extra_urls[:20]:
            if u not in seen_urls:
                target_urls.append(u)
                seen_urls.add(u)

        if unreachable:
            print(f"\n  [-] {len(unreachable)} host(s) unreachable:")
            for h in unreachable[:10]:
                print(f"      - {h}")
            if len(unreachable) > 10:
                print(f"      ... +{len(unreachable) - 10} more")

        print(f"\n{'='*60}")
        print(f"  SECRET SCANNER - Scanning {len(target_urls)} live target(s)")
        print(f"{'='*60}")

        if not target_urls:
            print("  [!] No reachable targets found. Check domain/subdomains.")
            return {
                'credentials_found': [], 'api_keys_found': [],
                'hardcoded_passwords': [], 'exposed_tokens': [],
                'js_files_scanned': [], 'api_endpoints_found': [],
                'env_files': [], 'config_leaks': [],
                'files_scanned': [], 'crawled_urls': [],
                'false_positives_filtered': 0, 'unique_secrets_count': 0,
                'total_occurrences': 0, 'next_steps': [],
                'shadow_it_flags': [],
            }

        for target_url in target_urls:
            print(f"\n[*] Scanning: {target_url}")
            html = self._fetch_page(target_url)
            if not html:
                print(f"  [-] Could not fetch {target_url}")
                continue

            self.visited.add(target_url)
            findings = self._scan_text(html, target_url, "HTML Page")
            all_findings.extend(findings)

            js_files = self._extract_js_files(html, target_url)
            for js_url in js_files:
                if js_url not in js_scanned:
                    js_scanned.add(js_url)
                    jsc = self._fetch_page(js_url)
                    if jsc:
                        jf = self._scan_text(jsc, js_url, "JavaScript File")
                        all_findings.extend(jf)
                        time.sleep(0.15)

            links = self._extract_links(html, target_url)
            count = 0
            for link in links:
                if count >= self.max_crawl:
                    break
                if link in self.visited:
                    continue
                self.visited.add(link)
                lhtml = self._fetch_page(link)
                if not lhtml:
                    continue
                crawled_urls.append(link)
                count += 1
                pf = self._scan_text(lhtml, link, "Crawled Page")
                all_findings.extend(pf)

                pjs = self._extract_js_files(lhtml, link)
                for js_url in pjs:
                    if js_url not in js_scanned:
                        js_scanned.add(js_url)
                        jsc = self._fetch_page(js_url)
                        if jsc:
                            jf = self._scan_text(jsc, js_url, "JavaScript File")
                            all_findings.extend(jf)
                time.sleep(0.25)

            ef, cl = self._check_sensitive_files(target_url)
            all_env.extend(ef)
            all_config.extend(cl)

        # ── Build results ──
        unique = list(self.seen_secrets.values())
        creds, keys, passwords, tokens = [], [], [], []
        shadow_flags = []

        for s in unique:
            out = {
                'type': s['type'],
                'source_url': s['source_url'],
                'source_type': s['source_type'],
                'masked_value': s['masked_value'],
                'severity': s['severity'],
                'context': s['context'],
                'locations': s['locations'],
                'occurrence_count': len(s['locations']),
            }
            cat = s['category']
            if cat == 'credentials_found':
                creds.append(out)
            elif cat == 'api_keys_found':
                keys.append(out)
            elif cat == 'hardcoded_passwords':
                passwords.append(out)
            elif cat == 'exposed_tokens':
                tokens.append(out)

            if s['severity'] in ('HIGH', 'CRITICAL'):
                shadow_flags.append({
                    'type': f"Exposed Secret ({s['type']})",
                    'asset': s['source_url'],
                    'reason': f"{s['type']} found across {len(s['locations'])} page(s). Rotate immediately.",
                    'module': 'secret_scanner',
                })

        total_raw = sum(len(s['locations']) for s in unique)
        fp_filtered = total_raw - len(unique)

        self._print_summary(unique, fp_filtered)

        next_steps = self._build_next_steps(keys, tokens, creds, passwords)

        return {
            'credentials_found': creds,
            'api_keys_found': keys,
            'hardcoded_passwords': passwords,
            'exposed_tokens': tokens,
            'js_files_scanned': list(js_scanned),
            'api_endpoints_found': [],
            'env_files': all_env,
            'config_leaks': all_config,
            'files_scanned': list(self.visited),
            'crawled_urls': crawled_urls,
            'false_positives_filtered': fp_filtered,
            'unique_secrets_count': len(unique),
            'total_occurrences': total_raw,
            'next_steps': next_steps,
            'shadow_it_flags': shadow_flags,
        }

    # ──────────────────────────────────────────────
    #  REPORTING
    # ──────────────────────────────────────────────

    def _build_next_steps(self, keys, tokens, creds, passwords):
        steps = []
        crit_keys = [k for k in keys if k['severity'] == 'CRITICAL']
        if crit_keys:
            steps.append({'action': 'Rotate Exposed API Keys',
                          'description': f"{len(crit_keys)} critical API key(s) found.", 'priority': 'CRITICAL'})
        crit_tok = [t for t in tokens if t['severity'] in ('HIGH', 'CRITICAL')]
        if crit_tok:
            steps.append({'action': 'Revoke Exposed Tokens',
                          'description': f"{len(crit_tok)} high/critical token(s) found.", 'priority': 'HIGH'})
        if creds:
            steps.append({'action': 'Rotate Exposed Credentials',
                          'description': f"{len(creds)} credential(s) found.", 'priority': 'CRITICAL'})
        if passwords:
            steps.append({'action': 'Remove Hardcoded Passwords',
                          'description': f"{len(passwords)} hardcoded password(s) found.", 'priority': 'CRITICAL'})
        if any([keys, tokens, creds, passwords]):
            steps.append({'action': 'Implement Secret Scanning in CI/CD',
                          'description': 'Use trufflehog/gitleaks in CI.', 'priority': 'HIGH'})
        return steps

    def _print_summary(self, unique, fp_filtered):
        print(f"\n{'='*80}")
        print(f"  SECRET SCAN RESULTS (DEDUPLICATED)")
        print(f"{'='*80}")
        print(f"  Unique secrets: {len(unique)}  |  Duplicates filtered: {fp_filtered}")
        print(f"{'='*80}")
        if not unique:
            print("  No secrets found.\n")
            return
        sev_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}
        tc = {}
        for s in unique:
            k = (s['type'], s['severity'])
            tc[k] = tc.get(k, 0) + 1
        print(f"\n  {'Type':<30} {'Severity':<10} {'Unique':<8} {'Pages':<8}")
        print(f"  {'-'*30} {'-'*10} {'-'*8} {'-'*8}")
        for (t, sv), c in sorted(tc.items(), key=lambda x: sev_order.get(x[0][1], 5)):
            pages = sum(len(s['locations']) for s in unique if s['type'] == t)
            print(f"  {t:<30} {sv:<10} {c:<8} {pages:<8}")
        print(f"\n  {'='*80}")
        print(f"  DETAILED FINDINGS")
        print(f"  {'='*80}")
        icons = {'CRITICAL': '[!!]', 'HIGH': '[!]', 'MEDIUM': '[~]', 'LOW': '[.]', 'INFO': '[i]'}
        for i, s in enumerate(sorted(unique, key=lambda x: sev_order.get(x['severity'], 5)), 1):
            icon = icons.get(s['severity'], '[?]')
            print(f"\n  {icon} #{i}: {s['type']} ({s['severity']})")
            print(f"      Value: {s['masked_value']}")
            print(f"      Found on {len(s['locations'])} page(s):")
            for loc in s['locations'][:5]:
                print(f"        - {loc['url']} ({loc['source_type']})")
            if len(s['locations']) > 5:
                print(f"        ... +{len(s['locations'])-5} more")
        print(f"\n{'='*80}\n")