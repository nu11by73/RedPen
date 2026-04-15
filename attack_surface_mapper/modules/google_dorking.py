"""
Google Dorking Module for Subdomain & Exposure Discovery
Supports two modes:
  1. Google Custom Search API (recommended - no CAPTCHA)
  2. Direct scraping fallback (rate-limited, CAPTCHA risk)

API Setup:
  1. Create API key: https://console.cloud.google.com/apis/credentials
  2. Create Custom Search Engine: https://programmablesearchengine.google.com/
     - Toggle "Search the entire web" = ON
  3. Set GOOGLE_API_KEY and GOOGLE_CX_ID in config.py
"""

import re
import time
import random
import logging
import requests
from urllib.parse import urlparse, quote_plus

logger = logging.getLogger(__name__)


class GoogleDorker:
    def __init__(self, config=None):
        self.config = config if isinstance(config, dict) else {}
        self.timeout = self.config.get('REQUEST_TIMEOUT', 10)
        self.found_subdomains = set()
        self.found_urls = set()
        self.captcha_hit = False
        self.results_log = []
        self.api_queries_used = 0

        # API credentials
        self.api_key = self.config.get('GOOGLE_API_KEY', '').strip()
        self.cx_id = self.config.get('GOOGLE_CX_ID', '').strip()
        self.max_pages = self.config.get('GOOGLE_DORKING_MAX_PAGES', 5)
        self.use_api = bool(self.api_key and self.cx_id)

        # Session for scraping fallback
        self.session = requests.Session()
        self.session.verify = False
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36 Edg/123.0.0.0',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
        ]

    # ──────────────────────────────────────────────
    #  GOOGLE CUSTOM SEARCH API
    # ──────────────────────────────────────────────

    def _search_api(self, query, num_pages=None):
        """
        Search via Google Custom Search JSON API.
        Free: 100 queries/day. Each page = 1 API query.
        Max 10 results per query, max startIndex = 91 (10 pages).
        """
        if num_pages is None:
            num_pages = min(self.max_pages, 10)

        urls_found = set()
        api_url = "https://www.googleapis.com/customsearch/v1"

        for page in range(num_pages):
            start_index = (page * 10) + 1
            if start_index > 91:
                break

            params = {
                'key': self.api_key,
                'cx': self.cx_id,
                'q': query,
                'start': start_index,
                'num': 10,
            }

            try:
                resp = requests.get(api_url, params=params, timeout=self.timeout)
                self.api_queries_used += 1

                if resp.status_code == 429:
                    print(f"  [!] Google API rate limit hit (429). Daily quota may be exhausted.")
                    self.results_log.append({
                        'query': query, 'status': 'RATE_LIMITED', 'page': page,
                        'method': 'API'
                    })
                    break

                if resp.status_code == 403:
                    error_msg = resp.json().get('error', {}).get('message', 'Forbidden')
                    if 'quota' in error_msg.lower() or 'limit' in error_msg.lower():
                        print(f"  [!] Google API daily quota exceeded.")
                    else:
                        print(f"  [!] Google API error 403: {error_msg}")
                    self.results_log.append({
                        'query': query, 'status': f'API_ERROR_403: {error_msg}',
                        'page': page, 'method': 'API'
                    })
                    break

                if resp.status_code != 200:
                    logger.debug(f"Google API returned {resp.status_code}: {resp.text[:200]}")
                    continue

                data = resp.json()
                items = data.get('items', [])

                if not items:
                    break

                for item in items:
                    link = item.get('link', '')
                    if link:
                        urls_found.add(link)
                    # Also check displayLink and formattedUrl
                    display = item.get('displayLink', '')
                    if display:
                        urls_found.add(f"https://{display}")
                    formatted = item.get('formattedUrl', '')
                    if formatted:
                        if not formatted.startswith('http'):
                            formatted = f"https://{formatted}"
                        urls_found.add(formatted)

                # Check if there are more results
                next_page = data.get('queries', {}).get('nextPage')
                if not next_page:
                    break

                # Small delay between API calls (be respectful)
                time.sleep(0.3)

            except requests.exceptions.Timeout:
                logger.debug(f"API timeout for: {query}")
                break
            except Exception as e:
                logger.debug(f"API error: {e}")
                break

        self.results_log.append({
            'query': query,
            'status': 'OK',
            'urls_found': len(urls_found),
            'method': 'API',
        })

        return urls_found

    # ──────────────────────────────────────────────
    #  DIRECT SCRAPING FALLBACK
    # ──────────────────────────────────────────────

    def _get_headers(self):
        return {
            'User-Agent': random.choice(self.user_agents),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Referer': 'https://www.google.com/',
        }

    def _search_scrape(self, query, num_pages=3):
        """Scrape Google search results directly. CAPTCHA risk."""
        urls_found = set()

        if self.captcha_hit:
            logger.debug("Skipping query - CAPTCHA was hit previously")
            return urls_found

        for page in range(num_pages):
            start = page * 10
            search_url = f"https://www.google.com/search?q={quote_plus(query)}&start={start}&num=100"

            try:
                delay = random.uniform(3.0, 7.0) if page > 0 else random.uniform(1.5, 3.0)
                time.sleep(delay)

                resp = self.session.get(
                    search_url, headers=self._get_headers(),
                    timeout=self.timeout, allow_redirects=True
                )

                blocked = (
                resp.status_code == 429
                or 'captcha' in resp.text.lower()
                or '/sorry/' in resp.url
                or 'support.google.com/websearch' in resp.text
                or 'unusual traffic' in resp.text.lower()
                or 'automated requests' in resp.text.lower()
                or resp.url.startswith('https://consent.google')
                )
                if blocked:
                    print(f"  [!] Google CAPTCHA/rate limit hit. Pausing scraping.")
                    self.captcha_hit = True
                    self.results_log.append({
                        'query': query, 'status': 'CAPTCHA', 'page': page,
                        'method': 'SCRAPE'
                    })
                    break

                if resp.status_code != 200:
                    continue

                html = resp.text

                for m in re.finditer(r'<a[^>]+href="(/url\?q=|)(https?://[^"&]+)', html):
                    urls_found.add(m.group(2))

                for m in re.finditer(r'<cite[^>]*>([^<]+)</cite>', html):
                    cite = m.group(1).strip()
                    cite = re.sub(r'<[^>]+>', '', cite)
                    cite = cite.replace(' › ', '/').replace('›', '/')
                    if not cite.startswith('http'):
                        cite = 'https://' + cite
                    urls_found.add(cite)

                for m in re.finditer(r'(?:data-href|ping)="(https?://[^"]+)"', html):
                    urls_found.add(m.group(1))

                if 'Next' not in html and 'aria-label="Next"' not in html:
                    break

            except requests.exceptions.Timeout:
                break
            except Exception as e:
                logger.debug(f"Scrape error: {e}")
                break

        self.results_log.append({
            'query': query,
            'status': 'OK' if not self.captcha_hit else 'CAPTCHA',
            'urls_found': len(urls_found),
            'method': 'SCRAPE',
        })

        return urls_found

    # ──────────────────────────────────────────────
    #  UNIFIED SEARCH METHOD
    # ──────────────────────────────────────────────

    def _search(self, query, num_pages=None):
        """Route to API or scraping based on config."""
        if self.use_api:
            return self._search_api(query, num_pages)
        else:
            pages = num_pages or 3
            return self._search_scrape(query, pages)

    # ──────────────────────────────────────────────
    #  SUBDOMAIN EXTRACTION
    # ──────────────────────────────────────────────

    def _extract_subdomains_from_urls(self, urls, target_domain):
        subdomains = set()
        target_clean = target_domain.lower().lstrip('.')

        sub_pattern = re.compile(r'([a-zA-Z0-9][-a-zA-Z0-9]*\.)+' + re.escape(target_clean))
        for url in urls:
            try:
                parsed = urlparse(url if url.startswith('http') else f'https://{url}')
                hostname = parsed.netloc.lower().split(':')[0]

                if not hostname:
                    hostname = url.lower().split('/')[0].split(':')[0]

                if hostname.endswith('.' + target_clean) or hostname == target_clean:
                    subdomains.add(hostname)

                for m in sub_pattern.finditer(url):
                    subdomains.add(m.group(0).lower())

            except Exception:
                continue

        return subdomains

    # ──────────────────────────────────────────────
    #  MAIN RUN
    # ──────────────────────────────────────────────

    def run(self, target_domain):
        """
        Run Google dorking for subdomain and exposure discovery.
        Uses API if GOOGLE_API_KEY and GOOGLE_CX_ID are set, otherwise scrapes.
        """
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        target = target_domain.lower().replace('https://', '').replace('http://', '').rstrip('/')

        print(f"\n{'='*60}")
        print(f"  GOOGLE DORKING - Target: {target}")
        if self.use_api:
            print(f"  Mode: Custom Search API (no CAPTCHA)")
        else:
            print(f"  Mode: Direct scraping (CAPTCHA risk)")
            print(f"  Tip: Set GOOGLE_API_KEY & GOOGLE_CX_ID in config.py for reliable results")
        print(f"{'='*60}")

        # ── Build dork queries ──
        dorks = self._build_dorks(target)

        all_urls = set()
        all_subdomains = set()
        dork_findings = []

        for i, dork_entry in enumerate(dorks, 1):
            query = dork_entry['query']
            category = dork_entry['category']
            pages = dork_entry.get('pages', 3 if not self.use_api else self.max_pages)

            if not self.use_api and self.captcha_hit:
                remaining = len(dorks) - i + 1
                print(f"  [!] Skipping {remaining} remaining dork(s) due to CAPTCHA")
                break

            label = query[:65] + '...' if len(query) > 65 else query
            print(f"  [{i}/{len(dorks)}] {label}")

            urls = self._search(query, pages)

            if urls:
                all_urls.update(urls)
                subs = self._extract_subdomains_from_urls(urls, target)
                new_subs = subs - all_subdomains
                all_subdomains.update(subs)

                if new_subs:
                    print(f"       -> {len(new_subs)} new subdomain(s)")
                    for s in sorted(new_subs):
                        print(f"          + {s}")

                # Categorize findings
                for url in urls:
                    finding = self._classify_finding(url, query, category)
                    if finding:
                        dork_findings.append(finding)

            # Delay between queries
            if self.use_api:
                time.sleep(0.5)
            elif not self.captcha_hit:
                time.sleep(random.uniform(2.0, 5.0))

        # Remove base domain from subdomain list
        all_subdomains.discard(target)
        all_subdomains.discard('www.' + target)

        # Deduplicate findings
        dork_findings = self._dedup_findings(dork_findings)

        # ── Summary ──
        self._print_summary(target, dorks, all_urls, all_subdomains, dork_findings)

        return {
            'subdomains': sorted(all_subdomains),
            'urls_found': sorted(all_urls),
            'dork_findings': dork_findings,
            'dorks_executed': sum(1 for r in self.results_log if r['status'] not in ('CAPTCHA', 'RATE_LIMITED')),
            'dorks_total': len(dorks),
            'captcha_hit': self.captcha_hit,
            'api_mode': self.use_api,
            'api_queries_used': self.api_queries_used,
            'query_log': self.results_log,
            'shadow_it_flags': self._build_shadow_flags(dork_findings),
            'next_steps': self._build_next_steps(dork_findings, all_subdomains),
        }

    # ──────────────────────────────────────────────
    #  DORK QUERIES
    # ──────────────────────────────────────────────

    def _build_dorks(self, target):
     """Build categorized dork queries for the target."""
     dorks = []

     def add(query, category, pages=None):
         entry = {'query': query, 'category': category}
         if pages:
             entry['pages'] = pages
         dorks.append(entry)

     # ── Subdomain Discovery (FIXED - no wildcard) ──
     # Google indexes subdomains under site:domain.com
     # Exclude www to surface other subdomains
     add(f'site:{target} -www.{target}', 'subdomain_discovery', 5)

     # Progressively exclude known subdomains to find more
     # (Google only returns ~100 results, so excluding known ones surfaces new ones)
     add(f'site:{target} -www.{target} -mail.{target}', 'subdomain_discovery', 3)
     add(f'site:{target} -www.{target} -mail.{target} -blog.{target} -shop.{target}', 'subdomain_discovery', 3)

     # ── Target specific subdomain patterns ──
     # These find subdomains by searching for content hosted on them
     add(f'site:{target} inurl:portal OR inurl:client OR inurl:account OR inurl:app', 'subdomain_discovery', 3)
     add(f'site:{target} inurl:my OR inurl:secure OR inurl:dashboard OR inurl:service', 'subdomain_discovery', 3)

     # ── Environment/Staging Discovery ──
     add(f'site:{target} inurl:dev OR inurl:staging OR inurl:test OR inurl:sandbox', 'environment_discovery')
     add(f'site:{target} inurl:uat OR inurl:preprod OR inurl:qa OR inurl:demo', 'environment_discovery')
     add(f'site:{target} inurl:api OR inurl:admin OR inurl:portal OR inurl:login', 'admin_panels')
     add(f'site:{target} inurl:vpn OR inurl:remote OR inurl:owa OR inurl:webmail', 'remote_access')
 
     # ── Exposed Files ──
     add(f'site:{target} intitle:"index of"', 'directory_listing')
     add(f'site:{target} filetype:conf OR filetype:env OR filetype:log', 'sensitive_files')
     add(f'site:{target} filetype:sql OR filetype:bak OR filetype:old', 'backup_files')
     add(f'site:{target} filetype:xml OR filetype:json inurl:config', 'config_files')
     add(f'site:{target} filetype:key OR filetype:pem OR filetype:crt', 'crypto_files')

     # ── Error/Debug Pages ──
     add(f'site:{target} intitle:"error" OR intitle:"exception" OR intitle:"stack trace"', 'error_pages')
     add(f'site:{target} intext:"sql syntax" OR intext:"mysql_fetch" OR intext:"ORA-"', 'sql_errors')
     add(f'site:{target} intext:"phpinfo" OR intitle:"phpinfo()"', 'info_disclosure')
     add(f'site:{target} intext:"debug" intitle:"debug" OR inurl:debug', 'debug_pages')

     # ── Login & Auth ──
     add(f'site:{target} intitle:"login" OR intitle:"sign in"', 'login_pages')
     add(f'site:{target} inurl:auth OR inurl:sso OR inurl:oauth OR inurl:saml', 'auth_endpoints')

     # ── Documents ──
     add(f'site:{target} filetype:pdf', 'documents')
     add(f'site:{target} filetype:xlsx OR filetype:xls OR filetype:csv', 'spreadsheets')
     add(f'site:{target} filetype:doc OR filetype:docx OR filetype:pptx', 'documents')

     # ── Exposed Panels ──
     add(f'site:{target} intitle:"dashboard" OR intitle:"admin panel" OR intitle:"control panel"', 'admin_panels')
     add(f'site:{target} inurl:jenkins OR inurl:grafana OR inurl:kibana OR inurl:jira', 'devops_tools')
     add(f'site:{target} inurl:phpmyadmin OR inurl:adminer OR inurl:phpinfo', 'database_tools')

     # ── Cloud/Storage ──
     add(f'site:s3.amazonaws.com "{target}"', 'cloud_storage')
     add(f'site:blob.core.windows.net "{target}"', 'cloud_storage')
     add(f'site:storage.googleapis.com "{target}"', 'cloud_storage')

     # ── Paste Sites / Code Repos (leaked data) ──
     add(f'site:pastebin.com "{target}"', 'paste_leaks')
     add(f'site:github.com "{target}" password OR secret OR api_key', 'code_leaks')
     add(f'site:trello.com "{target}"', 'project_leaks')
 
     return dorks

    # ──────────────────────────────────────────────
    #  FINDING CLASSIFICATION
    # ──────────────────────────────────────────────

    def _classify_finding(self, url, dork_query, category):
        """Classify a URL finding by severity and type."""
        url_lower = url.lower()
        path = urlparse(url).path.lower()

        severity_map = {
            'sensitive_files': 'HIGH',
            'backup_files': 'HIGH',
            'crypto_files': 'CRITICAL',
            'config_files': 'HIGH',
            'directory_listing': 'MEDIUM',
            'sql_errors': 'HIGH',
            'info_disclosure': 'MEDIUM',
            'debug_pages': 'HIGH',
            'database_tools': 'CRITICAL',
            'devops_tools': 'HIGH',
            'code_leaks': 'HIGH',
            'paste_leaks': 'HIGH',
            'cloud_storage': 'MEDIUM',
            'admin_panels': 'MEDIUM',
            'auth_endpoints': 'LOW',
            'login_pages': 'INFO',
            'remote_access': 'MEDIUM',
            'environment_discovery': 'MEDIUM',
            'subdomain_discovery': 'INFO',
            'documents': 'LOW',
            'spreadsheets': 'LOW',
            'project_leaks': 'MEDIUM',
        }

        # Boost severity for certain file extensions
        critical_extensions = ['.env', '.pem', '.key', '.sql', '.bak', '.conf']
        high_extensions = ['.log', '.old', '.config', '.yml', '.yaml']

        severity = severity_map.get(category, 'INFO')

        if any(path.endswith(ext) for ext in critical_extensions):
            severity = 'CRITICAL'
        elif any(path.endswith(ext) for ext in high_extensions):
            if severity not in ('CRITICAL',):
                severity = 'HIGH'

        # Only return findings that are at least LOW severity
        if severity == 'INFO' and category in ('subdomain_discovery', 'documents', 'login_pages'):
            return None

        finding_type_map = {
            'sensitive_files': 'Indexed Sensitive File',
            'backup_files': 'Indexed Backup File',
            'crypto_files': 'Indexed Cryptographic Material',
            'config_files': 'Indexed Config File',
            'directory_listing': 'Directory Listing',
            'sql_errors': 'SQL Error Disclosure',
            'info_disclosure': 'Information Disclosure',
            'debug_pages': 'Debug Page Exposed',
            'database_tools': 'Exposed Database Tool',
            'devops_tools': 'Exposed DevOps Tool',
            'code_leaks': 'Code Repository Leak',
            'paste_leaks': 'Paste Site Leak',
            'cloud_storage': 'Cloud Storage Reference',
            'admin_panels': 'Admin Panel',
            'remote_access': 'Remote Access Endpoint',
            'environment_discovery': 'Non-Production Environment',
            'project_leaks': 'Project Management Leak',
        }

        finding_type = finding_type_map.get(category, category.replace('_', ' ').title())

        return {
            'type': finding_type,
            'url': url,
            'dork': dork_query,
            'category': category,
            'severity': severity,
        }

    def _dedup_findings(self, findings):
        """Deduplicate findings by URL."""
        seen = set()
        unique = []
        for f in findings:
            if f is None:
                continue
            key = f['url']
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique

    # ──────────────────────────────────────────────
    #  OUTPUT
    # ──────────────────────────────────────────────

    def _print_summary(self, target, dorks, all_urls, all_subdomains, dork_findings):
        executed = sum(1 for r in self.results_log if r['status'] not in ('CAPTCHA', 'RATE_LIMITED'))

        print(f"\n{'='*60}")
        print(f"  GOOGLE DORKING RESULTS")
        print(f"{'='*60}")
        print(f"  Mode:            {'API' if self.use_api else 'Scraping'}")
        if self.use_api:
            print(f"  API queries:     {self.api_queries_used}")
        print(f"  Dorks executed:  {executed}/{len(dorks)}")
        print(f"  Unique URLs:     {len(all_urls)}")
        print(f"  Subdomains:      {len(all_subdomains)}")
        print(f"  Findings:        {len(dork_findings)}")

        if self.captcha_hit:
            print(f"  ⚠ CAPTCHA hit - results incomplete")
            print(f"    Set GOOGLE_API_KEY & GOOGLE_CX_ID in config.py to avoid this")

        print(f"{'='*60}")

        if all_subdomains:
            print(f"\n  Subdomains via Google:")
            for s in sorted(all_subdomains):
                print(f"    • {s}")

        if dork_findings:
            sev_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}
            print(f"\n  Notable Findings:")
            for f in sorted(dork_findings, key=lambda x: sev_order.get(x['severity'], 5))[:20]:
                icon = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🔵'}.get(f['severity'], '⚪')
                print(f"    {icon} [{f['severity']}] {f['type']}: {f['url'][:80]}")
            if len(dork_findings) > 20:
                print(f"    ... and {len(dork_findings) - 20} more")

        print()

    def _build_shadow_flags(self, findings):
        flags = []
        for f in findings:
            if f['severity'] in ('CRITICAL', 'HIGH'):
                flags.append({
                    'type': f'Google Indexed: {f["type"]}',
                    'asset': f['url'],
                    'reason': f'{f["type"]} found via Google dork. Severity: {f["severity"]}.',
                    'module': 'google_dorking',
                })
        return flags

    def _build_next_steps(self, findings, subdomains):
        steps = []
        sevs = [f['severity'] for f in findings]

        if 'CRITICAL' in sevs:
            crit = [f for f in findings if f['severity'] == 'CRITICAL']
            steps.append({
                'action': 'Remove Critical Google-Indexed Exposures',
                'description': f'{len(crit)} critical item(s) indexed by Google. Request removal via Google Search Console.',
                'priority': 'CRITICAL',
            })

        cats = set(f['category'] for f in findings)
        if 'sensitive_files' in cats or 'backup_files' in cats:
            steps.append({
                'action': 'Remove Sensitive Files from Web Root',
                'description': 'Config, backup, and sensitive files are indexed. Remove and block via robots.txt/.htaccess.',
                'priority': 'HIGH',
            })

        if 'directory_listing' in cats:
            steps.append({
                'action': 'Disable Directory Listing',
                'description': 'Open directory listings found. Disable in web server config.',
                'priority': 'HIGH',
            })

        if 'code_leaks' in cats or 'paste_leaks' in cats:
            steps.append({
                'action': 'Investigate External Code/Paste Leaks',
                'description': 'References to the target found on GitHub/Pastebin. Check for leaked credentials.',
                'priority': 'HIGH',
            })

        if subdomains:
            steps.append({
                'action': 'Review Discovered Subdomains',
                'description': f'{len(subdomains)} subdomain(s) found via Google. Verify they are authorized and secured.',
                'priority': 'MEDIUM',
            })

        return steps