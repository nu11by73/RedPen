"""
Alternative to Google Dorking: Wayback Machine + URLScan.io
No CAPTCHA, no rate limit issues, free.
"""

import re
import time
import requests
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class DorkAlternative:
    """Drop-in replacement for GoogleDorker with same interface."""

    def __init__(self, config=None):
        self.config = config if isinstance(config, dict) else {}
        self.timeout = self.config.get('REQUEST_TIMEOUT', 10)
        self.urlscan_key = self.config.get('URLSCAN_API_KEY', '').strip()
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                          'AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36'
        })

    # ──────────────────────────────────────────────
    #  WAYBACK MACHINE CDX API
    # ──────────────────────────────────────────────

    def _wayback_urls(self, domain):
        """
        Query Wayback Machine CDX for all archived URLs.
        Free, no key, no rate limit for reasonable use.
        """
        print(f"  [*] Wayback Machine CDX: {domain}")
        urls = set()

        try:
            resp = self.session.get(
                "https://web.archive.org/cdx/search/cdx",
                params={
                    "url": f"*.{domain}/*",
                    "output": "text",
                    "fl": "original",
                    "collapse": "urlkey",
                    "limit": "50000",
                },
                timeout=30,
            )
            if resp.status_code == 200:
                for line in resp.text.strip().splitlines():
                    line = line.strip()
                    if line and line.startswith("http"):
                        urls.add(line)
                print(f"    [+] {len(urls)} archived URLs found")
            else:
                print(f"    [-] Wayback returned {resp.status_code}")
        except Exception as e:
            print(f"    [-] Wayback error: {e}")

        return urls

    # ──────────────────────────────────────────────
    #  URLSCAN.IO
    # ──────────────────────────────────────────────

    def _urlscan_search(self, domain):
        """
        Query URLScan.io for recent scans of the domain.
        Free: 100 searches/day with API key, limited without.
        """
        print(f"  [*] URLScan.io: {domain}")
        urls = set()
        extra_data = []

        headers = {}
        if self.urlscan_key:
            headers['API-Key'] = self.urlscan_key

        try:
            resp = self.session.get(
                "https://urlscan.io/api/v1/search/",
                params={"q": f"domain:{domain}", "size": 1000},
                headers=headers,
                timeout=self.timeout,
            )

            if resp.status_code == 200:
                data = resp.json()
                results = data.get("results", [])
                print(f"    [+] {len(results)} scan results found")

                for r in results:
                    page = r.get("page", {})
                    task = r.get("task", {})

                    url = task.get("url", "")
                    if url:
                        urls.add(url)

                    page_domain = page.get("domain", "")
                    if page_domain:
                        urls.add(f"https://{page_domain}")

                    # Extract technology/server info
                    server = page.get("server", "")
                    title = page.get("title", "")
                    if server or title:
                        extra_data.append({
                            "url": url,
                            "domain": page_domain,
                            "server": server,
                            "title": title,
                            "ip": page.get("ip", ""),
                            "asn": page.get("asn", ""),
                            "status": page.get("status", ""),
                        })
            elif resp.status_code == 429:
                print(f"    [-] URLScan rate limit. Get free key: https://urlscan.io/user/signup")
            else:
                print(f"    [-] URLScan returned {resp.status_code}")

        except Exception as e:
            print(f"    [-] URLScan error: {e}")

        return urls, extra_data

    # ──────────────────────────────────────────────
    #  COMMON CRAWL INDEX
    # ──────────────────────────────────────────────

    def _commoncrawl_urls(self, domain):
        """
        Query Common Crawl index for URLs. Free, no key.
        Uses the latest available index.
        """
        print(f"  [*] Common Crawl: {domain}")
        urls = set()

        # Get latest index
        try:
            idx_resp = self.session.get(
                "https://index.commoncrawl.org/collinfo.json",
                timeout=self.timeout,
            )
            if idx_resp.status_code != 200:
                print(f"    [-] Could not fetch CC index list")
                return urls

            indexes = idx_resp.json()
            if not indexes:
                return urls

            # Use the 2 most recent indexes
            for index in indexes[:2]:
                api_url = index.get("cdx-api", "")
                if not api_url:
                    continue

                try:
                    resp = self.session.get(
                        api_url,
                        params={
                            "url": f"*.{domain}",
                            "output": "json",
                            "limit": "5000",
                        },
                        timeout=30,
                    )
                    if resp.status_code == 200:
                        for line in resp.text.strip().splitlines():
                            try:
                                import json
                                record = json.loads(line)
                                url = record.get("url", "")
                                if url:
                                    urls.add(url)
                            except Exception:
                                continue
                except Exception:
                    continue

            print(f"    [+] {len(urls)} URLs from Common Crawl")

        except Exception as e:
            print(f"    [-] Common Crawl error: {e}")

        return urls

    # ──────────────────────────────────────────────
    #  ALIENTVAULT OTX
    # ──────────────────────────────────────────────

    def _otx_urls(self, domain):
        """Query AlienVault OTX for passive DNS and URL data. Free."""
        print(f"  [*] AlienVault OTX: {domain}")
        urls = set()

        for endpoint in ["url_list", "passive_dns"]:
            try:
                resp = self.session.get(
                    f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/{endpoint}",
                    timeout=self.timeout,
                )
                if resp.status_code == 200:
                    data = resp.json()

                    if endpoint == "url_list":
                        for entry in data.get("url_list", []):
                            url = entry.get("url", "")
                            if url:
                                urls.add(url)

                    elif endpoint == "passive_dns":
                        for entry in data.get("passive_dns", []):
                            hostname = entry.get("hostname", "")
                            if hostname:
                                urls.add(f"https://{hostname}")

            except Exception:
                continue

        print(f"    [+] {len(urls)} URLs from OTX")
        return urls

    # ──────────────────────────────────────────────
    #  ANALYSIS
    # ──────────────────────────────────────────────

    SENSITIVE_PATTERNS = [
        (r'\.env($|\?)', 'Environment File', 'CRITICAL'),
        (r'\.git(/|$)', 'Git Repository', 'CRITICAL'),
        (r'\.svn(/|$)', 'SVN Repository', 'HIGH'),
        (r'\.sql($|\?)', 'SQL Dump', 'CRITICAL'),
        (r'\.bak($|\?)', 'Backup File', 'HIGH'),
        (r'\.old($|\?)', 'Old File', 'MEDIUM'),
        (r'\.log($|\?)', 'Log File', 'HIGH'),
        (r'\.pem($|\?)', 'PEM Certificate/Key', 'CRITICAL'),
        (r'\.key($|\?)', 'Private Key', 'CRITICAL'),
        (r'\.conf($|\?)', 'Config File', 'HIGH'),
        (r'\.yml($|\?)', 'YAML Config', 'MEDIUM'),
        (r'\.yaml($|\?)', 'YAML Config', 'MEDIUM'),
        (r'\.xml($|\?|&).*config', 'XML Config', 'HIGH'),
        (r'\.csv($|\?)', 'CSV Data', 'LOW'),
        (r'wp-config\.php', 'WordPress Config', 'CRITICAL'),
        (r'config\.php', 'PHP Config', 'HIGH'),
        (r'database\.yml', 'Database Config', 'CRITICAL'),
        (r'\.htpasswd', 'HTPasswd File', 'CRITICAL'),
        (r'\.htaccess', 'HTAccess File', 'MEDIUM'),
        (r'phpinfo', 'PHP Info Page', 'MEDIUM'),
        (r'phpmyadmin', 'phpMyAdmin', 'CRITICAL'),
        (r'adminer', 'Adminer DB Tool', 'CRITICAL'),
        (r'/admin(/|$)', 'Admin Panel', 'MEDIUM'),
        (r'jenkins', 'Jenkins CI', 'HIGH'),
        (r'grafana', 'Grafana Dashboard', 'HIGH'),
        (r'kibana', 'Kibana Dashboard', 'HIGH'),
        (r'/debug', 'Debug Endpoint', 'HIGH'),
        (r'actuator', 'Spring Actuator', 'HIGH'),
        (r'swagger', 'Swagger API Docs', 'MEDIUM'),
        (r'graphql', 'GraphQL Endpoint', 'MEDIUM'),
        (r'\.DS_Store', 'macOS DS_Store', 'MEDIUM'),
        (r'web\.config', 'IIS Web Config', 'HIGH'),
        (r'crossdomain\.xml', 'Flash Crossdomain', 'LOW'),
        (r'server-status', 'Apache Status', 'HIGH'),
        (r'server-info', 'Apache Info', 'HIGH'),
        (r'elmah\.axd', 'ELMAH Error Log', 'HIGH'),
        (r'trace\.axd', '.NET Trace', 'HIGH'),
    ]

    def _analyze_urls(self, urls, target_domain):
        """Analyze collected URLs for sensitive paths and subdomains."""
        subdomains = set()
        findings = []
        target_clean = target_domain.lower().lstrip('.')
        seen_findings = set()

        for url in urls:
            try:
                parsed = urlparse(url)
                hostname = parsed.netloc.lower().split(':')[0]
                path = parsed.path.lower()

                # Extract subdomains
                if hostname and (
                    hostname.endswith('.' + target_clean)
                    or hostname == target_clean
                ):
                    subdomains.add(hostname)

                # Check for sensitive patterns
                for pattern, finding_type, severity in self.SENSITIVE_PATTERNS:
                    if re.search(pattern, url, re.IGNORECASE):
                        key = f"{finding_type}:{hostname}{path}"
                        if key not in seen_findings:
                            seen_findings.add(key)
                            findings.append({
                                'type': finding_type,
                                'url': url,
                                'category': self._categorize_finding(finding_type),
                                'severity': severity,
                                'dork': f'[passive:{finding_type}]',
                            })
                        break  # one match per URL

            except Exception:
                continue

        subdomains.discard(target_clean)
        subdomains.discard('www.' + target_clean)

        return subdomains, findings

    def _categorize_finding(self, finding_type):
        cat_map = {
            'Environment File': 'sensitive_files',
            'Git Repository': 'sensitive_files',
            'SVN Repository': 'sensitive_files',
            'SQL Dump': 'backup_files',
            'Backup File': 'backup_files',
            'Old File': 'backup_files',
            'Log File': 'sensitive_files',
            'PEM Certificate/Key': 'crypto_files',
            'Private Key': 'crypto_files',
            'Config File': 'config_files',
            'YAML Config': 'config_files',
            'XML Config': 'config_files',
            'WordPress Config': 'config_files',
            'PHP Config': 'config_files',
            'Database Config': 'config_files',
            'HTPasswd File': 'sensitive_files',
            'HTAccess File': 'config_files',
            'PHP Info Page': 'info_disclosure',
            'phpMyAdmin': 'database_tools',
            'Adminer DB Tool': 'database_tools',
            'Admin Panel': 'admin_panels',
            'Jenkins CI': 'devops_tools',
            'Grafana Dashboard': 'devops_tools',
            'Kibana Dashboard': 'devops_tools',
            'Debug Endpoint': 'debug_pages',
            'Spring Actuator': 'debug_pages',
            'Swagger API Docs': 'info_disclosure',
            'GraphQL Endpoint': 'info_disclosure',
        }
        return cat_map.get(finding_type, 'other')

    # ──────────────────────────────────────────────
    #  MAIN RUN (same interface as GoogleDorker)
    # ──────────────────────────────────────────────

    def run(self, target_domain):
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        target = target_domain.lower().replace('https://', '').replace('http://', '').rstrip('/')

        print(f"\n{'='*60}")
        print(f"  PASSIVE DORKING - Target: {target}")
        print(f"  Sources: Wayback Machine, URLScan.io, Common Crawl, OTX")
        print(f"{'='*60}")

        all_urls = set()

        # Run all sources in parallel
        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = {
                executor.submit(self._wayback_urls, target): "wayback",
                executor.submit(self._urlscan_search, target): "urlscan",
                executor.submit(self._commoncrawl_urls, target): "commoncrawl",
                executor.submit(self._otx_urls, target): "otx",
            }

            urlscan_extra = []
            for future in as_completed(futures):
                source = futures[future]
                try:
                    result = future.result()
                    if source == "urlscan":
                        urls, extra = result
                        all_urls.update(urls)
                        urlscan_extra = extra
                    else:
                        all_urls.update(result)
                except Exception as e:
                    print(f"    [-] {source} failed: {e}")

        print(f"\n  [+] Total unique URLs collected: {len(all_urls)}")

        # Analyze
        subdomains, findings = self._analyze_urls(all_urls, target)

        # Sort findings by severity
        sev_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}
        findings.sort(key=lambda x: sev_order.get(x['severity'], 5))

        # Print summary
        self._print_summary(target, all_urls, subdomains, findings)

        # Build shadow IT flags
        shadow_flags = []
        for f in findings:
            if f['severity'] in ('CRITICAL', 'HIGH'):
                shadow_flags.append({
                    'type': f'Passive Discovery: {f["type"]}',
                    'asset': f['url'],
                    'reason': f'{f["type"]} found via passive URL analysis. Severity: {f["severity"]}.',
                    'module': 'google_dorking',
                })

        next_steps = self._build_next_steps(findings, subdomains)

        return {
            'subdomains': sorted(subdomains),
            'urls_found': sorted(all_urls),
            'dork_findings': findings,
            'dorks_executed': 4,  # 4 sources queried
            'dorks_total': 4,
            'captcha_hit': False,
            'api_mode': True,
            'api_queries_used': 0,
            'query_log': [],
            'shadow_it_flags': shadow_flags,
            'next_steps': next_steps,
        }

    def _print_summary(self, target, all_urls, subdomains, findings):
        print(f"\n{'='*60}")
        print(f"  PASSIVE DORKING RESULTS")
        print(f"{'='*60}")
        print(f"  Total URLs:      {len(all_urls)}")
        print(f"  Subdomains:      {len(subdomains)}")
        print(f"  Findings:        {len(findings)}")
        print(f"{'='*60}")

        if subdomains:
            print(f"\n  Subdomains discovered:")
            for s in sorted(subdomains):
                print(f"    • {s}")

        if findings:
            print(f"\n  Notable Findings:")
            for f in findings[:25]:
                icon = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🔵'}.get(f['severity'], '⚪')
                print(f"    {icon} [{f['severity']}] {f['type']}: {f['url'][:80]}")
            if len(findings) > 25:
                print(f"    ... and {len(findings) - 25} more")

        print()

    def _build_next_steps(self, findings, subdomains):
        steps = []
        sevs = [f['severity'] for f in findings]

        if 'CRITICAL' in sevs:
            crit = [f for f in findings if f['severity'] == 'CRITICAL']
            steps.append({
                'action': 'Remediate Critical Exposures',
                'description': f'{len(crit)} critical item(s) found in web archives/passive sources. '
                               f'These may still be live — verify and remove.',
                'priority': 'CRITICAL',
            })

        cats = set(f['category'] for f in findings)
        if 'sensitive_files' in cats or 'backup_files' in cats:
            steps.append({
                'action': 'Remove Sensitive Files',
                'description': 'Sensitive/backup files found in web archives. Verify current exposure and remove.',
                'priority': 'HIGH',
            })

        if 'database_tools' in cats or 'devops_tools' in cats:
            steps.append({
                'action': 'Restrict Management Tools',
                'description': 'Database/DevOps tools found exposed. Restrict access via IP whitelist or VPN.',
                'priority': 'HIGH',
            })

        if subdomains:
            steps.append({
                'action': 'Review Discovered Subdomains',
                'description': f'{len(subdomains)} subdomain(s) found via passive sources. Verify authorization.',
                'priority': 'MEDIUM',
            })

        return steps