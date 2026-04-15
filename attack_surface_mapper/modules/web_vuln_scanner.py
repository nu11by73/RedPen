"""
Web Vulnerability Scanner Module v2.0 - Non-Intrusive
Passive and non-intrusive checks only. No attack payloads are sent.

Checks:
  - Security Header Analysis (with CSP deep analysis)
  - SSL/TLS Certificate Analysis (expiry, self-signed, CN mismatch, weak sig)
  - Insecure Cookie Flags
  - CORS Misconfiguration
  - Server/Technology Disclosure & CMS Fingerprinting
  - JavaScript Library Version Detection (CVE matching)
  - Favicon Hash Fingerprinting
  - WAF Detection
  - Information Disclosure (stack traces, debug, errors, internal IPs, emails)
  - Sensitive Path Discovery (.git, .env, configs, API docs, backup files)
  - Source Map File Detection
  - Directory Listing Detection
  - HTTP Method Testing (OPTIONS-based)
  - CSRF Token Absence (passive form analysis)
  - Login Form Security Analysis
  - Subresource Integrity (SRI) Checks
  - Cloud Storage Reference Detection
  - Subdomain Takeover Indicators
  - Mixed Content Detection
  - Cache Header Analysis
  - HTTP-to-HTTPS Redirect Verification
  - HTML Comment Analysis
  - DNS Security Records (SPF, DMARC, CAA)
"""

import re
import ssl
import time
import socket
import hashlib
import logging
import subprocess
import requests
import urllib3
import base64
from urllib.parse import urlparse, urljoin, parse_qs
from datetime import datetime, timezone
from collections import OrderedDict
from rich.console import Console
from rich.panel import Panel

try:
    from bs4 import BeautifulSoup, Comment
    HAS_BS4 = True
except ImportError:
    HAS_BS4 = False

try:
    import mmh3
    HAS_MMH3 = True
except ImportError:
    HAS_MMH3 = False

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logger = logging.getLogger(__name__)

console = Console()

class WebVulnScanner:
    def __init__(self, config=None):
        self.config = config if isinstance(config, dict) else {}
        self.timeout = self.config.get('REQUEST_TIMEOUT', 10)
        self.max_targets = self.config.get('VULN_MAX_TARGETS', 30)
        self.crawl_depth = self.config.get('VULN_CRAWL_DEPTH', 2)
        self.scan_level = self.config.get('VULN_SCAN_LEVEL', 'standard')

        self.session = requests.Session()
        ua = self.config.get('USER_AGENT',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
            '(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36')
        self.session.headers.update({
            'User-Agent': ua,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
        })
        self.session.verify = False

        self.findings = []
        self.seen_findings = set()
        self.scanned_urls = set()
        self.forms_tested = 0
        self.requests_made = 0
        self.target_responses = {}

    # â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
    #  CONSTANTS
    # â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

    SECURITY_HEADERS = {
        'Strict-Transport-Security': {
            'severity': 'MEDIUM',
            'description': 'HSTS not set. Allows SSL stripping attacks.',
        },
        'Content-Security-Policy': {
            'severity': 'MEDIUM',
            'description': 'CSP not set. Increases XSS risk.',
        },
        'X-Content-Type-Options': {
            'severity': 'LOW',
            'description': 'X-Content-Type-Options not set. MIME sniffing possible.',
        },
        'X-Frame-Options': {
            'severity': 'MEDIUM',
            'description': 'X-Frame-Options not set. Clickjacking possible.',
        },
        'X-XSS-Protection': {
            'severity': 'LOW',
            'description': 'X-XSS-Protection not set (legacy but useful for old browsers).',
        },
        'Referrer-Policy': {
            'severity': 'LOW',
            'description': 'Referrer-Policy not set. May leak URLs to third parties.',
        },
        'Permissions-Policy': {
            'severity': 'LOW',
            'description': 'Permissions-Policy not set. Browser features not restricted.',
        },
    }

    INFO_LEAK_HEADERS = [
        'X-AspNet-Version', 'X-AspNetMvc-Version', 'X-Debug-Token',
        'X-Debug-Token-Link', 'X-Runtime', 'X-Generator',
        'X-Drupal-Cache', 'X-Drupal-Dynamic-Cache',
    ]

    SUBDOMAIN_TAKEOVER_CNAMES = {
        'github.io': "There isn't a GitHub Pages site here",
        'herokuapp.com': 'No such app',
        'pantheon.io': '404 error unknown site',
        'zendesk.com': 'Help Center Closed',
        'readme.io': 'Project doesnt exist',
        's3.amazonaws.com': 'NoSuchBucket',
        'ghost.io': 'The thing you were looking for is no longer here',
        'surge.sh': 'project not found',
        'bitbucket.io': 'Repository not found',
        'wordpress.com': 'Do you want to register',
        'teamwork.com': 'Oops - We didn',
        'helpjuice.com': 'We could not find what you',
        'helpscout.net': 'No settings were found',
        'cargo.site': '404 Not Found',
        'feedpress.me': 'The feed has not been found',
        'freshdesk.com': 'There is no helpdesk here',
        'uptime.com': 'page not found',
        'pingdom.com': 'Public Report Not Activated',
        'tilda.ws': 'Please renew your subscription',
        'shopify.com': 'Sorry, this shop is currently unavailable',
        'webflow.io': "The page you are looking for doesn't exist",
        'fly.dev': '404 Not Found',
        'netlify.app': 'Not Found',
    }

    JS_LIBRARIES = [
        {
            'name': 'jQuery',
            'patterns': [
                r'jquery[.\s/\-]?v?(\d+\.\d+\.\d+)',
                r'jQuery\s+(?:JavaScript\s+Library\s+)?v?(\d+\.\d+\.\d+)',
            ],
            'vulnerable_below': '3.5.0',
            'cves': 'CVE-2020-11022, CVE-2020-11023 (XSS in htmlPrefilter)',
            'severity': 'MEDIUM',
        },
        {
            'name': 'jQuery UI',
            'patterns': [r'jquery[.\s\-]?ui[.\s/\-]?v?(\d+\.\d+\.\d+)'],
            'vulnerable_below': '1.13.0',
            'cves': 'CVE-2021-41182, CVE-2021-41183, CVE-2021-41184 (XSS)',
            'severity': 'MEDIUM',
        },
        {
            'name': 'AngularJS',
            'patterns': [
                r'angular[.\s/\-]?v?(\d+\.\d+\.\d+)',
                r'AngularJS\s+v(\d+\.\d+\.\d+)',
            ],
            'vulnerable_below': '1.8.0',
            'cves': 'Multiple template injection / sandbox escape vulnerabilities',
            'severity': 'HIGH',
        },
        {
            'name': 'Bootstrap',
            'patterns': [
                r'bootstrap[.\s/\-]?v?(\d+\.\d+\.\d+)',
                r'Bootstrap\s+v(\d+\.\d+\.\d+)',
            ],
            'vulnerable_below': '3.4.1',
            'cves': 'CVE-2019-8331 (XSS in tooltip/popover)',
            'severity': 'MEDIUM',
        },
        {
            'name': 'Lodash',
            'patterns': [r'lodash[.\s/\-]?v?(\d+\.\d+\.\d+)'],
            'vulnerable_below': '4.17.21',
            'cves': 'CVE-2021-23337 (Command injection), CVE-2020-28500 (ReDoS)',
            'severity': 'HIGH',
        },
        {
            'name': 'Moment.js',
            'patterns': [r'moment(?:\.js)?[.\s/\-]?v?(\d+\.\d+\.\d+)'],
            'vulnerable_below': '2.29.4',
            'cves': 'CVE-2022-24785 (Path traversal), CVE-2022-31129 (ReDoS)',
            'severity': 'MEDIUM',
        },
        {
            'name': 'Handlebars.js',
            'patterns': [r'handlebars[.\s/\-]?v?(\d+\.\d+\.\d+)'],
            'vulnerable_below': '4.7.7',
            'cves': 'CVE-2021-23369, CVE-2021-23383 (Prototype pollution)',
            'severity': 'HIGH',
        },
        {
            'name': 'Underscore.js',
            'patterns': [r'underscore[.\s/\-]?v?(\d+\.\d+\.\d+)'],
            'vulnerable_below': '1.13.6',
            'cves': 'CVE-2021-23358 (Arbitrary code exec via template)',
            'severity': 'HIGH',
        },
        {
            'name': 'DOMPurify',
            'patterns': [r'dompurify[.\s/\-]?v?(\d+\.\d+\.\d+)'],
            'vulnerable_below': '2.3.6',
            'cves': 'Multiple mXSS bypass vulnerabilities',
            'severity': 'HIGH',
        },
        {
            'name': 'Vue.js',
            'patterns': [r'vue[.\s/\-]?v?(\d+\.\d+\.\d+)', r'Vue\.js\s+v(\d+\.\d+\.\d+)'],
            'vulnerable_below': '2.7.14',
            'cves': 'Various XSS in v2 template compiler',
            'severity': 'MEDIUM',
        },
        {
            'name': 'React',
            'patterns': [r'react(?:\.production)?[.\s/\-]?v?(\d+\.\d+\.\d+)'],
            'vulnerable_below': '16.13.0',
            'cves': 'CVE-2020-7919 (XSS in certain SSR scenarios)',
            'severity': 'LOW',
        },
        {
            'name': 'TinyMCE',
            'patterns': [r'tinymce[.\s/\-]?v?(\d+\.\d+\.\d+)'],
            'vulnerable_below': '5.10.0',
            'cves': 'CVE-2022-23494 (XSS)',
            'severity': 'MEDIUM',
        },
        {
            'name': 'CKEditor',
            'patterns': [r'ckeditor[.\s/\-]?v?(\d+\.\d+\.\d+)'],
            'vulnerable_below': '4.18.0',
            'cves': 'Multiple XSS vulnerabilities',
            'severity': 'MEDIUM',
        },
    ]

    CMS_PATTERNS = [
        ('WordPress', [
            (r'<meta[^>]+content=["\']WordPress\s*([\d.]*)', 'body'),
            (r'/wp-content/', 'body'),
            (r'/wp-includes/', 'body'),
        ]),
        ('Joomla', [
            (r'<meta[^>]+content=["\']Joomla', 'body'),
            (r'/components/com_', 'body'),
            (r'/media/jui/', 'body'),
        ]),
        ('Drupal', [
            (r'<meta[^>]+content=["\']Drupal', 'body'),
            (r'Drupal\.settings', 'body'),
            (r'/sites/default/files/', 'body'),
        ]),
        ('Magento', [
            (r'/skin/frontend/', 'body'),
            (r'Mage\.Cookies', 'body'),
        ]),
        ('Shopify', [
            (r'cdn\.shopify\.com', 'body'),
            (r'Shopify\.theme', 'body'),
        ]),
        ('Ghost', [
            (r'<meta[^>]+content=["\']Ghost', 'body'),
        ]),
        ('Next.js', [
            (r'__NEXT_DATA__', 'body'),
            (r'/_next/static/', 'body'),
        ]),
        ('Nuxt.js', [
            (r'__NUXT__', 'body'),
            (r'/_nuxt/', 'body'),
        ]),
        ('Hugo', [(r'<meta[^>]+content=["\']Hugo', 'body')]),
        ('Jekyll', [(r'<meta[^>]+content=["\']Jekyll', 'body')]),
        ('ASP.NET', [
            (r'__VIEWSTATE', 'body'),
            (r'__EVENTVALIDATION', 'body'),
        ]),
    ]

    WAF_SIGNATURES = {
        'Cloudflare': {
            'headers': {'server': 'cloudflare'},
            'header_keys': ['cf-ray', 'cf-cache-status'],
            'cookies': ['__cfduid', '__cf_bm', 'cf_clearance'],
        },
        'AWS CloudFront/WAF': {
            'headers': {},
            'header_keys': ['x-amz-cf-id', 'x-amz-cf-pop'],
            'cookies': ['AWSALB', 'AWSALBCORS'],
        },
        'Akamai': {
            'headers': {},
            'header_keys': ['x-akamai-transformed'],
            'cookies': ['AKA_A2'],
        },
        'Sucuri': {
            'headers': {'server': 'sucuri'},
            'header_keys': ['x-sucuri-id', 'x-sucuri-cache'],
            'cookies': ['sucuri_cloudproxy'],
        },
        'Imperva/Incapsula': {
            'headers': {},
            'header_keys': ['x-iinfo'],
            'cookies': ['visid_incap_', 'incap_ses_'],
        },
        'F5 BIG-IP': {
            'headers': {},
            'header_keys': [],
            'cookies': ['BIGipServer'],
        },
        'Barracuda': {
            'headers': {},
            'header_keys': [],
            'cookies': ['barra_counter_session'],
        },
        'Fortinet FortiWeb': {
            'headers': {},
            'header_keys': [],
            'cookies': ['FORTIWAFSID'],
        },
        'DenyAll': {
            'headers': {},
            'header_keys': [],
            'cookies': ['sessioncookie'],
        },
    }

    FAVICON_HASHES = {
        116323821: 'Spring Boot',
        -1137684688: 'Plesk',
        1485257654: 'WordPress',
        988422585: 'Atlassian Jira',
        -162429756: 'GLPI',
        1150108930: 'pfSense',
        -620881420: 'Grafana',
        -305179312: 'Spring Boot (leaf)',
        1354567743: 'Apache Tomcat',
        -1645834167: 'Microsoft OWA',
        -1166125415: 'Jenkins',
        81586820: 'Fortinet FortiGate',
        -1588080585: 'SonarQube',
        1165257324: 'Kibana',
        -1073467747: 'Webmin',
        1382726720: 'GitLab',
        -266008933: 'Zabbix',
        -1293617961: 'Nextcloud',
        1574601346: 'Synology DSM',
        -1427573425: 'phpMyAdmin',
        876876147: 'cPanel',
        -1023653885: 'Zimbra',
    }

    CLOUD_PATTERNS = [
        (r'[a-z0-9\-]+\.s3[\.\-][a-z0-9\-]+\.amazonaws\.com', 'AWS S3 Bucket'),
        (r's3\.amazonaws\.com/[a-z0-9\.\-]+', 'AWS S3 Bucket'),
        (r'[a-z0-9\-]+\.s3\.amazonaws\.com', 'AWS S3 Bucket'),
        (r'storage\.googleapis\.com/[a-z0-9\.\-_]+', 'Google Cloud Storage'),
        (r'[a-z0-9\-]+\.storage\.googleapis\.com', 'Google Cloud Storage'),
        (r'[a-z0-9\-]+\.blob\.core\.windows\.net', 'Azure Blob Storage'),
        (r'[a-z0-9\-]+\.firebaseio\.com', 'Firebase Database'),
        (r'[a-z0-9\-]+\.firebasestorage\.googleapis\.com', 'Firebase Storage'),
        (r'[a-z0-9\-]+\.digitaloceanspaces\.com', 'DigitalOcean Spaces'),
    ]

    # â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
    #  MAIN RUN
    # â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

    def run(self, target_domain, subdomains=None):
        console.print(f"\n[bold cyan]{'='*60}[/bold cyan]")
        console.print(f"[bold cyan]  Module 11: Basic Web Vulnerability Scanner - {target_domain}[/bold cyan]")
        console.print(f"[bold cyan]{'='*60}[/bold cyan]\n")
        self.findings = []
        self.seen_findings = set()
        self.scanned_urls = set()
        self.requests_made = 0
        self.forms_tested = 0
        self.target_responses = {}

        target = target_domain.lower().replace('https://', '').replace('http://', '').rstrip('/')

        print(f"\n{'='*60}")
        print(f"  WEB VULNERABILITY SCANNER (Non-Intrusive) - {target}")
        print(f"  Scan Level: {self.scan_level}")
        print(f"{'='*60}")

        # Build target list
        targets = [f"https://{target}"]
        if subdomains:
            for sub in subdomains[:self.max_targets - 1]:
                if isinstance(sub, dict):
                    sub = sub.get('subdomain', sub.get('domain', ''))
                if isinstance(sub, str) and sub:
                    sub = sub.strip().lower()
                    if not sub.startswith('http'):
                        targets.append(f"https://{sub}")
                    else:
                        targets.append(sub)

        seen = set()
        unique_targets = []
        for t in targets:
            if t not in seen:
                seen.add(t)
                unique_targets.append(t)
        targets = unique_targets[:self.max_targets]

        print(f"  Targets: {len(targets)}\n")

        # â”€â”€ Phase 1: Passive analysis â”€â”€
        print("[*] Phase 1: Passive analysis (headers, cookies, CSP, info disclosure, WAF)")
        for target_url in targets:
            self._passive_scan(target_url)

        # â”€â”€ Phase 2: SSL/TLS certificate analysis â”€â”€
        print(f"\n[*] Phase 2: SSL/TLS certificate analysis")
        checked_hosts = set()
        for target_url in targets:
            hostname = urlparse(target_url).netloc
            if hostname not in checked_hosts:
                checked_hosts.add(hostname)
                self._check_ssl_tls(hostname, target_url)

        # â”€â”€ Phase 3: HTTPâ†’HTTPS redirect & transport security â”€â”€
        print(f"\n[*] Phase 3: HTTP-to-HTTPS redirect verification")
        checked_domains = set()
        for target_url in targets:
            hostname = urlparse(target_url).netloc
            if hostname not in checked_domains:
                checked_domains.add(hostname)
                self._check_https_redirect(hostname)

        # â”€â”€ Phase 4: Technology fingerprinting â”€â”€
        print(f"\n[*] Phase 4: Technology fingerprinting (CMS, JS libraries, favicon)")
        for target_url in targets:
            resp = self.target_responses.get(target_url)
            if resp:
                self._fingerprint_technology(target_url, resp)

        # â”€â”€ Phase 5: Crawl & page analysis â”€â”€
        print(f"\n[*] Phase 5: Crawl & page analysis (CSRF, login forms, SRI, comments, cloud refs)")
        all_js_urls = set()
        for target_url in targets[:15]:
            js_found = self._crawl_and_analyze(target_url)
            all_js_urls.update(js_found)

        # â”€â”€ Phase 5b: Source map detection â”€â”€
        if all_js_urls:
            print(f"\n[*] Phase 5b: Source map detection ({len(all_js_urls)} JS files)")
            self._check_source_maps(all_js_urls)

        # â”€â”€ Phase 6: Sensitive path & file discovery â”€â”€
        print(f"\n[*] Phase 6: Sensitive path & file discovery")
        for target_url in targets[:15]:
            self._test_paths(target_url)

        # â”€â”€ Phase 7: CORS testing â”€â”€
        print(f"\n[*] Phase 7: CORS misconfiguration testing")
        for target_url in targets:
            self._test_cors(target_url)

        # â”€â”€ Phase 8: HTTP method testing â”€â”€
        if self.scan_level in ('standard', 'thorough'):
            print(f"\n[*] Phase 8: HTTP method testing")
            for target_url in targets[:10]:
                self._test_http_methods(target_url)

        # â”€â”€ Phase 9: Subdomain takeover â”€â”€
        if subdomains:
            print(f"\n[*] Phase 9: Subdomain takeover checks")
            self._check_subdomain_takeover(subdomains[:50])

        # â”€â”€ Phase 10: Mixed content & cache headers â”€â”€
        print(f"\n[*] Phase 10: Mixed content & cache header analysis")
        for target_url in targets[:15]:
            self._check_mixed_content(target_url)
            self._check_cache_headers(target_url)

        # â”€â”€ Phase 11: DNS security records â”€â”€
        print(f"\n[*] Phase 11: DNS security records (SPF, DMARC, CAA)")
        self._check_dns_security(target)

        # â”€â”€ Finalize â”€â”€
        self.findings = self._dedup_findings(self.findings)
        self._print_summary()
        return self._build_results(target)

    # â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
    #  PHASE 1: PASSIVE ANALYSIS
    # â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

    def _passive_scan(self, target_url):
        try:
            resp = self._request('GET', target_url)
            if not resp:
                return
        except Exception:
            return

        self.target_responses[target_url] = resp
        resp_headers_lower = {k.lower(): v for k, v in resp.headers.items()}

        # â”€â”€ Security Headers â”€â”€
        for header, info in self.SECURITY_HEADERS.items():
            if header.lower() not in resp_headers_lower:
                self._add_finding(
                    vuln_type='Missing Security Header',
                    severity=info['severity'],
                    url=target_url,
                    detail=f"Missing: {header}. {info['description']}",
                    category='security_headers',
                    evidence=f'Header "{header}" not present in response',
                )

        # â”€â”€ CSP Deep Analysis â”€â”€
        csp = resp_headers_lower.get('content-security-policy', '')
        if csp:
            self._analyze_csp(csp, target_url)

        # â”€â”€ Additional Info Leak Headers â”€â”€
        for header in self.INFO_LEAK_HEADERS:
            val = resp.headers.get(header, '')
            if val:
                self._add_finding(
                    vuln_type='Information Leak Header',
                    severity='LOW',
                    url=target_url,
                    detail=f'Header "{header}" exposes internal info: {val}',
                    category='info_disclosure',
                    evidence=f'{header}: {val}',
                )

        # â”€â”€ Server Banner â”€â”€
        server = resp.headers.get('Server', '')
        powered = resp.headers.get('X-Powered-By', '')
        if server and re.search(r'[\d]+\.[\d]+', server):
            self._add_finding(
                vuln_type='Server Version Disclosure',
                severity='LOW', url=target_url,
                detail=f'Server header exposes version: {server}',
                category='info_disclosure',
                evidence=f'Server: {server}',
            )
        if powered:
            self._add_finding(
                vuln_type='Technology Disclosure',
                severity='LOW', url=target_url,
                detail=f'X-Powered-By header present: {powered}',
                category='info_disclosure',
                evidence=f'X-Powered-By: {powered}',
            )

        # â”€â”€ Insecure Cookies â”€â”€
        for cookie in resp.cookies:
            issues = []
            if not cookie.secure:
                issues.append('Missing Secure flag')
            rest_keys = [k.lower() for k in cookie._rest.keys()] if hasattr(cookie, '_rest') else []
            if 'httponly' not in rest_keys:
                issues.append('Missing HttpOnly flag')
            samesite = None
            if hasattr(cookie, '_rest'):
                for k, v in cookie._rest.items():
                    if k.lower() == 'samesite':
                        samesite = v
            if not samesite:
                issues.append('Missing SameSite attribute')
            if issues:
                self._add_finding(
                    vuln_type='Insecure Cookie',
                    severity='LOW' if len(issues) == 1 else 'MEDIUM',
                    url=target_url,
                    detail=f'Cookie "{cookie.name}": {", ".join(issues)}',
                    category='cookie_security',
                    evidence=f'Set-Cookie: {cookie.name}=...',
                )

        # â”€â”€ WAF Detection â”€â”€
        self._detect_waf(resp, target_url)

        # â”€â”€ Body Analysis â”€â”€
        body = resp.text[:80000]
        body_lower = body.lower()

        # Info disclosure patterns
        disclosure_patterns = [
            (r'(?:stack\s*trace|traceback|exception\s+in\s+thread)', 'Stack Trace Disclosure', 'HIGH'),
            (r'(?:phpinfo$$$$|<title>phpinfo$$$$)', 'phpinfo() Exposed', 'HIGH'),
            (r'(?:debug\s*=\s*true|debug\s+mode\s+is\s+on)', 'Debug Mode Enabled', 'HIGH'),
            (r'(?:django\.core\.exceptions|settings\.py|DJANGO_SETTINGS_MODULE)', 'Django Debug Info', 'HIGH'),
            (r'(?:laravel|symfony).*?exception', 'Framework Exception Disclosure', 'MEDIUM'),
            (r'(?:Warning:\s+\w+$$$$)', 'PHP Warning Exposed', 'MEDIUM'),
            (r'(?:Fatal\s+error:\s+)', 'PHP Fatal Error Exposed', 'HIGH'),
            (r'(?:Parse\s+error:\s+syntax\s+error)', 'PHP Parse Error Exposed', 'HIGH'),
            (r'(?:internal\s+server\s+error.*?(?:at\s+|in\s+/))', 'Detailed Error Message', 'MEDIUM'),
        ]
        for pattern, name, severity in disclosure_patterns:
            match = re.search(pattern, body_lower)
            if match:
                context = body[max(0, match.start() - 30):match.end() + 50]
                self._add_finding(
                    vuln_type=name, severity=severity, url=target_url,
                    detail=f'{name} detected in response body',
                    category='info_disclosure', evidence=context[:200],
                )

        # Internal IP leakage (headers + body)
        all_text = body + '\n' + '\n'.join(f'{k}: {v}' for k, v in resp.headers.items())
        internal_ips = re.findall(
            r'(?:^|[^\d])((?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|'
            r'172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|'
            r'192\.168\.\d{1,3}\.\d{1,3}))(?:[^\d]|$)', all_text
        )
        # Deduplicate
        unique_ips = list(set(internal_ips))
        if unique_ips:
            self._add_finding(
                vuln_type='Internal IP Address Leakage',
                severity='MEDIUM', url=target_url,
                detail=f'{len(unique_ips)} internal IP(s) found in response: {", ".join(unique_ips[:5])}',
                category='internal_leakage',
                evidence=f'IPs: {", ".join(unique_ips[:5])}',
            )

        # Email leakage
        emails = re.findall(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}', body)
        safe_prefixes = ['info@', 'support@', 'contact@', 'help@', 'noreply@',
                         'no-reply@', 'admin@', 'webmaster@', 'sales@', 'hello@',
                         'example@', 'test@', 'user@', 'email@']
        sensitive_emails = [e for e in set(emails)
                           if not any(e.lower().startswith(p) for p in safe_prefixes)
                           and 'example.com' not in e.lower()
                           and 'sentry.io' not in e.lower()
                           and '@schema.org' not in e.lower()
                           and '@w3.org' not in e.lower()]
        if sensitive_emails:
            self._add_finding(
                vuln_type='Email Address Leakage',
                severity='LOW', url=target_url,
                detail=f'{len(sensitive_emails)} email(s) found: {", ".join(sensitive_emails[:5])}',
                category='internal_leakage',
                evidence=f'Emails: {", ".join(sensitive_emails[:5])}',
            )

    def _analyze_csp(self, csp_value, url):
        """Deep analysis of Content-Security-Policy header."""
        directives = {}
        for part in csp_value.split(';'):
            part = part.strip()
            if not part:
                continue
            tokens = part.split()
            if tokens:
                directives[tokens[0].lower()] = ' '.join(tokens[1:]) if len(tokens) > 1 else ''

        issues = []

        # Check script-src or default-src for dangerous values
        script_src = directives.get('script-src', directives.get('default-src', ''))
        if "'unsafe-inline'" in script_src:
            issues.append(("'unsafe-inline' in script-src allows inline scripts", 'HIGH'))
        if "'unsafe-eval'" in script_src:
            issues.append(("'unsafe-eval' in script-src allows eval()", 'HIGH'))
        if 'data:' in script_src:
            issues.append(("'data:' URI in script-src can be abused for XSS", 'MEDIUM'))
        if 'http:' in script_src:
            issues.append(("HTTP source in script-src allows MitM injection", 'MEDIUM'))

        # Check for wildcards
        for directive, value in directives.items():
            if value.strip() == '*':
                issues.append((f"Wildcard '*' in {directive} allows any source", 'MEDIUM'))
                break

        # Check for missing important directives
        if 'frame-ancestors' not in directives:
            issues.append(("Missing frame-ancestors directive (clickjacking risk)", 'MEDIUM'))
        if 'base-uri' not in directives:
            issues.append(("Missing base-uri directive", 'LOW'))
        if 'form-action' not in directives:
            issues.append(("Missing form-action directive", 'LOW'))
        if 'object-src' not in directives:
            issues.append(("Missing object-src directive (should be 'none')", 'LOW'))
        elif "'none'" not in directives.get('object-src', ''):
            issues.append(("object-src not set to 'none'", 'LOW'))
        if 'upgrade-insecure-requests' not in directives:
            issues.append(("Missing upgrade-insecure-requests", 'LOW'))

        for issue_detail, sev in issues:
            self._add_finding(
                vuln_type='CSP Weakness',
                severity=sev, url=url,
                detail=f'Content-Security-Policy issue: {issue_detail}',
                category='csp_issues',
                evidence=f'CSP: {csp_value[:200]}',
            )

    def _detect_waf(self, resp, url):
        """Detect WAF/CDN from response headers and cookies."""
        detected = []
        resp_headers_lower = {k.lower(): v.lower() for k, v in resp.headers.items()}
        cookie_names = [c.name for c in resp.cookies]
        cookie_str = ' '.join(cookie_names).lower()

        for waf_name, sigs in self.WAF_SIGNATURES.items():
            found = False
            # Check header values
            for hdr, val in sigs.get('headers', {}).items():
                if hdr in resp_headers_lower and val in resp_headers_lower[hdr]:
                    found = True
                    break
            # Check header keys
            if not found:
                for hdr_key in sigs.get('header_keys', []):
                    if hdr_key.lower() in resp_headers_lower:
                        found = True
                        break
            # Check cookies
            if not found:
                for cookie_sig in sigs.get('cookies', []):
                    if cookie_sig.lower() in cookie_str:
                        found = True
                        break
            if found:
                detected.append(waf_name)

        if detected:
            self._add_finding(
                vuln_type='WAF/CDN Detected',
                severity='INFO', url=url,
                detail=f'WAF/CDN detected: {", ".join(detected)}',
                category='waf_detected',
                evidence=f'Signatures matched: {", ".join(detected)}',
            )

    # â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
    #  PHASE 2: SSL/TLS CERTIFICATE ANALYSIS
    # â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

    def _check_ssl_tls(self, hostname, target_url):
        """Analyze SSL/TLS certificate for issues."""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    protocol = ssock.version()

                    # Check expiry
                    not_after_str = cert.get('notAfter', '')
                    if not_after_str:
                        not_after = datetime.strptime(not_after_str, '%b %d %H:%M:%S %Y %Z')
                        days_left = (not_after - datetime.utcnow()).days
                        if days_left < 0:
                            self._add_finding(
                                vuln_type='SSL Certificate Expired',
                                severity='CRITICAL', url=target_url,
                                detail=f'Certificate expired {abs(days_left)} day(s) ago on {not_after_str}',
                                category='ssl_tls',
                                evidence=f'notAfter: {not_after_str}',
                            )
                        elif days_left < 30:
                            self._add_finding(
                                vuln_type='SSL Certificate Expiring Soon',
                                severity='MEDIUM', url=target_url,
                                detail=f'Certificate expires in {days_left} day(s) on {not_after_str}',
                                category='ssl_tls',
                                evidence=f'notAfter: {not_after_str}',
                            )

                    # Self-signed check
                    subject = dict(x[0] for x in cert.get('subject', []))
                    issuer = dict(x[0] for x in cert.get('issuer', []))
                    if subject == issuer:
                        self._add_finding(
                            vuln_type='Self-Signed Certificate',
                            severity='HIGH', url=target_url,
                            detail=f'Certificate is self-signed. Issuer = Subject = {subject.get("commonName", "unknown")}',
                            category='ssl_tls',
                            evidence=f'Subject: {subject}, Issuer: {issuer}',
                        )

                    # CN / SAN mismatch
                    cn = subject.get('commonName', '')
                    san_list = []
                    for san_type, san_val in cert.get('subjectAltName', []):
                        if san_type == 'DNS':
                            san_list.append(san_val.lower())
                    all_names = set(san_list)
                    if cn:
                        all_names.add(cn.lower())
                    hostname_lower = hostname.lower()
                    matched = False
                    for name in all_names:
                        if name == hostname_lower:
                            matched = True
                            break
                        if name.startswith('*.') and hostname_lower.endswith(name[1:]):
                            matched = True
                            break
                    if not matched and all_names:
                        self._add_finding(
                            vuln_type='SSL Certificate CN Mismatch',
                            severity='HIGH', url=target_url,
                            detail=f'Certificate names {list(all_names)[:5]} do not match hostname {hostname}',
                            category='ssl_tls',
                            evidence=f'Hostname: {hostname}, Cert names: {list(all_names)[:5]}',
                        )

                    # Weak protocol
                    if protocol and protocol in ('TLSv1', 'TLSv1.1', 'SSLv3', 'SSLv2'):
                        self._add_finding(
                            vuln_type='Weak TLS Protocol',
                            severity='HIGH', url=target_url,
                            detail=f'Server supports deprecated protocol: {protocol}',
                            category='ssl_tls',
                            evidence=f'Negotiated protocol: {protocol}',
                        )

                    # Try to get signature algorithm
                    try:
                        der_cert = ssock.getpeercert(binary_form=True)
                        from cryptography import x509 as cx509
                        cert_obj = cx509.load_der_x509_certificate(der_cert)
                        sig_algo = cert_obj.signature_hash_algorithm
                        if sig_algo and sig_algo.name.lower() in ('md5', 'sha1'):
                            self._add_finding(
                                vuln_type='Weak Certificate Signature',
                                severity='HIGH', url=target_url,
                                detail=f'Certificate uses weak signature algorithm: {sig_algo.name}',
                                category='ssl_tls',
                                evidence=f'Signature: {sig_algo.name}',
                            )
                    except ImportError:
                        pass
                    except Exception:
                        pass

                    print(f"  [+] {hostname}: cert valid, {days_left}d remaining, {protocol}")

        except ssl.SSLCertVerificationError as e:
            self._add_finding(
                vuln_type='SSL Certificate Verification Failed',
                severity='HIGH', url=target_url,
                detail=f'Certificate verification failed: {str(e)[:200]}',
                category='ssl_tls',
                evidence=str(e)[:300],
            )
        except ssl.SSLError as e:
            self._add_finding(
                vuln_type='SSL/TLS Error',
                severity='MEDIUM', url=target_url,
                detail=f'SSL error connecting to {hostname}: {str(e)[:200]}',
                category='ssl_tls',
                evidence=str(e)[:300],
            )
        except (socket.timeout, socket.error, ConnectionRefusedError):
            pass
        except Exception as e:
            logger.debug(f"SSL check error {hostname}: {e}")

    # â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
    #  PHASE 3: HTTPâ†’HTTPS REDIRECT
    # â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

    def _check_https_redirect(self, hostname):
        """Verify that HTTP properly redirects to HTTPS."""
        try:
            resp = self._request('GET', f'http://{hostname}', allow_redirects=False, timeout=5)
            if not resp:
                return

            if resp.status_code in (301, 302, 307, 308):
                location = resp.headers.get('Location', '')
                if location.startswith('https://'):
                    if resp.status_code != 301:
                        self._add_finding(
                            vuln_type='Non-Permanent HTTPS Redirect',
                            severity='LOW', url=f'http://{hostname}',
                            detail=f'HTTP redirects to HTTPS with {resp.status_code} instead of 301. '
                                   f'Use 301 for permanent redirect.',
                            category='security_headers',
                            evidence=f'HTTP {resp.status_code} -> {location}',
                        )
                    print(f"  [+] {hostname}: HTTP -> HTTPS redirect OK ({resp.status_code})")
                else:
                    self._add_finding(
                        vuln_type='HTTP Does Not Redirect to HTTPS',
                        severity='MEDIUM', url=f'http://{hostname}',
                        detail=f'HTTP redirects to non-HTTPS location: {location}',
                        category='security_headers',
                        evidence=f'Location: {location}',
                    )
            elif resp.status_code == 200:
                self._add_finding(
                    vuln_type='HTTP Does Not Redirect to HTTPS',
                    severity='MEDIUM', url=f'http://{hostname}',
                    detail='HTTP serves content directly without redirecting to HTTPS',
                    category='security_headers',
                    evidence=f'HTTP 200 on port 80',
                )
        except Exception:
            pass

    # â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
    #  PHASE 4: TECHNOLOGY FINGERPRINTING
    # â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

    def _fingerprint_technology(self, target_url, resp):
        """Identify CMS, JS libraries, and technology via favicon hash."""
        body = resp.text[:100000]
        detected_tech = []

        # â”€â”€ CMS Fingerprinting â”€â”€
        cookie_names = ' '.join(c.name.lower() for c in resp.cookies)
        headers_str = ' '.join(f'{k}: {v}' for k, v in resp.headers.items())

        for cms_name, patterns in self.CMS_PATTERNS:
            for pattern, source in patterns:
                if source == 'body' and re.search(pattern, body, re.IGNORECASE):
                    detected_tech.append(cms_name)
                    break
                elif source == 'cookie_name' and re.search(pattern, cookie_names, re.IGNORECASE):
                    detected_tech.append(cms_name)
                    break
                elif source in ('header', 'header_name') and re.search(pattern, headers_str, re.IGNORECASE):
                    detected_tech.append(cms_name)
                    break

        # Additional header-based detection
        powered = resp.headers.get('X-Powered-By', '').lower()
        if 'express' in powered:
            detected_tech.append('Express.js')
        if 'asp.net' in powered:
            detected_tech.append('ASP.NET')
        if 'php' in powered:
            detected_tech.append('PHP')
        if resp.headers.get('X-Drupal-Cache'):
            detected_tech.append('Drupal')
        if resp.headers.get('X-Application-Context'):
            detected_tech.append('Spring Framework')
        for c in resp.cookies:
            if c.name == 'JSESSIONID':
                detected_tech.append('Java (JSESSIONID)')
                break
            if c.name == 'laravel_session':
                detected_tech.append('Laravel')
                break
            if c.name == 'PHPSESSID':
                detected_tech.append('PHP')
                break

        detected_tech = list(set(detected_tech))
        if detected_tech:
            self._add_finding(
                vuln_type='Technology Stack Identified',
                severity='INFO', url=target_url,
                detail=f'Detected: {", ".join(detected_tech)}',
                category='technology',
                evidence=f'Technologies: {", ".join(detected_tech)}',
            )
            for tech in detected_tech:
                print(f"  [i] Detected: {tech}")

        # â”€â”€ JavaScript Library Detection â”€â”€
        self._detect_js_libraries(body, target_url)

        # â”€â”€ Favicon Hash Fingerprinting â”€â”€
        self._check_favicon(target_url)

    def _detect_js_libraries(self, content, url):
        """Detect JavaScript libraries and check for known vulnerabilities."""
        content_lower = content.lower()
        detected = set()

        for lib in self.JS_LIBRARIES:
            for pattern in lib['patterns']:
                match = re.search(pattern, content_lower)
                if match:
                    version = match.group(1) if match.lastindex else None
                    lib_key = lib['name']
                    if lib_key in detected:
                        continue
                    detected.add(lib_key)

                    if version and self._version_lt(version, lib['vulnerable_below']):
                        self._add_finding(
                            vuln_type='Vulnerable JavaScript Library',
                            severity=lib['severity'], url=url,
                            detail=f'{lib["name"]} v{version} is below {lib["vulnerable_below"]}. '
                                   f'Known issues: {lib["cves"]}',
                            category='technology',
                            evidence=f'{lib["name"]} {version} < {lib["vulnerable_below"]}',
                        )
                    elif version:
                        self._add_finding(
                            vuln_type='JavaScript Library Detected',
                            severity='INFO', url=url,
                            detail=f'{lib["name"]} v{version} detected',
                            category='technology',
                            evidence=f'{lib["name"]} {version}',
                        )
                    break

    def _check_favicon(self, base_url):
        """Identify technology by favicon hash."""
        if not HAS_MMH3:
            return

        try:
            resp = self._request('GET', base_url.rstrip('/') + '/favicon.ico', timeout=5)
            if not resp or resp.status_code != 200 or len(resp.content) < 100:
                return

            encoded = base64.encodebytes(resp.content)
            fav_hash = mmh3.hash(encoded)

            tech = self.FAVICON_HASHES.get(fav_hash)
            if tech:
                self._add_finding(
                    vuln_type='Technology Identified via Favicon',
                    severity='INFO', url=base_url,
                    detail=f'Favicon hash ({fav_hash}) matches: {tech}',
                    category='technology',
                    evidence=f'mmh3 hash: {fav_hash} -> {tech}',
                )
                print(f"  [i] Favicon -> {tech} (hash: {fav_hash})")
            else:
                logger.debug(f"Unknown favicon hash for {base_url}: {fav_hash}")
        except Exception as e:
            logger.debug(f"Favicon check failed for {base_url}: {e}")

    # â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
    #  PHASE 5: CRAWL & PAGE ANALYSIS
    # â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

    def _crawl_and_analyze(self, base_url):
        """Crawl pages and perform per-page passive analysis."""
        visited = set()
        to_visit = [base_url]
        base_netloc = urlparse(base_url).netloc
        depth = 0
        js_urls = set()
        pages_found = 0

        while to_visit and depth < self.crawl_depth and pages_found < 30:
            next_level = []
            for url in to_visit:
                if url in visited:
                    continue
                visited.add(url)

                # Use cached response if available
                resp = self.target_responses.get(url)
                if not resp:
                    try:
                        resp = self._request('GET', url)
                        if not resp:
                            continue
                    except Exception:
                        continue

                body = resp.text
                pages_found += 1

                # â”€â”€ Extract JS files â”€â”€
                for m in re.finditer(r'<script[^>]+src=["\']([^"\']+)["\']', body, re.IGNORECASE):
                    js_url = urljoin(url, m.group(1))
                    js_urls.add(js_url)

                # â”€â”€ JS Library detection in page â”€â”€
                self._detect_js_libraries(body, url)

                # â”€â”€ Extract & analyze forms â”€â”€
                forms = self._extract_forms(body, url)
                for form in forms:
                    self._check_csrf(url, form)
                    self._check_login_form_security(url, form)

                # â”€â”€ SRI Check â”€â”€
                self._check_sri(body, url, base_netloc)

                # â”€â”€ HTML Comment Analysis â”€â”€
                self._check_html_comments(body, url)

                # â”€â”€ Cloud Storage References â”€â”€
                self._check_cloud_references(body, url)

                # â”€â”€ Extract links for next depth â”€â”€
                if depth < self.crawl_depth - 1:
                    links = self._extract_links(body, url, base_netloc)
                    for link in links:
                        if link not in visited:
                            next_level.append(link)

                time.sleep(0.15)

            to_visit = next_level[:50]
            depth += 1

        if pages_found:
            print(f"  {base_url} -> {pages_found} page(s), {len(js_urls)} JS file(s)")

        # Also scan JS file contents for libraries
        for js_url in list(js_urls)[:30]:
            try:
                js_resp = self._request('GET', js_url, timeout=5)
                if js_resp and js_resp.status_code == 200 and len(js_resp.text) > 50:
                    self._detect_js_libraries(js_resp.text[:100000], js_url)
            except Exception:
                pass
            time.sleep(0.1)

        return js_urls

    def _check_csrf(self, page_url, form):
        """Passively check if a POST form has CSRF protection."""
        self.forms_tested += 1
        method = form.get('method', 'GET')
        inputs = form.get('inputs', {})
        action = form.get('action', page_url)

        if not inputs or method != 'POST':
            return

        has_csrf = False
        csrf_names = ['csrf', 'token', '_token', 'csrfmiddlewaretoken',
                      'authenticity_token', 'xsrf', '__requestverificationtoken',
                      'antiforgery', '__csrf', 'csrf_token']
        for name in inputs:
            if any(csrf in name.lower() for csrf in csrf_names):
                has_csrf = True
                break
            if inputs[name].get('type') == 'hidden' and len(inputs[name].get('value', '')) > 20:
                has_csrf = True
                break

        if not has_csrf:
            self._add_finding(
                vuln_type='Missing CSRF Token',
                severity='MEDIUM', url=action,
                detail=f'POST form at {page_url} lacks a CSRF token. '
                       f'Inputs: {", ".join(list(inputs.keys())[:5])}',
                category='csrf',
                evidence=f'Form action: {action}, Method: POST',
            )

    def _check_login_form_security(self, page_url, form):
        """Check login forms for security issues."""
        inputs = form.get('inputs', {})
        action = form.get('action', page_url)

        has_password = False
        password_autocomplete_ok = True

        for name, info in inputs.items():
            if info.get('type') == 'password':
                has_password = True
                ac = info.get('autocomplete', '')
                if ac not in ('off', 'new-password', 'current-password'):
                    password_autocomplete_ok = False

        if not has_password:
            return

        # Check if form posts to HTTP
        if action.startswith('http://'):
            self._add_finding(
                vuln_type='Login Form Posts Over HTTP',
                severity='HIGH', url=page_url,
                detail=f'Login form submits credentials over unencrypted HTTP: {action}',
                category='login_security',
                evidence=f'Form action: {action}',
            )

        if not password_autocomplete_ok:
            self._add_finding(
                vuln_type='Password Field Missing Autocomplete Control',
                severity='LOW', url=page_url,
                detail='Password field lacks autocomplete="off" or autocomplete="new-password"',
                category='login_security',
                evidence=f'Form at: {page_url}',
            )

    def _check_sri(self, html, page_url, page_netloc):
        """Check external scripts/stylesheets for Subresource Integrity."""
        # Find script tags with src
        external_scripts = []
        for m in re.finditer(
            r'<script([^>]+)src=["\']([^"\']+)["\']([^>]*)>', html, re.IGNORECASE
        ):
            attrs = m.group(1) + m.group(3)
            src = m.group(2)
            full_src = urljoin(page_url, src)
            parsed_src = urlparse(full_src)
            if parsed_src.netloc and parsed_src.netloc != page_netloc:
                if 'integrity' not in attrs.lower():
                    external_scripts.append(full_src)

        # Find link tags for stylesheets
        for m in re.finditer(
            r'<link([^>]+)href=["\']([^"\']+)["\']([^>]*)>', html, re.IGNORECASE
        ):
            attrs = m.group(1) + m.group(3)
            if 'stylesheet' not in attrs.lower():
                continue
            href = m.group(2)
            full_href = urljoin(page_url, href)
            parsed_href = urlparse(full_href)
            if parsed_href.netloc and parsed_href.netloc != page_netloc:
                if 'integrity' not in attrs.lower():
                    external_scripts.append(full_href)

        if external_scripts:
            unique = list(set(external_scripts))[:5]
            self._add_finding(
                vuln_type='Missing Subresource Integrity (SRI)',
                severity='MEDIUM', url=page_url,
                detail=f'{len(set(external_scripts))} external resource(s) loaded without integrity attribute',
                category='sri_missing',
                evidence=f'Examples: {", ".join(unique[:3])}',
            )

    def _check_html_comments(self, html, url):
        """Analyze HTML comments for sensitive content."""
        comments = re.findall(r'<!--(.*?)-->', html, re.DOTALL)
        sensitive_patterns = [
            (r'(?:password|passwd|pwd)\s*[:=]', 'Password reference'),
            (r'(?:api[_\-]?key|apikey|secret[_\-]?key)\s*[:=]', 'API key reference'),
            (r'(?:TODO|FIXME|HACK|XXX|BUG)\b', 'Developer note'),
            (r'(?:admin|root|superuser)\s*[:=]', 'Admin credential reference'),
            (r'(?:username|user)\s*[:=]\s*["\']?\w', 'Username reference'),
            (r'(?:jdbc:|mysql://|postgres://|mongodb://)', 'Database connection string'),
            (r'(?:BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY)', 'Private key'),
            (r'(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})', 'Internal IP'),
            (r'(?:https?://(?:dev|staging|internal|test|local)[.\-])', 'Internal URL'),
        ]

        for comment in comments:
            if len(comment.strip()) < 5:
                continue
            for pattern, desc in sensitive_patterns:
                if re.search(pattern, comment, re.IGNORECASE):
                    snippet = comment.strip()[:150]
                    self._add_finding(
                        vuln_type='Sensitive HTML Comment',
                        severity='MEDIUM' if 'password' in desc.lower() or 'key' in desc.lower()
                                          or 'private' in desc.lower() else 'LOW',
                        url=url,
                        detail=f'{desc} found in HTML comment',
                        category='html_comments',
                        evidence=f'<!-- {snippet} -->',
                    )
                    break  # One finding per comment

    def _check_cloud_references(self, content, url):
        """Detect references to cloud storage buckets."""
        found_refs = []
        for pattern, cloud_type in self.CLOUD_PATTERNS:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                ref = f"{cloud_type}: {match}"
                if ref not in found_refs:
                    found_refs.append(ref)

        if found_refs:
            unique = list(set(found_refs))[:10]
            self._add_finding(
                vuln_type='Cloud Storage Reference',
                severity='MEDIUM', url=url,
                detail=f'{len(unique)} cloud storage reference(s) found. '
                       f'Verify bucket permissions are properly configured.',
                category='cloud_references',
                evidence=f'{"; ".join(unique[:3])}',
            )

    def _check_source_maps(self, js_urls):
        """Check if JavaScript source map files are accessible."""
        maps_found = []
        for js_url in list(js_urls)[:30]:
            map_url = js_url + '.map'
            try:
                resp = self._request('GET', map_url, timeout=5, allow_redirects=False)
                if resp and resp.status_code == 200 and len(resp.text) > 100:
                    # Verify it looks like a source map
                    if '"sources"' in resp.text[:500] or '"mappings"' in resp.text[:500]:
                        maps_found.append(map_url)
            except Exception:
                pass
            time.sleep(0.1)

        if maps_found:
            self._add_finding(
                vuln_type='Source Map Files Exposed',
                severity='MEDIUM', url=maps_found[0],
                detail=f'{len(maps_found)} JavaScript source map(s) accessible. '
                       f'Exposes original source code.',
                category='source_maps',
                evidence=f'Maps: {", ".join(maps_found[:3])}',
            )

    # â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
    #  PHASE 6: SENSITIVE PATH & FILE DISCOVERY
    # â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
    def _is_false_positive(self, body, homepage_hash, soft404_hash):
        """Fast check: is this response a redirect page, soft 404, or homepage clone?"""
        body_lower = body.lower()

        fp_sigs = [
            'page not found', '404 not found', 'does not exist',
            'the page you requested', 'could not be found', 'nothing here',
            'no longer available', "page doesn't exist", 'page does not exist',
            "we couldn't find", 'error 404', 'requested url was not found',
            'resource not found', 'was not found on this server',
            'the requested resource was not found', 'this page is not available',
        ]
        if any(sig in body_lower for sig in fp_sigs):
            return True

        if re.search(r'<meta[^>]+http-equiv\s*=\s*["\']?refresh["\']?', body_lower):
            return True

        if len(body) < 4000 and re.search(
            r'(?:window|document)\.location|location\.(?:href|replace|assign)\s*[$$=]',
            body_lower,
        ):
            return True

        body_hash = hashlib.md5(body.strip().encode(errors='ignore')).hexdigest()
        if homepage_hash and body_hash == homepage_hash:
            return True
        if soft404_hash and body_hash == soft404_hash:
            return True

        return False

    def _validate_null_indicator(self, body, path):
        """For paths with indicator=None, verify the response matches expected content."""
        body_lower = body[:6000].lower()

        path_keywords = {
            '/wp-admin':      ['wordpress', 'wp-login', 'wp-admin', 'wp-content', 'wp-includes'],
            '/wp-login.php':  ['wordpress', 'wp-login', 'user_login', 'loginform', 'wp-submit'],
            '/admin':         ['admin panel', 'dashboard', 'administration', 'sign in', 'log in', 'username', 'password'],
            '/administrator': ['administrator', 'joomla', 'control panel', 'sign in', 'log in'],
            '/graphql':       ['"data"', '"errors"', 'graphql', '__schema', '__type'],
            '/.DS_Store':     [],
        }

        keywords = path_keywords.get(path)
        if keywords is not None:
            if not keywords:
                return '<html' not in body_lower and '<!doctype' not in body_lower
            return any(kw in body_lower for kw in keywords)

        backup_exts = ('.bak', '.old', '.orig', '.save', '.swp', '.tmp', '~', '.copy', '.dist')
        if any(path.endswith(ext) for ext in backup_exts):
            if '<html' in body_lower and '<body' in body_lower and '<head' in body_lower:
                return False

        return True

    def _test_paths(self, base_url):
        """Discover sensitive files, endpoints, and backup files with false-positive filtering."""

        homepage_hash = None
        soft404_hash = None

        hp_resp = self.target_responses.get(base_url)
        if hp_resp and hp_resp.status_code == 200:
            homepage_hash = hashlib.md5(hp_resp.text.strip().encode(errors='ignore')).hexdigest()

        bogus = f"/pg-{hashlib.md5(base_url.encode()).hexdigest()[:8]}-nxist"
        s4_resp = self._request('GET', base_url.rstrip('/') + bogus, allow_redirects=False)
        if s4_resp and s4_resp.status_code == 200:
            soft404_hash = hashlib.md5(s4_resp.text.strip().encode(errors='ignore')).hexdigest()

        interesting_paths = [
            ('/.git/HEAD', 'ref:', 'Exposed Git Repository', 'CRITICAL'),
            ('/.git/config', '[core]', 'Exposed Git Config', 'CRITICAL'),
            ('/.svn/entries', 'dir', 'Exposed SVN Repository', 'HIGH'),
            ('/.env', '=', 'Exposed Environment File', 'CRITICAL'),
            ('/.env.backup', '=', 'Exposed Environment Backup', 'CRITICAL'),
            ('/.env.old', '=', 'Exposed Environment Backup', 'CRITICAL'),
            ('/.DS_Store', None, 'Exposed .DS_Store File', 'LOW'),
            ('/robots.txt', 'disallow', 'Robots.txt Found', 'INFO'),
            ('/sitemap.xml', '<?xml', 'Sitemap Found', 'INFO'),
            ('/crossdomain.xml', 'cross-domain', 'Flash Crossdomain Policy', 'LOW'),
            ('/clientaccesspolicy.xml', 'access-policy', 'Silverlight Access Policy', 'LOW'),
            ('/elmah.axd', 'error log', 'ELMAH Error Log Exposed', 'HIGH'),
            ('/trace.axd', 'application trace', 'ASP.NET Trace Exposed', 'HIGH'),
            ('/server-status', 'apache', 'Apache Server Status Exposed', 'MEDIUM'),
            ('/server-info', 'apache', 'Apache Server Info Exposed', 'MEDIUM'),
            ('/wp-json/wp/v2/users', '"id"', 'WordPress User Enumeration', 'MEDIUM'),
            ('/api/swagger', 'swagger', 'Exposed Swagger/API Docs', 'LOW'),
            ('/swagger-ui.html', 'swagger', 'Exposed Swagger UI', 'LOW'),
            ('/swagger.json', '"swagger"', 'Exposed Swagger JSON', 'LOW'),
            ('/openapi.json', '"openapi"', 'Exposed OpenAPI JSON', 'LOW'),
            ('/api-docs', 'swagger', 'Exposed API Documentation', 'LOW'),
            ('/graphql', None, 'GraphQL Endpoint Accessible', 'LOW'),
            ('/actuator/health', 'status', 'Spring Actuator Health Exposed', 'MEDIUM'),
            ('/actuator/env', 'property', 'Spring Actuator Env Exposed', 'HIGH'),
            ('/actuator/configprops', 'property', 'Spring Actuator Config Exposed', 'HIGH'),
            ('/actuator/beans', '"bean"', 'Spring Actuator Beans Exposed', 'HIGH'),
            ('/.well-known/security.txt', 'contact', 'Security.txt Found', 'INFO'),
            ('/debug', 'debug', 'Debug Endpoint Accessible', 'MEDIUM'),
            ('/console', 'console', 'Web Console Exposed', 'HIGH'),
            ('/phpinfo.php', 'phpinfo', 'phpinfo() Page Exposed', 'HIGH'),
            ('/info.php', 'phpinfo', 'PHP Info Page Exposed', 'HIGH'),
            ('/wp-config.php.bak', 'DB_', 'WordPress Config Backup', 'CRITICAL'),
            ('/web.config', 'configuration', 'IIS web.config Exposed', 'HIGH'),
            ('/package.json', '"name"', 'package.json Exposed', 'LOW'),
            ('/composer.json', '"name"', 'composer.json Exposed', 'LOW'),
            ('/.htpasswd', ':', '.htpasswd Exposed', 'CRITICAL'),
            ('/backup.sql', 'create table', 'SQL Backup Exposed', 'CRITICAL'),
            ('/dump.sql', 'create table', 'SQL Dump Exposed', 'CRITICAL'),
            ('/database.yml', 'adapter', 'Database Config Exposed', 'CRITICAL'),
            ('/config.yml', ':', 'Config YAML Exposed', 'HIGH'),
            ('/config.json', '{', 'Config JSON Exposed', 'HIGH'),
            ('/admin', None, 'Admin Panel Accessible', 'MEDIUM'),
            ('/administrator', None, 'Admin Panel Accessible', 'MEDIUM'),
            ('/wp-admin', None, 'WordPress Admin Found', 'INFO'),
            ('/wp-login.php', None, 'WordPress Login Found', 'INFO'),
        ]

        backup_bases = ['/index.php', '/config.php', '/settings.php',
                        '/web.config', '/app.config', '/database.php',
                        '/wp-config.php', '/.htaccess', '/configuration.php']
        backup_exts = ['.bak', '.old', '.orig', '.save', '.swp', '.tmp',
                       '~', '.copy', '.dist']
        for base_file in backup_bases:
            for ext in backup_exts:
                backup_path = base_file + ext
                interesting_paths.append(
                    (backup_path, None, f'Backup File Exposed ({backup_path})', 'HIGH')
                )

        for entry in interesting_paths:
            path, indicator, name, severity = entry
            url = base_url.rstrip('/') + path
            if url in self.scanned_urls:
                continue
            self.scanned_urls.add(url)

            resp = self._request('GET', url, allow_redirects=False)

            if not resp or resp.status_code != 200:
                continue

            body = resp.text
            if len(body.strip()) < 20:
                continue

            if self._is_false_positive(body, homepage_hash, soft404_hash):
                continue

            if indicator is None:
                if not self._validate_null_indicator(body, path):
                    continue
                self._add_finding(
                    vuln_type=name, severity=severity, url=url,
                    detail=f'{name} at {path} (HTTP 200)',
                    category='path_discovery',
                    evidence=resp.text[:200],
                )
            elif indicator.lower() in body.lower():
                if '.env' in path:
                    if not any(x in body for x in ['DB_', 'API_', 'SECRET', 'KEY=', 'PASSWORD']):
                        continue
                self._add_finding(
                    vuln_type=name, severity=severity, url=url,
                    detail=f'{name} at {path}',
                    category='path_discovery',
                    evidence=resp.text[:200],
                )

            time.sleep(0.1)

        # Directory Listing Detection
        dir_paths = ['/', '/images/', '/uploads/', '/assets/', '/static/',
                     '/css/', '/js/', '/files/', '/media/', '/backup/',
                     '/logs/', '/tmp/', '/data/', '/includes/']
        for path in dir_paths:
            url = base_url.rstrip('/') + path
            if url in self.scanned_urls:
                continue
            self.scanned_urls.add(url)

            resp = self._request('GET', url)
            if not resp or resp.status_code != 200:
                continue

            body_lower = resp.text.lower()
            if any(sig in body_lower for sig in ['index of /', 'directory listing for',
                                                  '<title>directory listing',
                                                  'parent directory</a>']):
                self._add_finding(
                    vuln_type='Directory Listing Enabled',
                    severity='MEDIUM', url=url,
                    detail=f'Directory listing enabled at {path}',
                    category='path_discovery',
                    evidence=resp.text[:300],
                )
            time.sleep(0.1)

    def _test_cors(self, target_url):
        parsed = urlparse(target_url)
        target_origin = f"{parsed.scheme}://{parsed.netloc}"

        tests = [
            ('https://evil.com', 'Arbitrary Origin Reflected', 'HIGH'),
            ('null', 'Null Origin Accepted', 'MEDIUM'),
            (f"https://sub.{parsed.netloc}", 'Subdomain Wildcard', 'LOW'),
            (f"{target_origin}.evil.com", 'Origin Prefix Bypass', 'HIGH'),
        ]

        for origin, desc, severity in tests:
            try:
                resp = self._request('GET', target_url, headers={'Origin': origin})
                if not resp:
                    continue

                acao = resp.headers.get('Access-Control-Allow-Origin', '')
                acac = resp.headers.get('Access-Control-Allow-Credentials', '').lower()

                if acao == '*':
                    self._add_finding(
                        vuln_type='CORS Misconfiguration',
                        severity='MEDIUM' if acac != 'true' else 'HIGH',
                        url=target_url,
                        detail=f'CORS allows any origin (ACAO: *). Credentials: {acac}',
                        category='cors',
                        evidence=f'ACAO: {acao}, ACAC: {acac}',
                    )
                    break

                if acao == origin and origin not in (target_origin,):
                    esc_sev = 'CRITICAL' if acac == 'true' else severity
                    self._add_finding(
                        vuln_type='CORS Misconfiguration',
                        severity=esc_sev, url=target_url,
                        detail=f'CORS reflects arbitrary origin: {desc}. Credentials: {acac}',
                        category='cors',
                        evidence=f'ACAO: {acao}, ACAC: {acac}, Test: {desc}',
                    )
                    break
            except Exception:
                pass

    def _test_http_methods(self, target_url):
        dangerous = ['PUT', 'DELETE', 'PATCH', 'TRACE', 'CONNECT']
        try:
            resp = self._request('OPTIONS', target_url)
            if resp:
                allow = resp.headers.get('Allow', '')
                if allow:
                    allowed = [m.strip().upper() for m in allow.split(',')]
                    bad = [m for m in allowed if m in dangerous]
                    if bad:
                        self._add_finding(
                            vuln_type='Dangerous HTTP Methods Allowed',
                            severity='MEDIUM', url=target_url,
                            detail=f'Dangerous methods: {", ".join(bad)}',
                            category='http_methods',
                            evidence=f'Allow: {allow}',
                        )
                    if 'TRACE' in allowed:
                        self._add_finding(
                            vuln_type='HTTP TRACE Method Enabled (XST Risk)',
                            severity='MEDIUM', url=target_url,
                            detail='TRACE method enabled. Cross-Site Tracing may be possible.',
                            category='http_methods',
                            evidence='Allow header includes TRACE',
                        )
        except Exception:
            pass

    def _check_subdomain_takeover(self, subdomains):
        for sub in subdomains:
            if isinstance(sub, dict):
                sub = sub.get('subdomain', sub.get('domain', ''))
            if not isinstance(sub, str) or not sub:
                continue
            sub = sub.strip().lower()

            try:
                result = subprocess.run(
                    ['nslookup', '-type=CNAME', sub],
                    capture_output=True, text=True, timeout=5
                )
                output = result.stdout.lower()

                for cname_domain, error_sig in self.SUBDOMAIN_TAKEOVER_CNAMES.items():
                    if cname_domain in output:
                        try:
                            resp = self._request('GET', f"https://{sub}", timeout=5)
                            if resp and error_sig.lower() in resp.text.lower():
                                self._add_finding(
                                    vuln_type='Subdomain Takeover',
                                    severity='HIGH', url=f"https://{sub}",
                                    detail=f'{sub} has dangling CNAME to {cname_domain}. Error signature detected.',
                                    category='subdomain_takeover',
                                    evidence=f'CNAME: {cname_domain}, Error: "{error_sig}"',
                                )
                            elif resp is None:
                                self._add_finding(
                                    vuln_type='Potential Subdomain Takeover',
                                    severity='MEDIUM', url=f"https://{sub}",
                                    detail=f'{sub} CNAME to {cname_domain} returns no response.',
                                    category='subdomain_takeover',
                                    evidence=f'CNAME: {cname_domain}, No response',
                                )
                        except Exception:
                            pass
            except Exception:
                pass

            try:
                socket.getaddrinfo(sub, 80)
            except socket.gaierror:
                self._add_finding(
                    vuln_type='Dangling DNS Record',
                    severity='LOW', url=f"https://{sub}",
                    detail=f'{sub} does not resolve (NXDOMAIN). May indicate abandoned infrastructure.',
                    category='subdomain_takeover',
                    evidence='DNS resolution failed',
                )

    def _check_mixed_content(self, target_url):
        if not target_url.startswith('https://'):
            return

        resp = self.target_responses.get(target_url)
        if not resp:
            resp = self._request('GET', target_url)
        if not resp:
            return

        http_resources = re.findall(
            r'(?:src|href|action)\s*=\s*["\']?(http://[^\s"\'<>]+)',
            resp.text, re.IGNORECASE
        )
        safe_domains = ['schemas.microsoft.com', 'www.w3.org', 'schema.org',
                        'xmlns.com', 'purl.org', 'ogp.me']
        mixed = []
        for resource_url in http_resources:
            parsed_res = urlparse(resource_url)
            if parsed_res.netloc not in safe_domains and parsed_res.netloc:
                mixed.append(resource_url)

        if mixed:
            unique_mixed = list(set(mixed))[:10]
            self._add_finding(
                vuln_type='Mixed Content',
                severity='MEDIUM', url=target_url,
                detail=f'{len(set(mixed))} HTTP resource(s) loaded on HTTPS page.',
                category='mixed_content',
                evidence=f'Examples: {", ".join(unique_mixed[:3])}',
            )

    def _check_cache_headers(self, target_url):
        """Check if sensitive-looking pages have proper cache control."""
        sensitive_paths = ['/login', '/signin', '/account', '/profile',
                          '/dashboard', '/admin', '/settings', '/password',
                          '/checkout', '/payment', '/billing']

        base = target_url.rstrip('/')
        for path in sensitive_paths:
            url = base + path
            if url in self.scanned_urls:
                continue

            resp = self._request('GET', url, allow_redirects=False)
            if not resp or resp.status_code not in (200, 301, 302):
                continue

            if resp.status_code == 200:
                cc = resp.headers.get('Cache-Control', '')
                pragma = resp.headers.get('Pragma', '')
                if not cc or ('no-store' not in cc.lower() and 'private' not in cc.lower()):
                    self._add_finding(
                        vuln_type='Missing Cache-Control on Sensitive Page',
                        severity='LOW', url=url,
                        detail=f'Sensitive page {path} missing Cache-Control: no-store or private. '
                               f'Current: "{cc or "not set"}"',
                        category='cache_headers',
                        evidence=f'Cache-Control: {cc}, Pragma: {pragma}',
                    )
            time.sleep(0.1)

    def _check_dns_security(self, domain):
        """Check SPF, DMARC, and CAA DNS records."""
        try:
            import dns.resolver

            # SPF
            try:
                answers = dns.resolver.resolve(domain, 'TXT')
                has_spf = any('v=spf1' in str(rdata) for rdata in answers)
                if not has_spf:
                    self._add_finding(
                        vuln_type='Missing SPF Record',
                        severity='MEDIUM', url=f'dns://{domain}',
                        detail='No SPF record found. Domain may be spoofable for email.',
                        category='dns_security',
                        evidence='No TXT record containing v=spf1',
                    )
                else:
                    for rdata in answers:
                        spf_str = str(rdata)
                        if 'v=spf1' in spf_str and '+all' in spf_str:
                            self._add_finding(
                                vuln_type='Permissive SPF Record',
                                severity='HIGH', url=f'dns://{domain}',
                                detail='SPF record uses +all, which allows any server to send mail as this domain.',
                                category='dns_security',
                                evidence=f'SPF: {spf_str}',
                            )
                    print(f"  [+] SPF record found for {domain}")
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
                self._add_finding(
                    vuln_type='Missing SPF Record',
                    severity='MEDIUM', url=f'dns://{domain}',
                    detail='No SPF record found.',
                    category='dns_security',
                    evidence='DNS query returned no TXT records',
                )

            # DMARC
            try:
                answers = dns.resolver.resolve(f'_dmarc.{domain}', 'TXT')
                has_dmarc = any('v=DMARC1' in str(rdata) for rdata in answers)
                if not has_dmarc:
                    self._add_finding(
                        vuln_type='Missing DMARC Record',
                        severity='MEDIUM', url=f'dns://{domain}',
                        detail='No DMARC record found. Email spoofing detection is not configured.',
                        category='dns_security',
                        evidence='No TXT record at _dmarc containing v=DMARC1',
                    )
                else:
                    for rdata in answers:
                        dmarc_str = str(rdata)
                        if 'v=DMARC1' in dmarc_str and 'p=none' in dmarc_str:
                            self._add_finding(
                                vuln_type='DMARC Policy Set to None',
                                severity='LOW', url=f'dns://{domain}',
                                detail='DMARC record exists but policy is "none" (monitoring only).',
                                category='dns_security',
                                evidence=f'DMARC: {dmarc_str}',
                            )
                    print(f"  [+] DMARC record found for {domain}")
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
                self._add_finding(
                    vuln_type='Missing DMARC Record',
                    severity='MEDIUM', url=f'dns://{domain}',
                    detail='No DMARC record found.',
                    category='dns_security',
                    evidence='DNS query for _dmarc returned no results',
                )

            # CAA
            try:
                answers = dns.resolver.resolve(domain, 'CAA')
                if answers:
                    print(f"  [+] CAA record found for {domain}")
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
                self._add_finding(
                    vuln_type='Missing CAA Record',
                    severity='LOW', url=f'dns://{domain}',
                    detail='No CAA record found. Any CA can issue certificates for this domain.',
                    category='dns_security',
                    evidence='No CAA DNS record',
                )
            except Exception:
                pass

            return

        except ImportError:
            pass

        self._dns_check_fallback(domain)

    def _dns_check_fallback(self, domain):
        """Fallback DNS check using subprocess."""
        for cmd_name in ['dig', 'nslookup']:
            try:
                if cmd_name == 'dig':
                    r = subprocess.run(['dig', '+short', 'TXT', domain],
                                       capture_output=True, text=True, timeout=10)
                    if 'v=spf1' not in r.stdout:
                        self._add_finding(
                            vuln_type='Missing SPF Record', severity='MEDIUM',
                            url=f'dns://{domain}',
                            detail='No SPF record found.',
                            category='dns_security', evidence='dig TXT query returned no SPF',
                        )
                    else:
                        print(f"  [+] SPF record found for {domain}")
                        if '+all' in r.stdout:
                            self._add_finding(
                                vuln_type='Permissive SPF Record', severity='HIGH',
                                url=f'dns://{domain}',
                                detail='SPF uses +all (allows any sender).',
                                category='dns_security', evidence=r.stdout.strip()[:200],
                            )

                    r = subprocess.run(['dig', '+short', 'TXT', f'_dmarc.{domain}'],
                                       capture_output=True, text=True, timeout=10)
                    if 'v=DMARC1' not in r.stdout:
                        self._add_finding(
                            vuln_type='Missing DMARC Record', severity='MEDIUM',
                            url=f'dns://{domain}',
                            detail='No DMARC record found.',
                            category='dns_security', evidence='dig TXT _dmarc returned no DMARC',
                        )
                    else:
                        print(f"  [+] DMARC record found for {domain}")

                    r = subprocess.run(['dig', '+short', 'CAA', domain],
                                       capture_output=True, text=True, timeout=10)
                    if not r.stdout.strip():
                        self._add_finding(
                            vuln_type='Missing CAA Record', severity='LOW',
                            url=f'dns://{domain}',
                            detail='No CAA record found.',
                            category='dns_security', evidence='No CAA record',
                        )
                    else:
                        print(f"  [+] CAA record found for {domain}")

                else:
                    r = subprocess.run(['nslookup', '-type=TXT', domain],
                                       capture_output=True, text=True, timeout=10)
                    if 'v=spf1' not in r.stdout:
                        self._add_finding(
                            vuln_type='Missing SPF Record', severity='MEDIUM',
                            url=f'dns://{domain}', detail='No SPF record found.',
                            category='dns_security', evidence='nslookup TXT returned no SPF',
                        )
                    else:
                        print(f"  [+] SPF record found for {domain}")

                    r2 = subprocess.run(['nslookup', '-type=TXT', f'_dmarc.{domain}'],
                                        capture_output=True, text=True, timeout=10)
                    if 'v=DMARC1' not in r2.stdout:
                        self._add_finding(
                            vuln_type='Missing DMARC Record', severity='MEDIUM',
                            url=f'dns://{domain}', detail='No DMARC record found.',
                            category='dns_security', evidence='nslookup returned no DMARC',
                        )
                    else:
                        print(f"  [+] DMARC record found for {domain}")

                return

            except FileNotFoundError:
                continue
            except Exception as e:
                logger.debug(f"DNS fallback error with {cmd_name}: {e}")
                continue

        print(f"  [-] DNS checks skipped (no dig/nslookup/dnspython available)")

    def _version_lt(self, v1, v2):
        """Check if version v1 < v2."""
        try:
            parts1 = tuple(int(x) for x in v1.split('.'))
            parts2 = tuple(int(x) for x in v2.split('.'))
            return parts1 < parts2
        except (ValueError, AttributeError):
            return False

    def _request(self, method, url, timeout=None, allow_redirects=True,
                 data=None, params=None, headers=None):
        self.requests_made += 1
        try:
            kwargs = {
                'timeout': timeout or self.timeout,
                'allow_redirects': allow_redirects,
                'verify': False,
            }
            if data:
                kwargs['data'] = data
            if params:
                kwargs['params'] = params
            if headers:
                merged = dict(self.session.headers)
                merged.update(headers)
                kwargs['headers'] = merged

            return self.session.request(method, url, **kwargs)
        except requests.exceptions.SSLError:
            if url.startswith('https://'):
                try:
                    alt = 'http://' + url[8:]
                    return self.session.request(method, alt, **kwargs)
                except Exception:
                    return None
            return None
        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError):
            return None
        except Exception as e:
            logger.debug(f"Request error {method} {url}: {e}")
            return None

    def _extract_forms(self, html, base_url):
        forms = []
        if not HAS_BS4:
            for m in re.finditer(r'<form([^>]*)>(.*?)</form>', html, re.DOTALL | re.IGNORECASE):
                attrs = m.group(1)
                body = m.group(2)
                action = re.search(r'action=["\']([^"\']*)["\']', attrs)
                method = re.search(r'method=["\']([^"\']*)["\']', attrs)
                inputs = {}
                for inp in re.finditer(r'<input([^>]*)>', body, re.IGNORECASE):
                    inp_attrs = inp.group(1)
                    name = re.search(r'name=["\']([^"\']*)["\']', inp_attrs)
                    val = re.search(r'value=["\']([^"\']*)["\']', inp_attrs)
                    itype = re.search(r'type=["\']([^"\']*)["\']', inp_attrs)
                    ac = re.search(r'autocomplete=["\']([^"\']*)["\']', inp_attrs)
                    if name:
                        inputs[name.group(1)] = {
                            'value': val.group(1) if val else '',
                            'type': itype.group(1).lower() if itype else 'text',
                            'autocomplete': ac.group(1).lower() if ac else '',
                        }
                forms.append({
                    'action': urljoin(base_url, action.group(1)) if action else base_url,
                    'method': (method.group(1).upper() if method else 'GET'),
                    'inputs': inputs,
                })
            return forms

        try:
            soup = BeautifulSoup(html, 'html.parser')
            for form in soup.find_all('form'):
                action = form.get('action', '')
                action = urljoin(base_url, action) if action else base_url
                method = form.get('method', 'GET').upper()
                inputs = {}
                for inp in form.find_all(['input', 'textarea', 'select']):
                    name = inp.get('name')
                    if not name:
                        continue
                    itype = inp.get('type', 'text').lower()
                    val = inp.get('value', '')
                    ac = inp.get('autocomplete', '')
                    if itype in ('submit', 'button', 'image', 'reset'):
                        continue
                    inputs[name] = {'value': val, 'type': itype, 'autocomplete': ac.lower()}
                if inputs:
                    forms.append({'action': action, 'method': method, 'inputs': inputs})
        except Exception as e:
            logger.debug(f"Form extraction error: {e}")
        return forms

    def _extract_links(self, html, base_url, base_netloc):
        links = set()
        if HAS_BS4:
            try:
                soup = BeautifulSoup(html, 'html.parser')
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
            for m in re.finditer(r'href=["\']([^"\'#]+)["\']', html):
                full = urljoin(base_url, m.group(1))
                p = urlparse(full)
                if p.netloc == base_netloc:
                    links.add(f"{p.scheme}://{p.netloc}{p.path}")
        return links

    def _add_finding(self, vuln_type, severity, url, detail, category,
                     evidence='', param=''):
        dedup_key = (vuln_type, url, param, category)
        if dedup_key in self.seen_findings:
            return
        self.seen_findings.add(dedup_key)

        finding = {
            'type': vuln_type,
            'severity': severity,
            'url': url,
            'detail': detail,
            'category': category,
            'evidence': evidence,
        }
        if param:
            finding['parameter'] = param
        self.findings.append(finding)

        icons = {'CRITICAL': '[!!]', 'HIGH': '[!]', 'MEDIUM': '[~]',
                 'LOW': '[.]', 'INFO': '[i]'}
        icon = icons.get(severity, '[?]')
        print(f"  {icon} [{severity}] {vuln_type}: {url[:70]}")

    def _dedup_findings(self, findings):
        seen = set()
        unique = []
        for f in findings:
            key = (f['type'], f['url'], f.get('parameter', ''), f['category'])
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique

    def _print_summary(self):
        sev_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
        cat_counts = {}
        for f in self.findings:
            sev_counts[f['severity']] = sev_counts.get(f['severity'], 0) + 1
            cat_counts[f['category']] = cat_counts.get(f['category'], 0) + 1

        print(f"\n{'='*60}")
        print(f"  VULNERABILITY SCAN RESULTS (Non-Intrusive)")
        print(f"{'='*60}")
        print(f"  Total findings:  {len(self.findings)}")
        print(f"  CRITICAL:        {sev_counts['CRITICAL']}")
        print(f"  HIGH:            {sev_counts['HIGH']}")
        print(f"  MEDIUM:          {sev_counts['MEDIUM']}")
        print(f"  LOW:             {sev_counts['LOW']}")
        print(f"  INFO:            {sev_counts['INFO']}")
        print(f"  Requests made:   {self.requests_made}")
        print(f"  Forms analyzed:  {self.forms_tested}")
        print(f"{'='*60}")

        if cat_counts:
            print(f"\n  By Category:")
            for cat, count in sorted(cat_counts.items(), key=lambda x: x[1], reverse=True):
                print(f"    {cat.replace('_', ' ').title():<40} {count}")

        if self.findings:
            sev_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}
            print(f"\n  Detailed Findings:")
            print(f"  {'-'*56}")
            for i, f in enumerate(
                sorted(self.findings, key=lambda x: sev_order.get(x['severity'], 5)), 1
            ):
                icons = {'CRITICAL': '[!!]', 'HIGH': '[!]', 'MEDIUM': '[~]',
                         'LOW': '[.]', 'INFO': '[i]'}
                icon = icons.get(f['severity'], '[?]')
                print(f"\n  {icon} #{i} [{f['severity']}] {f['type']}")
                print(f"     URL: {f['url'][:80]}")
                if f.get('parameter'):
                    print(f"     Param: {f['parameter']}")
                print(f"     Detail: {f['detail'][:120]}")
                if f.get('evidence'):
                    print(f"     Evidence: {f['evidence'][:120]}")

        print(f"\n{'='*60}\n")

    def _build_results(self, target):
        sev_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}
        sorted_findings = sorted(self.findings, key=lambda x: sev_order.get(x['severity'], 5))

        by_category = {}
        for f in sorted_findings:
            cat = f['category']
            if cat not in by_category:
                by_category[cat] = []
            by_category[cat].append(f)

        shadow_flags = []
        for f in sorted_findings:
            if f['severity'] in ('CRITICAL', 'HIGH'):
                shadow_flags.append({
                    'type': f'Vulnerability: {f["type"]}',
                    'asset': f['url'],
                    'reason': f'{f["detail"][:200]}',
                    'module': 'web_vuln_scanner',
                })

        next_steps = self._build_next_steps(by_category)

        return {
            'all_findings': sorted_findings,
            'by_category': by_category,
            'summary': {
                'total': len(self.findings),
                'critical': sum(1 for f in self.findings if f['severity'] == 'CRITICAL'),
                'high': sum(1 for f in self.findings if f['severity'] == 'HIGH'),
                'medium': sum(1 for f in self.findings if f['severity'] == 'MEDIUM'),
                'low': sum(1 for f in self.findings if f['severity'] == 'LOW'),
                'info': sum(1 for f in self.findings if f['severity'] == 'INFO'),
            },
            'scan_stats': {
                'requests_made': self.requests_made,
                'forms_analyzed': self.forms_tested,
                'scan_level': self.scan_level,
            },
            'shadow_it_flags': shadow_flags,
            'next_steps': next_steps,
        }

    def _build_next_steps(self, by_cat):
        steps = []

        if 'ssl_tls' in by_cat:
            crit = [f for f in by_cat['ssl_tls'] if f['severity'] in ('CRITICAL', 'HIGH')]
            if crit:
                steps.append({
                    'action': 'Fix SSL/TLS Certificate Issues',
                    'description': f'{len(crit)} critical/high SSL issue(s). '
                                   'Renew expired certs, replace self-signed certs, fix CN mismatches.',
                    'priority': 'CRITICAL',
                })

        if 'csp_issues' in by_cat:
            steps.append({
                'action': 'Strengthen Content Security Policy',
                'description': f'{len(by_cat["csp_issues"])} CSP weakness(es). '
                               "Remove 'unsafe-inline'/'unsafe-eval', add missing directives.",
                'priority': 'HIGH',
            })

        if 'cors' in by_cat:
            steps.append({
                'action': 'Fix CORS Configuration',
                'description': f'{len(by_cat["cors"])} finding(s). '
                               'Restrict Access-Control-Allow-Origin to trusted domains.',
                'priority': 'HIGH',
            })

        if 'path_discovery' in by_cat:
            crit_paths = [f for f in by_cat['path_discovery'] if f['severity'] in ('CRITICAL', 'HIGH')]
            if crit_paths:
                steps.append({
                    'action': 'Remove Exposed Sensitive Files',
                    'description': f'{len(crit_paths)} critical/high file(s) exposed. '
                                   'Remove .git, .env, backups, and debug endpoints from production.',
                    'priority': 'CRITICAL',
                })

        if 'security_headers' in by_cat:
            steps.append({
                'action': 'Implement Security Headers',
                'description': f'{len(by_cat["security_headers"])} header issue(s). '
                               'Add HSTS, CSP, X-Frame-Options, X-Content-Type-Options.',
                'priority': 'MEDIUM',
            })

        if 'subdomain_takeover' in by_cat:
            steps.append({
                'action': 'Clean Up Dangling DNS Records',
                'description': f'{len(by_cat["subdomain_takeover"])} finding(s). '
                               'Remove DNS records pointing to decommissioned services.',
                'priority': 'HIGH',
            })

        if 'csrf' in by_cat:
            steps.append({
                'action': 'Implement CSRF Protection',
                'description': f'{len(by_cat["csrf"])} form(s) missing CSRF tokens.',
                'priority': 'MEDIUM',
            })

        if 'cookie_security' in by_cat:
            steps.append({
                'action': 'Harden Cookie Configuration',
                'description': f'{len(by_cat["cookie_security"])} insecure cookie(s). '
                               'Set Secure, HttpOnly, and SameSite attributes.',
                'priority': 'MEDIUM',
            })

        if 'info_disclosure' in by_cat:
            steps.append({
                'action': 'Fix Information Disclosure',
                'description': f'{len(by_cat["info_disclosure"])} finding(s). '
                               'Remove version headers, disable debug mode, suppress errors.',
                'priority': 'MEDIUM',
            })

        if 'technology' in by_cat:
            vuln_libs = [f for f in by_cat['technology'] if 'Vulnerable' in f['type']]
            if vuln_libs:
                steps.append({
                    'action': 'Update Vulnerable JavaScript Libraries',
                    'description': f'{len(vuln_libs)} outdated library/libraries with known CVEs.',
                    'priority': 'HIGH',
                })

        if 'sri_missing' in by_cat:
            steps.append({
                'action': 'Implement Subresource Integrity (SRI)',
                'description': f'{len(by_cat["sri_missing"])} page(s) loading external resources without integrity checks.',
                'priority': 'MEDIUM',
            })

        if 'source_maps' in by_cat:
            steps.append({
                'action': 'Remove Source Map Files from Production',
                'description': 'Source maps expose original source code to attackers.',
                'priority': 'MEDIUM',
            })

        if 'dns_security' in by_cat:
            steps.append({
                'action': 'Implement DNS Security Records',
                'description': f'{len(by_cat["dns_security"])} DNS issue(s). '
                               'Add SPF, DMARC, and CAA records.',
                'priority': 'MEDIUM',
            })

        if 'login_security' in by_cat:
            steps.append({
                'action': 'Harden Login Form Security',
                'description': f'{len(by_cat["login_security"])} issue(s). '
                               'Ensure forms post over HTTPS, set autocomplete attributes.',
                'priority': 'HIGH',
            })

        if 'cloud_references' in by_cat:
            steps.append({
                'action': 'Audit Cloud Storage Bucket Permissions',
                'description': f'{len(by_cat["cloud_references"])} cloud reference(s) found. '
                               'Verify buckets are not publicly writable.',
                'priority': 'MEDIUM',
            })

        if 'html_comments' in by_cat:
            steps.append({
                'action': 'Remove Sensitive HTML Comments',
                'description': f'{len(by_cat["html_comments"])} comment(s) with sensitive content.',
                'priority': 'LOW',
            })

        if 'cache_headers' in by_cat:
            steps.append({
                'action': 'Add Cache-Control to Sensitive Pages',
                'description': f'{len(by_cat["cache_headers"])} sensitive page(s) missing '
                               'Cache-Control: no-store.',
                'priority': 'LOW',
            })

        if 'http_methods' in by_cat:
            steps.append({
                'action': 'Restrict HTTP Methods',
                'description': f'{len(by_cat["http_methods"])} finding(s). '
                               'Disable TRACE, PUT, DELETE on production.',
                'priority': 'LOW',
            })

        if 'mixed_content' in by_cat:
            steps.append({
                'action': 'Fix Mixed Content',
                'description': f'{len(by_cat["mixed_content"])} page(s) loading HTTP resources over HTTPS.',
                'priority': 'MEDIUM',
            })

        if 'internal_leakage' in by_cat:
            steps.append({
                'action': 'Remove Internal Information Leakage',
                'description': f'{len(by_cat["internal_leakage"])} finding(s). '
                               'Remove internal IPs and sensitive emails from responses.',
                'priority': 'MEDIUM',
            })

        return steps
