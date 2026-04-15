"""
CDN & Proxy Detection Utility
Identifies CDN-fronted domains to prevent false positives in IP/ASN analysis.
Used by network_recon and web_vuln_scanner modules.
"""

import re
import socket
import struct
import logging
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logger = logging.getLogger(__name__)


class CDNDetector:
    """
    Multi-method CDN detection:
      1. Known CDN IP ranges (CIDR matching)
      2. Known CDN ASNs
      3. HTTP response header signatures
      4. Cookie signatures
      5. CNAME chain analysis
    """

    # ── Known CDN IPv4 CIDR Ranges ──
    CDN_IP_RANGES = {
        'Cloudflare': [
            '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22',
            '103.31.4.0/22', '141.101.64.0/18', '108.162.192.0/18',
            '190.93.240.0/20', '188.114.96.0/20', '197.234.240.0/22',
            '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13',
            '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22',
        ],
        'Fastly': [
            '23.235.32.0/20', '43.249.72.0/22', '103.244.50.0/24',
            '103.245.222.0/23', '103.245.224.0/24', '104.156.80.0/20',
            '140.248.64.0/18', '140.248.128.0/17', '146.75.0.0/17',
            '151.101.0.0/16', '157.52.64.0/18', '167.82.0.0/17',
            '167.82.128.0/20', '167.82.160.0/20', '167.82.224.0/20',
            '185.31.16.0/22', '199.27.72.0/21', '199.232.0.0/16',
        ],
        'Akamai': [
            '23.0.0.0/12', '23.32.0.0/11', '23.64.0.0/14',
            '23.72.0.0/13', '104.64.0.0/10',
            '184.24.0.0/13', '184.50.0.0/15', '184.84.0.0/14',
            '2.16.0.0/13',
        ],
        'AWS CloudFront': [
            '13.32.0.0/15', '13.35.0.0/16', '13.224.0.0/14',
            '13.249.0.0/16', '18.64.0.0/14', '18.68.0.0/16',
            '18.154.0.0/15', '18.160.0.0/15', '18.164.0.0/14',
            '52.46.0.0/18', '52.84.0.0/15', '52.222.128.0/17',
            '54.182.0.0/16', '54.192.0.0/16', '54.230.0.0/16',
            '54.239.128.0/18', '54.239.192.0/19', '64.252.64.0/18',
            '64.252.128.0/18', '65.8.0.0/16', '65.9.0.0/17',
            '65.9.128.0/18', '70.132.0.0/18', '71.152.0.0/17',
            '99.84.0.0/16', '99.86.0.0/16', '108.138.0.0/15',
            '108.156.0.0/14', '116.129.226.0/25', '130.176.0.0/17',
            '143.204.0.0/16', '144.220.0.0/16', '204.246.164.0/22',
            '204.246.168.0/22', '204.246.172.0/24', '204.246.174.0/23',
            '204.246.176.0/20', '205.251.200.0/21', '205.251.249.0/24',
            '205.251.250.0/23', '205.251.252.0/23', '205.251.254.0/24',
        ],
        'Sucuri': [
            '192.88.134.0/23', '185.93.228.0/22', '66.248.200.0/22',
        ],
        'Incapsula/Imperva': [
            '199.83.128.0/21', '198.143.32.0/19', '149.126.72.0/21',
            '103.28.248.0/22', '45.64.64.0/22', '107.154.0.0/16',
            '45.60.0.0/16', '45.223.0.0/16',
        ],
        'StackPath/MaxCDN': [
            '69.16.128.0/17', '93.188.128.0/17', '173.222.0.0/15',
        ],
    }

    # ── Known CDN ASNs ──
    CDN_ASNS = {
        'AS13335': 'Cloudflare',
        'AS209242': 'Cloudflare',
        'AS14789': 'Cloudflare (Spectrum)',
        'AS20940': 'Akamai',
        'AS16625': 'Akamai',
        'AS21342': 'Akamai',
        'AS21399': 'Akamai',
        'AS54113': 'Fastly',
        'AS16509': 'Amazon (may be CloudFront)',
        'AS14618': 'Amazon (may be CloudFront)',
        'AS15169': 'Google (may be Cloud CDN)',
        'AS8075': 'Microsoft (may be Azure CDN)',
        'AS30148': 'Sucuri',
        'AS19551': 'Incapsula/Imperva',
        'AS33438': 'StackPath/MaxCDN',
        'AS132892': 'KeyCDN',
        'AS200325': 'Bunny CDN',
        'AS22822': 'Limelight Networks',
        'AS2906': 'Netflix Open Connect',
        'AS46489': 'Twitch/Amazon',
        'AS36183': 'Akamai (Prolexic)',
        'AS12222': 'Akamai',
        'AS35994': 'Akamai',
        'AS393560': 'Cloudflare (WARP)',
        'AS399561': 'Fastly',
        'AS394536': 'Fastly',
    }

    # ── Response Header Signatures ──
    HEADER_SIGNATURES = {
        'Cloudflare': {
            'server_pattern': r'^cloudflare$',
            'header_keys': ['cf-ray', 'cf-cache-status', 'cf-request-id'],
            'cookie_patterns': ['__cfduid', '__cf_bm', 'cf_clearance'],
        },
        'AWS CloudFront': {
            'server_pattern': r'^amazons3$|^cloudfront$',
            'header_keys': ['x-amz-cf-id', 'x-amz-cf-pop', 'x-amz-request-id'],
            'cookie_patterns': ['AWSALB', 'AWSALBCORS'],
        },
        'Akamai': {
            'server_pattern': r'^AkamaiGHost',
            'header_keys': ['x-akamai-transformed', 'x-akamai-request-id',
                            'x-akamai-staging', 'x-check-cacheable'],
            'cookie_patterns': ['AKA_A2', 'akamai'],
        },
        'Fastly': {
            'server_pattern': None,
            'header_keys': ['x-served-by', 'x-cache', 'x-cache-hits',
                            'x-fastly-request-id', 'fastly-debug-digest'],
            'cookie_patterns': [],
        },
        'Sucuri': {
            'server_pattern': r'^Sucuri',
            'header_keys': ['x-sucuri-id', 'x-sucuri-cache'],
            'cookie_patterns': ['sucuri_cloudproxy'],
        },
        'Incapsula/Imperva': {
            'server_pattern': None,
            'header_keys': ['x-iinfo', 'x-cdn'],
            'cookie_patterns': ['visid_incap_', 'incap_ses_', '__utm_inc'],
        },
        'Varnish': {
            'server_pattern': None,
            'header_keys': ['x-varnish', 'via'],
            'cookie_patterns': [],
            'via_pattern': r'varnish',
        },
        'Nginx (Reverse Proxy)': {
            'server_pattern': r'^nginx',
            'header_keys': ['x-nginx-cache'],
            'cookie_patterns': [],
        },
        'KeyCDN': {
            'server_pattern': r'^keycdn',
            'header_keys': ['x-edge-location'],
            'cookie_patterns': [],
        },
        'Bunny CDN': {
            'server_pattern': r'^BunnyCDN',
            'header_keys': ['cdn-pullzone', 'cdn-uid', 'cdn-requestid'],
            'cookie_patterns': [],
        },
        'StackPath': {
            'server_pattern': None,
            'header_keys': ['x-sp-request-id'],
            'cookie_patterns': [],
        },
        'Azure CDN': {
            'server_pattern': None,
            'header_keys': ['x-ms-ref', 'x-azure-ref'],
            'cookie_patterns': [],
        },
        'Google Cloud CDN': {
            'server_pattern': r'^gws$|^GFE',
            'header_keys': ['x-goog-generation', 'x-guploader-uploadid'],
            'cookie_patterns': [],
        },
        'DDoS-Guard': {
            'server_pattern': r'^ddos-guard',
            'header_keys': [],
            'cookie_patterns': ['__ddg'],
        },
        'ArvanCloud': {
            'server_pattern': r'^ArvanCloud',
            'header_keys': ['ar-atime', 'ar-cache', 'ar-request-id'],
            'cookie_patterns': [],
        },
    }

    # ── CNAME patterns that indicate CDN ──
    CNAME_CDN_PATTERNS = {
        r'\.cloudflare\.com$': 'Cloudflare',
        r'\.cloudflare\.net$': 'Cloudflare',
        r'\.cloudfront\.net$': 'AWS CloudFront',
        r'\.akamaiedge\.net$': 'Akamai',
        r'\.akamaitechnologies\.com$': 'Akamai',
        r'\.akamaized\.net$': 'Akamai',
        r'\.edgesuite\.net$': 'Akamai',
        r'\.edgekey\.net$': 'Akamai',
        r'\.fastly\.net$': 'Fastly',
        r'\.fastlylb\.net$': 'Fastly',
        r'\.azureedge\.net$': 'Azure CDN',
        r'\.azurefd\.net$': 'Azure Front Door',
        r'\.msecnd\.net$': 'Azure CDN',
        r'\.sucuri\.net$': 'Sucuri',
        r'\.incapdns\.net$': 'Incapsula/Imperva',
        r'\.impervadns\.net$': 'Incapsula/Imperva',
        r'\.stackpathdns\.com$': 'StackPath',
        r'\.netlify\.app$': 'Netlify CDN',
        r'\.vercel-dns\.com$': 'Vercel CDN',
        r'\.cdn77\.org$': 'CDN77',
        r'\.kxcdn\.com$': 'KeyCDN',
        r'\.b-cdn\.net$': 'Bunny CDN',
        r'\.lxdns\.com$': 'ChinaNetCenter',
        r'\.cdnhwc\d+\.com$': 'Huawei CDN',
        r'\.cdn\.dnsv1\.com$': 'Tencent CDN',
        r'\.kunlun\w+\.com$': 'Alibaba CDN',
    }

    def __init__(self, timeout=10):
        self.timeout = timeout
        self._compiled_cidrs = {}
        self._compile_cidrs()

    def _compile_cidrs(self):
        """Pre-compute CIDR ranges to (network_int, mask_int) tuples for fast matching."""
        for cdn_name, cidrs in self.CDN_IP_RANGES.items():
            self._compiled_cidrs[cdn_name] = []
            for cidr in cidrs:
                try:
                    network, prefix_len = cidr.split('/')
                    prefix_len = int(prefix_len)
                    network_int = self._ip_to_int(network)
                    mask_int = (0xFFFFFFFF << (32 - prefix_len)) & 0xFFFFFFFF
                    self._compiled_cidrs[cdn_name].append((network_int, mask_int))
                except Exception:
                    continue

    @staticmethod
    def _ip_to_int(ip):
        return struct.unpack('!I', socket.inet_aton(ip))[0]

    def _ip_in_cdn_range(self, ip):
        """Check if an IP falls within any known CDN CIDR range."""
        try:
            ip_int = self._ip_to_int(ip)
        except (OSError, struct.error):
            return None

        for cdn_name, ranges in self._compiled_cidrs.items():
            for network_int, mask_int in ranges:
                if (ip_int & mask_int) == (network_int & mask_int):
                    return cdn_name
        return None

    def check_asn(self, asn_str):
        """Check if an ASN belongs to a known CDN provider.

        Args:
            asn_str: ASN string like 'AS13335' or '13335'

        Returns:
            CDN name string or None
        """
        if not asn_str:
            return None
        asn_upper = asn_str.upper().strip()
        if not asn_upper.startswith('AS'):
            asn_upper = f'AS{asn_upper}'
        return self.CDN_ASNS.get(asn_upper)

    def check_ip(self, ip):
        """Check if an IP belongs to a known CDN range.

        Returns:
            CDN name string or None
        """
        if not ip:
            return None
        return self._ip_in_cdn_range(ip)

    def check_headers(self, response):
        """Detect CDN from HTTP response headers and cookies.

        Args:
            response: requests.Response object

        Returns:
            list of detected CDN names (may be empty)
        """
        if not response:
            return []

        detected = []
        headers_lower = {k.lower(): v.lower() for k, v in response.headers.items()}
        server_lower = headers_lower.get('server', '')
        via_lower = headers_lower.get('via', '')
        cookie_names = ' '.join(c.name.lower() for c in response.cookies)

        for cdn_name, sigs in self.HEADER_SIGNATURES.items():
            found = False

            # Server header pattern
            if sigs.get('server_pattern') and server_lower:
                if re.search(sigs['server_pattern'], server_lower, re.IGNORECASE):
                    found = True

            # Header keys
            if not found:
                for hk in sigs.get('header_keys', []):
                    if hk.lower() in headers_lower:
                        found = True
                        break

            # Cookie patterns
            if not found:
                for cp in sigs.get('cookie_patterns', []):
                    if cp.lower() in cookie_names:
                        found = True
                        break

            # Via header pattern
            if not found and sigs.get('via_pattern') and via_lower:
                if re.search(sigs['via_pattern'], via_lower, re.IGNORECASE):
                    found = True

            if found:
                detected.append(cdn_name)

        return detected

    def check_cname(self, hostname):
        """Check CNAME chain for CDN indicators.

        Args:
            hostname: domain name to check

        Returns:
            dict with 'cdn_name', 'cname_chain' or None
        """
        cname_chain = []

        # Try dnspython first
        try:
            import dns.resolver
            try:
                answers = dns.resolver.resolve(hostname, 'CNAME')
                for rdata in answers:
                    cname_chain.append(str(rdata.target).rstrip('.').lower())
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
                    dns.resolver.NoNameservers, dns.resolver.Timeout):
                pass
        except ImportError:
            # Fallback: subprocess
            import subprocess
            try:
                result = subprocess.run(
                    ['nslookup', '-type=CNAME', hostname],
                    capture_output=True, text=True, timeout=5
                )
                for line in result.stdout.split('\n'):
                    line_lower = line.strip().lower()
                    if 'canonical name' in line_lower or 'cname' in line_lower:
                        match = re.search(r'=\s*(\S+)', line)
                        if match:
                            cname_chain.append(match.group(1).rstrip('.').lower())
            except Exception:
                pass

        # Check CNAME chain against known CDN patterns
        for cname in cname_chain:
            for pattern, cdn_name in self.CNAME_CDN_PATTERNS.items():
                if re.search(pattern, cname):
                    return {
                        'cdn_name': cdn_name,
                        'cname_chain': cname_chain,
                        'matched_cname': cname,
                    }

        return {'cdn_name': None, 'cname_chain': cname_chain} if cname_chain else None

    def full_detect(self, hostname, resolved_ips=None, asn=None, response=None):
        """Run all CDN detection methods and return a consolidated result.

        Returns:
            dict: {
                'is_cdn': bool,
                'cdn_name': str or None (primary),
                'all_detected': list of str,
                'detection_methods': list of str,
                'cname_chain': list or None,
                'is_origin_ip': bool (True = IP is likely the actual origin),
                'confidence': str ('high', 'medium', 'low'),
            }
        """
        all_detected = []
        methods = []
        cname_info = None

        # Method 1: IP range check
        if resolved_ips:
            for ip in resolved_ips:
                cdn = self.check_ip(ip)
                if cdn:
                    all_detected.append(cdn)
                    methods.append(f'ip_range:{ip}')

        # Method 2: ASN check
        if asn:
            cdn = self.check_asn(asn)
            if cdn:
                all_detected.append(cdn)
                methods.append(f'asn:{asn}')

        # Method 3: HTTP headers
        if response:
            header_cdns = self.check_headers(response)
            all_detected.extend(header_cdns)
            for h in header_cdns:
                methods.append(f'headers:{h}')

        # Method 4: CNAME chain
        cname_result = self.check_cname(hostname)
        if cname_result and cname_result.get('cdn_name'):
            all_detected.append(cname_result['cdn_name'])
            methods.append(f'cname:{cname_result["matched_cname"]}')
            cname_info = cname_result.get('cname_chain')

        # Deduplicate & determine primary CDN
        unique_cdns = list(dict.fromkeys(all_detected))  # preserves order, dedupes
        is_cdn = len(unique_cdns) > 0

        # Determine confidence
        if len(methods) >= 3:
            confidence = 'high'
        elif len(methods) == 2:
            confidence = 'high'
        elif len(methods) == 1:
            confidence = 'medium'
        else:
            confidence = 'low'

        return {
            'is_cdn': is_cdn,
            'cdn_name': unique_cdns[0] if unique_cdns else None,
            'all_detected': unique_cdns,
            'detection_methods': methods,
            'cname_chain': cname_info,
            'is_origin_ip': not is_cdn,
            'confidence': confidence,
        }

    def attempt_origin_discovery(self, hostname, session=None):
        """Attempt to discover the origin IP behind a CDN.

        Non-intrusive methods only:
          1. Check for direct-connect subdomains
          2. Check mail/MX records (mail servers often bypass CDN)
          3. Check historical DNS via SecurityTrails-style headers
          4. Check SPF record for ip4: directives
          5. Check for origin headers in response

        Returns:
            dict with 'possible_origins' list and 'methods_used'
        """
        origins = []
        methods_used = []

        # ── 1. Direct-connect subdomains ──
        direct_subs = [
            f'direct.{hostname}', f'origin.{hostname}', f'direct-connect.{hostname}',
            f'real.{hostname}', f'backend.{hostname}', f'origin-www.{hostname}',
            f'www2.{hostname}', f'server.{hostname}', f'host.{hostname}',
            f'webmail.{hostname}', f'mail.{hostname}', f'smtp.{hostname}',
            f'ftp.{hostname}', f'cpanel.{hostname}', f'webdisk.{hostname}',
            f'whm.{hostname}', f'autodiscover.{hostname}',
            f'staging.{hostname}', f'dev.{hostname}', f'test.{hostname}',
        ]
        for sub in direct_subs:
            try:
                ips = socket.getaddrinfo(sub, 80, socket.AF_INET)
                for _, _, _, _, addr in ips:
                    ip = addr[0]
                    if not self.check_ip(ip):
                        origins.append({
                            'ip': ip,
                            'source': f'subdomain:{sub}',
                            'confidence': 'medium',
                        })
                        methods_used.append(f'subdomain:{sub}')
            except (socket.gaierror, socket.timeout, OSError):
                continue

        # ── 2. MX records ──
        try:
            import dns.resolver
            try:
                mx_answers = dns.resolver.resolve(hostname, 'MX')
                for rdata in mx_answers:
                    mx_host = str(rdata.exchange).rstrip('.')
                    # Skip third-party mail (Google, Microsoft, etc.)
                    skip = ['google', 'outlook', 'microsoft', 'zoho',
                            'protonmail', 'mimecast', 'barracuda', 'pphosted']
                    if any(s in mx_host.lower() for s in skip):
                        continue
                    try:
                        mx_ips = socket.getaddrinfo(mx_host, 25, socket.AF_INET)
                        for _, _, _, _, addr in mx_ips:
                            ip = addr[0]
                            if not self.check_ip(ip):
                                origins.append({
                                    'ip': ip,
                                    'source': f'mx:{mx_host}',
                                    'confidence': 'low',
                                })
                                methods_used.append(f'mx:{mx_host}')
                    except Exception:
                        pass
            except Exception:
                pass
        except ImportError:
            pass

        # ── 3. SPF record for ip4: directives ──
        try:
            import dns.resolver
            try:
                txt_answers = dns.resolver.resolve(hostname, 'TXT')
                for rdata in txt_answers:
                    txt = str(rdata)
                    if 'v=spf1' in txt:
                        ip4_matches = re.findall(r'ip4:(\d+\.\d+\.\d+\.\d+(?:/\d+)?)', txt)
                        for ip_or_cidr in ip4_matches:
                            ip = ip_or_cidr.split('/')[0]
                            if not self.check_ip(ip):
                                origins.append({
                                    'ip': ip,
                                    'source': f'spf:ip4:{ip_or_cidr}',
                                    'confidence': 'medium',
                                })
                                methods_used.append(f'spf:{ip_or_cidr}')
            except Exception:
                pass
        except ImportError:
            pass

        # ── 4. Response header leaks ──
        if session:
            try:
                resp = session.get(f'https://{hostname}', timeout=self.timeout, verify=False)
                origin_headers = [
                    'x-origin-server', 'x-backend-server', 'x-real-ip',
                    'x-forwarded-server', 'x-upstream', 'x-host',
                    'x-server-addr', 'x-actual-server', 'x-backend-host',
                ]
                for hdr in origin_headers:
                    val = resp.headers.get(hdr, '')
                    if val:
                        ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', val)
                        if ip_match:
                            ip = ip_match.group(1)
                            if not self.check_ip(ip):
                                origins.append({
                                    'ip': ip,
                                    'source': f'header:{hdr}',
                                    'confidence': 'high',
                                })
                                methods_used.append(f'header:{hdr}')
            except Exception:
                pass

        # Deduplicate origins by IP
        seen_ips = set()
        unique_origins = []
        for o in origins:
            if o['ip'] not in seen_ips:
                seen_ips.add(o['ip'])
                unique_origins.append(o)

        return {
            'possible_origins': unique_origins,
            'methods_used': methods_used,
        }

    @staticmethod
    def get_cdn_note(cdn_name):
        """Return a human-readable note about what being behind this CDN means."""
        notes = {
            'Cloudflare': 'IPs belong to Cloudflare edge network. Origin server IP is hidden. '
                          'Port scans, geolocation, and ASN data reflect Cloudflare, not the origin.',
            'AWS CloudFront': 'IPs belong to Amazon CloudFront CDN. Origin may be EC2, S3, or external.',
            'Akamai': 'IPs belong to Akamai CDN edge. Origin infrastructure is proxied.',
            'Fastly': 'IPs belong to Fastly CDN. Origin is behind the Fastly edge.',
            'Sucuri': 'IPs belong to Sucuri WAF/CDN. Origin server is protected behind Sucuri.',
            'Incapsula/Imperva': 'IPs belong to Imperva/Incapsula WAF. Origin is proxied.',
            'Azure CDN': 'IPs belong to Microsoft Azure CDN. Origin may be Azure or external.',
            'Google Cloud CDN': 'IPs belong to Google Cloud infrastructure.',
        }
        return notes.get(cdn_name,
                         f'IPs belong to {cdn_name} CDN/proxy. Origin server IP is likely hidden.')