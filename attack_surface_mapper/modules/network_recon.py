"""
Network Reconnaissance Module - CDN-Aware
Handles IP resolution, ASN lookup, geolocation with proper CDN detection
to prevent false positives.
"""

import re
import json
import time
import socket
import logging
import subprocess
import requests
import urllib3
from urllib.parse import urlparse

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logger = logging.getLogger(__name__)

try:
    from cdn_detector import CDNDetector
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
    HAS_CDN_DETECTOR = True
except ImportError:
    HAS_CDN_DETECTOR = False
    logger.warning("cdn_detector not found — CDN detection disabled, expect false positives")


class NetworkRecon:
    def __init__(self, config=None):
        self.config = config if isinstance(config, dict) else {}
        self.timeout = self.config.get('REQUEST_TIMEOUT', 10)
        self.session = requests.Session()
        ua = self.config.get('USER_AGENT',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')
        self.session.headers.update({'User-Agent': ua})
        self.session.verify = False

        self.cdn_detector = CDNDetector(timeout=self.timeout) if HAS_CDN_DETECTOR else None
        self.findings = []
        self._findings_lock = threading.Lock()

    def run(self, target_domain, subdomains=None):
        """Main entry point."""
        self.findings = []
        target = target_domain.lower().strip().replace('https://', '').replace('http://', '').rstrip('/')

        print(f"\n{'='*60}")
        print(f"  NETWORK RECONNAISSANCE (CDN-Aware) - {target}")
        print(f"{'='*60}")

        # Build host list
        hosts = [target]
        if subdomains:
            for sub in subdomains[:50]:
                if isinstance(sub, dict):
                    sub = sub.get('subdomain', sub.get('domain', ''))
                if isinstance(sub, str) and sub.strip():
                    hosts.append(sub.strip().lower())

        results = {}
        with ThreadPoolExecutor(max_workers=10) as executor:
            future_to_host = {
                executor.submit(self._analyze_host, h): h for h in hosts
            }
            for future in as_completed(future_to_host):
                try:
                    result = future.result()
                    if result:
                        key = result.get('hostname', future_to_host[future])
                        results[key] = result
                except Exception as exc:
                    host = future_to_host[future]
                    pass  # Individual host failure, continue

        self._print_summary(results)
        return {
            'hosts': results,
            'findings': self.findings,
        }

    def _analyze_host(self, hostname):
        """Full analysis of a single host with CDN awareness."""
        print(f"\n  [*] Analyzing: {hostname}")

        result = {
            'hostname': hostname,
            'ips': [],
            'asn': None,
            'asn_org': None,
            'geo': None,
            'cdn': {
                'is_cdn': False,
                'cdn_name': None,
                'all_detected': [],
                'detection_methods': [],
                'is_origin_ip': True,
                'confidence': 'low',
                'note': None,
            },
            'origin_discovery': None,
            'reverse_dns': [],
        }

        # ── Step 1: Resolve IPs ──
        ips = self._resolve_ips(hostname)
        result['ips'] = ips
        if not ips:
            print(f"    [-] Could not resolve {hostname}")
            return result

        print(f"    [+] IPs: {', '.join(ips)}")

        # ── Step 2: ASN / Geo lookup ──
        primary_ip = ips[0]
        asn_info = self._lookup_asn(primary_ip)
        result['asn'] = asn_info.get('asn')
        result['asn_org'] = asn_info.get('org')
        result['geo'] = asn_info.get('geo')

        # ── Step 3: CDN Detection (BEFORE reporting infrastructure) ──
        if self.cdn_detector:
            # Get HTTP response for header-based detection
            http_resp = None
            try:
                http_resp = self.session.get(f'https://{hostname}',
                                             timeout=self.timeout, verify=False)
            except Exception:
                try:
                    http_resp = self.session.get(f'http://{hostname}',
                                                 timeout=self.timeout, verify=False)
                except Exception:
                    pass

            cdn_result = self.cdn_detector.full_detect(
                hostname=hostname,
                resolved_ips=ips,
                asn=asn_info.get('asn'),
                response=http_resp,
            )
            result['cdn'] = cdn_result

            if cdn_result['is_cdn']:
                cdn_name = cdn_result['cdn_name']
                cdn_note = CDNDetector.get_cdn_note(cdn_name)
                result['cdn']['note'] = cdn_note

                print(f"    [!] CDN DETECTED: {cdn_name} (confidence: {cdn_result['confidence']})")
                print(f"        Methods: {', '.join(cdn_result['detection_methods'])}")
                print(f"        Note: {cdn_note[:100]}")

                # Tag the IPs as CDN edge IPs
                for i, ip in enumerate(result['ips']):
                    result['ips'][i] = ip  # IPs stay the same but are flagged via cdn.is_cdn

                # ── Step 3b: Attempt origin discovery ──
                print(f"    [*] Attempting origin IP discovery...")
                origin_result = self.cdn_detector.attempt_origin_discovery(
                    hostname, session=self.session
                )
                result['origin_discovery'] = origin_result

                if origin_result['possible_origins']:
                    for origin in origin_result['possible_origins']:
                        print(f"    [+] Possible origin: {origin['ip']} "
                              f"(via {origin['source']}, confidence: {origin['confidence']})")
                        # Do ASN/geo on the origin IP
                        origin_asn = self._lookup_asn(origin['ip'])
                        origin['asn'] = origin_asn.get('asn')
                        origin['asn_org'] = origin_asn.get('org')
                        origin['geo'] = origin_asn.get('geo')

                    self.findings.append({
                        'type': 'Origin IP Discovered Behind CDN',
                        'severity': 'MEDIUM',
                        'host': hostname,
                        'detail': f'Origin IP(s) found behind {cdn_name}: '
                                  f'{", ".join(o["ip"] for o in origin_result["possible_origins"][:3])}',
                        'category': 'cdn_bypass',
                    })
                else:
                    print(f"    [-] No origin IPs discovered")

                # Add CDN finding
                self.findings.append({
                    'type': 'CDN/Proxy Detected',
                    'severity': 'INFO',
                    'host': hostname,
                    'detail': f'{hostname} is behind {cdn_name}. '
                              f'Resolved IPs ({", ".join(ips)}) are CDN edge IPs, '
                              f'not the origin server.',
                    'category': 'infrastructure',
                })

            else:
                print(f"    [+] No CDN detected — IPs likely belong to origin server")
                if asn_info.get('org'):
                    print(f"    [+] ASN: {asn_info['asn']} ({asn_info['org']})")
                if asn_info.get('geo'):
                    geo = asn_info['geo']
                    print(f"    [+] Geo: {geo.get('city', '?')}, "
                          f"{geo.get('region', '?')}, {geo.get('country', '?')}")
        else:
            # No CDN detector available — report raw data with warning
            print(f"    [!] CDN detection unavailable — results may contain false positives")
            if asn_info.get('org'):
                print(f"    [+] ASN: {asn_info['asn']} ({asn_info['org']})")

        # ── Step 4: Reverse DNS ──
        for ip in ips[:3]:
            rdns = self._reverse_dns(ip)
            if rdns:
                result['reverse_dns'].append({'ip': ip, 'hostname': rdns})
                print(f"    [+] rDNS: {ip} -> {rdns}")

        return result

    def _resolve_ips(self, hostname):
        """Resolve hostname to IPv4 addresses."""
        ips = []
        try:
            results = socket.getaddrinfo(hostname, None, socket.AF_INET)
            for _, _, _, _, addr in results:
                ip = addr[0]
                if ip not in ips:
                    ips.append(ip)
        except (socket.gaierror, socket.timeout):
            pass
        return ips

    def _lookup_asn(self, ip):
        """Lookup ASN, org, and geo for an IP."""
        result = {'asn': None, 'org': None, 'geo': None}

        # Try ip-api.com (free, no key needed)
        try:
            resp = self.session.get(
                f'http://ip-api.com/json/{ip}?fields=status,message,country,'
                f'regionName,city,lat,lon,isp,org,as,query',
                timeout=self.timeout
            )
            if resp.status_code == 200:
                data = resp.json()
                if data.get('status') == 'success':
                    as_field = data.get('as', '')
                    asn_match = re.match(r'(AS\d+)', as_field)
                    result['asn'] = asn_match.group(1) if asn_match else as_field
                    result['org'] = data.get('org') or data.get('isp', '')
                    result['geo'] = {
                        'country': data.get('country'),
                        'region': data.get('regionName'),
                        'city': data.get('city'),
                        'lat': data.get('lat'),
                        'lon': data.get('lon'),
                    }
                    return result
        except Exception:
            pass

        # Fallback: ipinfo.io
        try:
            resp = self.session.get(f'https://ipinfo.io/{ip}/json', timeout=self.timeout)
            if resp.status_code == 200:
                data = resp.json()
                org = data.get('org', '')
                asn_match = re.match(r'(AS\d+)', org)
                result['asn'] = asn_match.group(1) if asn_match else None
                result['org'] = org
                loc = data.get('loc', '')
                parts = loc.split(',') if loc else []
                result['geo'] = {
                    'country': data.get('country'),
                    'region': data.get('region'),
                    'city': data.get('city'),
                    'lat': float(parts[0]) if len(parts) >= 2 else None,
                    'lon': float(parts[1]) if len(parts) >= 2 else None,
                }
                return result
        except Exception:
            pass

        # Fallback: whois via subprocess
        try:
            r = subprocess.run(['whois', ip], capture_output=True, text=True, timeout=10)
            if r.returncode == 0:
                for line in r.stdout.split('\n'):
                    if 'OriginAS:' in line or 'origin:' in line.lower():
                        asn_match = re.search(r'(AS\d+)', line)
                        if asn_match:
                            result['asn'] = asn_match.group(1)
                    if 'OrgName:' in line or 'org-name:' in line.lower():
                        result['org'] = line.split(':', 1)[1].strip()
        except Exception:
            pass

        return result

    def _reverse_dns(self, ip):
        """Reverse DNS lookup."""
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            return hostname
        except (socket.herror, socket.gaierror, socket.timeout):
            return None

    def _print_summary(self, results):
        """Print a CDN-aware summary."""
        print(f"\n{'='*60}")
        print(f"  NETWORK RECON SUMMARY")
        print(f"{'='*60}")

        cdn_hosts = []
        direct_hosts = []

        for host, data in results.items():
            if data['cdn']['is_cdn']:
                cdn_hosts.append((host, data))
            else:
                direct_hosts.append((host, data))

        if cdn_hosts:
            print(f"\n  ── CDN-Fronted Hosts ({len(cdn_hosts)}) ──")
            print(f"  NOTE: IPs below are CDN edge IPs, NOT origin servers.\n")
            for host, data in cdn_hosts:
                cdn = data['cdn']
                print(f"    {host}")
                print(f"      CDN: {cdn['cdn_name']} (confidence: {cdn['confidence']})")
                print(f"      Edge IPs: {', '.join(data['ips'])}")
                if data.get('origin_discovery', {}).get('possible_origins'):
                    origins = data['origin_discovery']['possible_origins']
                    for o in origins[:3]:
                        org_str = f" ({o.get('asn_org', 'unknown')})" if o.get('asn_org') else ''
                        print(f"      Possible Origin: {o['ip']}{org_str} "
                              f"[via {o['source']}, {o['confidence']}]")
                else:
                    print(f"      Origin: Not discovered")

        if direct_hosts:
            print(f"\n  ── Direct Hosts ({len(direct_hosts)}) ──\n")
            for host, data in direct_hosts:
                ip_str = ', '.join(data['ips']) if data['ips'] else 'unresolved'
                org = data.get('asn_org', '')
                asn = data.get('asn', '')
                geo = data.get('geo', {}) or {}
                loc = f"{geo.get('city', '?')}, {geo.get('country', '?')}" if geo else '?'
                print(f"    {host}")
                print(f"      IP: {ip_str}  ASN: {asn} ({org})  Geo: {loc}")

        if self.findings:
            print(f"\n  ── Findings ({len(self.findings)}) ──")
            for f in self.findings:
                print(f"    [{f['severity']}] {f['type']}: {f['detail'][:100]}")

        print(f"\n{'='*60}\n")