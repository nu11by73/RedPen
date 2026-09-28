#!/usr/bin/env python3

import argparse
import asyncio
import ipaddress
import json
import socket
import ssl
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import quote

import httpx
from ipwhois import IPWhois


DEFAULT_PORTS = [80, 443, 3000, 3001, 8000, 8080, 8443]
DEFAULT_PATHS = [
    "/mcp",
    "/sse",
    "/mcp/sse",
    "/api/mcp",
    "/.well-known/mcp",
]

INITIALIZE_REQUEST = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": "2025-06-18",
        "capabilities": {},
        "clientInfo": {
            "name": "authorized-perimeter-mcp-scanner",
            "version": "1.0",
        },
    },
}

MAX_RESPONSE_BYTES = 32 * 1024


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def clean_domain(value: str) -> str:
    value = value.strip().lower().rstrip(".")

    if "://" in value or "/" in value:
        raise ValueError(
            f"Expected a DNS domain, not a URL: {value!r}"
        )

    if not value or len(value) > 253:
        raise ValueError(f"Invalid domain: {value!r}")

    return value


def resolve_domain(domain: str) -> list[str]:
    addresses: set[str] = set()

    try:
        results = socket.getaddrinfo(
            domain,
            None,
            family=socket.AF_UNSPEC,
            type=socket.SOCK_STREAM,
        )
    except socket.gaierror as exc:
        print(
            f"[!] DNS resolution failed for {domain}: {exc}",
            file=sys.stderr,
        )
        return []

    for result in results:
        address = result[4][0]

        try:
            parsed = ipaddress.ip_address(address)
        except ValueError:
            continue

        if parsed.is_global:
            addresses.add(str(parsed))

    return sorted(
        addresses,
        key=lambda item: (
            ipaddress.ip_address(item).version,
            int(ipaddress.ip_address(item)),
        ),
    )


def rdap_lookup(address: str) -> dict[str, Any]:
    record: dict[str, Any] = {
        "address": address,
        "lookup_succeeded": False,
        "candidate_prefixes": [],
    }

    try:
        result = IPWhois(address).lookup_rdap(depth=1)
    except Exception as exc:
        record["error"] = type(exc).__name__
        return record

    record["lookup_succeeded"] = True
    record["asn"] = result.get("asn")
    record["asn_description"] = result.get("asn_description")
    record["asn_country_code"] = result.get("asn_country_code")

    network = result.get("network") or {}
    record["network_name"] = network.get("name")
    record["network_handle"] = network.get("handle")
    record["network_country"] = network.get("country")
    record["network_cidr"] = network.get("cidr")

    candidates: set[str] = set()

    asn_cidr = result.get("asn_cidr")
    if isinstance(asn_cidr, str):
        for value in asn_cidr.split(","):
            value = value.strip()
            try:
                candidates.add(
                    str(ipaddress.ip_network(value, strict=False))
                )
            except ValueError:
                pass

    network_cidr = network.get("cidr")
    if isinstance(network_cidr, str):
        for value in network_cidr.split(","):
            value = value.strip()
            try:
                candidates.add(
                    str(ipaddress.ip_network(value, strict=False))
                )
            except ValueError:
                pass

    record["candidate_prefixes"] = sorted(candidates)
    return record


def discover_command(args: argparse.Namespace) -> int:
    domains = [clean_domain(value) for value in args.domain]

    report: dict[str, Any] = {
        "generated_at": utc_now(),
        "domains": [],
        "unique_addresses": [],
        "candidate_prefixes": [],
        "warning": (
            "Candidate prefixes are derived from DNS and RDAP. They may "
            "belong to a CDN, hosting provider, or shared cloud platform. "
            "Approve only networks your organization owns or is authorized "
            "to test."
        ),
    }

    all_addresses: set[str] = set()

    for domain in domains:
        addresses = resolve_domain(domain)
        all_addresses.update(addresses)

        report["domains"].append({
            "domain": domain,
            "addresses": addresses,
        })

    rdap_records = []

    for address in sorted(all_addresses):
        print(f"[*] RDAP lookup: {address}", file=sys.stderr)
        rdap_records.append(rdap_lookup(address))

    candidate_prefixes: set[str] = set()

    for record in rdap_records:
        candidate_prefixes.update(record.get("candidate_prefixes", []))

    report["unique_addresses"] = sorted(all_addresses)
    report["rdap"] = rdap_records
    report["candidate_prefixes"] = sorted(candidate_prefixes)

    rendered = json.dumps(report, indent=2)

    if args.output:
        Path(args.output).write_text(rendered + "\n", encoding="utf-8")
        print(f"[*] Wrote {args.output}", file=sys.stderr)
    else:
        print(rendered)

    if args.approval_template:
        lines = [
            "# Review every CIDR before removing the leading '#'.",
            "# Approve only company-owned or explicitly authorized ranges.",
            "",
        ]

        for prefix in sorted(candidate_prefixes):
            lines.append(f"# {prefix}")

        Path(args.approval_template).write_text(
            "\n".join(lines) + "\n",
            encoding="utf-8",
        )
        print(
            f"[*] Wrote approval template: {args.approval_template}",
            file=sys.stderr,
        )

    return 0


def read_cidrs(filename: str) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    networks = []

    for line_number, raw_line in enumerate(
        Path(filename).read_text(encoding="utf-8").splitlines(),
        start=1,
    ):
        line = raw_line.split("#", 1)[0].strip()

        if not line:
            continue

        try:
            network = ipaddress.ip_network(line, strict=False)
        except ValueError as exc:
            raise ValueError(
                f"{filename}:{line_number}: invalid CIDR {line!r}"
            ) from exc

        networks.append(network)

    return list(ipaddress.collapse_addresses(networks))


def usable_address_count(
    network: ipaddress.IPv4Network | ipaddress.IPv6Network,
) -> int:
    if network.version == 4 and network.prefixlen <= 30:
        return max(0, network.num_addresses - 2)

    return network.num_addresses


def enumerate_addresses(
    networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network],
    maximum: int,
) -> list[str]:
    total = sum(usable_address_count(network) for network in networks)

    if total > maximum:
        raise ValueError(
            f"Approved networks contain approximately {total:,} usable "
            f"addresses, exceeding --max-hosts={maximum:,}. Split the scan "
            "or deliberately raise the limit."
        )

    addresses: list[str] = []

    for network in networks:
        if network.version == 4 and network.prefixlen <= 30:
            iterator = network.hosts()
        else:
            iterator = iter(network)

        addresses.extend(str(address) for address in iterator)

    return addresses


def parse_integer_list(value: str, minimum: int, maximum: int) -> list[int]:
    results: set[int] = set()

    for item in value.split(","):
        item = item.strip()

        if not item:
            continue

        try:
            number = int(item)
        except ValueError as exc:
            raise ValueError(f"Invalid integer: {item!r}") from exc

        if not minimum <= number <= maximum:
            raise ValueError(
                f"Value {number} is outside {minimum}–{maximum}"
            )

        results.add(number)

    if not results:
        raise ValueError("At least one value is required")

    return sorted(results)


def parse_paths(value: str) -> list[str]:
    paths: set[str] = set()

    for item in value.split(","):
        item = item.strip()

        if not item:
            continue

        if not item.startswith("/"):
            item = "/" + item

        paths.add(item)

    if not paths:
        raise ValueError("At least one endpoint path is required")

    return sorted(paths)


def host_for_url(target: str) -> str:
    try:
        address = ipaddress.ip_address(target)
        if address.version == 6:
            return f"[{address}]"
    except ValueError:
        pass

    return target


def scheme_for_port(port: int) -> str:
    if port in {443, 8443, 9443}:
        return "https"

    return "http"


def make_url(target: str, port: int, path: str) -> str:
    scheme = scheme_for_port(port)
    host = host_for_url(target)
    encoded_path = quote(path, safe="/%:@-._~")

    return f"{scheme}://{host}:{port}{encoded_path}"


def classify_response(
    status: int,
    headers: dict[str, str],
    body: bytes,
    method: str,
    path: str,
) -> tuple[str | None, list[str]]:
    reasons: list[str] = []
    score = 0

    content_type = headers.get("content-type", "").lower()
    lowered_headers = {key.lower(): value for key, value in headers.items()}

    text = body.decode("utf-8", errors="replace")
    lowered_text = text.lower()

    if "mcp-session-id" in lowered_headers:
        score += 5
        reasons.append("MCP-Session-Id response header")

    if "text/event-stream" in content_type:
        score += 3
        reasons.append("SSE response content type")

    parsed = None

    try:
        parsed = json.loads(text) if text.strip() else None
    except ValueError:
        parsed = None

    if isinstance(parsed, dict):
        result = parsed.get("result")
        error = parsed.get("error")

        if parsed.get("jsonrpc") == "2.0":
            score += 1
            reasons.append("JSON-RPC 2.0 response")

        if isinstance(result, dict):
            if "protocolVersion" in result:
                score += 5
                reasons.append("MCP protocolVersion in result")

            if "serverInfo" in result:
                score += 5
                reasons.append("MCP serverInfo in result")

            if "capabilities" in result:
                score += 2
                reasons.append("capabilities in initialize result")

        if isinstance(error, dict):
            message = str(error.get("message", "")).lower()

            if "initialize" in message:
                score += 2
                reasons.append("JSON-RPC error references initialize")

            if "mcp" in message:
                score += 3
                reasons.append("JSON-RPC error references MCP")

    textual_markers = [
        "model context protocol",
        "mcp-session-id",
        '"protocolversion"',
        '"serverinfo"',
    ]

    if any(marker in lowered_text for marker in textual_markers):
        score += 3
        reasons.append("MCP marker in response body")

    if path.endswith("/sse") and "text/event-stream" in content_type:
        score += 2
        reasons.append("SSE content on an MCP-associated path")

    if method == "POST" and status in {200, 201, 202}:
        if "application/json" in content_type:
            score += 1

    if score >= 7:
        return "high", reasons

    if score >= 4:
        return "medium", reasons

    if score >= 2:
        return "low", reasons

    return None, reasons


async def read_limited_response(
    response: httpx.Response,
    limit: int,
    read_timeout: float,
) -> bytes:
    content_type = response.headers.get("content-type", "").lower()

    # An SSE connection can intentionally remain open indefinitely. Its
    # headers are sufficient for initial classification.
    if "text/event-stream" in content_type:
        return b""

    collected = bytearray()

    async def consume() -> None:
        async for chunk in response.aiter_bytes():
            remaining = limit - len(collected)

            if remaining <= 0:
                break

            collected.extend(chunk[:remaining])

            if len(collected) >= limit:
                break

    try:
        await asyncio.wait_for(consume(), timeout=read_timeout)
    except (asyncio.TimeoutError, httpx.HTTPError):
        pass

    return bytes(collected)


async def one_request(
    client: httpx.AsyncClient,
    semaphore: asyncio.Semaphore,
    target: str,
    port: int,
    path: str,
    method: str,
    timeout: float,
    host_header: str | None,
) -> dict[str, Any] | None:
    url = make_url(target, port, path)

    headers = {
        "Accept": "application/json, text/event-stream",
        "User-Agent": "authorized-mcp-perimeter-scanner/1.0",
    }

    if host_header:
        headers["Host"] = host_header

    request_kwargs: dict[str, Any] = {
        "headers": headers,
        "timeout": httpx.Timeout(
            connect=min(timeout, 3.0),
            read=timeout,
            write=timeout,
            pool=timeout,
        ),
    }

    if method == "POST":
        request_kwargs["json"] = INITIALIZE_REQUEST
        headers["Content-Type"] = "application/json"

    async with semaphore:
        try:
            request = client.build_request(
                method,
                url,
                **request_kwargs,
            )

            response = await client.send(
                request,
                stream=True,
                follow_redirects=False,
            )

            try:
                body = await read_limited_response(
                    response,
                    MAX_RESPONSE_BYTES,
                    timeout,
                )

                response_headers = {
                    key.lower(): value
                    for key, value in response.headers.items()
                }

                confidence, reasons = classify_response(
                    response.status_code,
                    response_headers,
                    body,
                    method,
                    path,
                )

                if not confidence:
                    return None

                snippet = body.decode(
                    "utf-8",
                    errors="replace",
                )[:500]

                return {
                    "timestamp": utc_now(),
                    "target": target,
                    "virtual_host": host_header,
                    "port": port,
                    "scheme": scheme_for_port(port),
                    "path": path,
                    "method": method,
                    "status": response.status_code,
                    "confidence": confidence,
                    "reasons": reasons,
                    "server_header": response_headers.get("server"),
                    "content_type": response_headers.get("content-type"),
                    "mcp_session_id_present": (
                        "mcp-session-id" in response_headers
                    ),
                    "location": response_headers.get("location"),
                    "response_snippet": snippet,
                }
            finally:
                await response.aclose()

        except (
            httpx.ConnectError,
            httpx.ConnectTimeout,
            httpx.ReadTimeout,
            httpx.RemoteProtocolError,
            ssl.SSLError,
        ):
            return None
        except httpx.HTTPError:
            return None


async def probe_endpoint(
    client: httpx.AsyncClient,
    semaphore: asyncio.Semaphore,
    target: str,
    port: int,
    path: str,
    timeout: float,
    host_header: str | None,
) -> list[dict[str, Any]]:
    results = []

    # GET detects SSE endpoints and exposed metadata.
    get_result = await one_request(
        client=client,
        semaphore=semaphore,
        target=target,
        port=port,
        path=path,
        method="GET",
        timeout=timeout,
        host_header=host_header,
    )

    if get_result:
        results.append(get_result)

    # POST performs the normal MCP initialize handshake. It does not invoke
    # tools or resources.
    post_result = await one_request(
        client=client,
        semaphore=semaphore,
        target=target,
        port=port,
        path=path,
        method="POST",
        timeout=timeout,
        host_header=host_header,
    )

    if post_result:
        results.append(post_result)

    return results


def finding_key(finding: dict[str, Any]) -> tuple[Any, ...]:
    return (
        finding.get("target"),
        finding.get("virtual_host"),
        finding.get("port"),
        finding.get("path"),
        finding.get("method"),
        finding.get("status"),
    )


async def scan_async(args: argparse.Namespace) -> dict[str, Any]:
    ports = parse_integer_list(args.ports, 1, 65535)
    paths = parse_paths(args.paths)

    networks = read_cidrs(args.cidr_file) if args.cidr_file else []
    addresses = enumerate_addresses(networks, args.max_hosts)

    hostnames = sorted({
        clean_domain(hostname)
        for hostname in (args.hostname or [])
    })

    if not addresses and not hostnames:
        raise ValueError(
            "Supply --cidr-file, at least one --hostname, or both"
        )

    tasks = []
    semaphore = asyncio.Semaphore(args.concurrency)

    limits = httpx.Limits(
        max_connections=args.concurrency,
        max_keepalive_connections=min(args.concurrency, 50),
        keepalive_expiry=2.0,
    )

    async with httpx.AsyncClient(
        verify=False,
        trust_env=False,
        limits=limits,
    ) as client:
        # Direct IP scans find services that do not require virtual hosting.
        for address in addresses:
            for port in ports:
                for path in paths:
                    tasks.append(
                        asyncio.create_task(
                            probe_endpoint(
                                client,
                                semaphore,
                                address,
                                port,
                                path,
                                args.timeout,
                                None,
                            )
                        )
                    )

        # DNS-name scans preserve TLS SNI and the HTTP Host header.
        for hostname in hostnames:
            for port in ports:
                for path in paths:
                    tasks.append(
                        asyncio.create_task(
                            probe_endpoint(
                                client,
                                semaphore,
                                hostname,
                                port,
                                path,
                                args.timeout,
                                hostname,
                            )
                        )
                    )

        findings: list[dict[str, Any]] = []
        completed = 0

        for future in asyncio.as_completed(tasks):
            completed += 1
            batch = await future

            for finding in batch:
                findings.append(finding)
                print(
                    "[+] "
                    f"{finding['confidence'].upper()} "
                    f"{finding['method']} "
                    f"{finding['scheme']}://"
                    f"{finding['target']}:{finding['port']}"
                    f"{finding['path']}",
                    file=sys.stderr,
                )

            if completed % 500 == 0:
                print(
                    f"[*] Completed {completed:,}/{len(tasks):,} "
                    "endpoint probes",
                    file=sys.stderr,
                )

    unique = {
        finding_key(finding): finding
        for finding in findings
    }

    confidence_order = {
        "high": 0,
        "medium": 1,
        "low": 2,
    }

    sorted_findings = sorted(
        unique.values(),
        key=lambda item: (
            confidence_order.get(item["confidence"], 9),
            item["target"],
            item["port"],
            item["path"],
            item["method"],
        ),
    )

    return {
        "generated_at": utc_now(),
        "approved_networks": [str(network) for network in networks],
        "address_count": len(addresses),
        "hostnames": hostnames,
        "ports": ports,
        "paths": paths,
        "initialize_protocol_version": (
            INITIALIZE_REQUEST["params"]["protocolVersion"]
        ),
        "findings": sorted_findings,
        "notes": [
            "Only HTTP-based MCP transports can be detected.",
            "Unknown custom paths and unscanned ports will not be found.",
            "Low-confidence findings require manual validation.",
            "The initialize request does not invoke MCP tools or resources.",
        ],
    }


def scan_command(args: argparse.Namespace) -> int:
    try:
        report = asyncio.run(scan_async(args))
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted", file=sys.stderr)
        return 130

    rendered = json.dumps(report, indent=2)

    if args.output:
        Path(args.output).write_text(rendered + "\n", encoding="utf-8")
        print(f"[*] Wrote {args.output}", file=sys.stderr)
    else:
        print(rendered)

    print(
        f"[*] Findings: {len(report['findings'])}",
        file=sys.stderr,
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Discover candidate perimeter ranges and scan approved networks "
            "for HTTP-based MCP servers"
        )
    )

    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
    )

    discover = subparsers.add_parser(
        "discover",
        help="Resolve domains and obtain candidate RDAP prefixes",
    )
    discover.add_argument(
        "--domain",
        action="append",
        required=True,
        help="Company domain; may be supplied multiple times",
    )
    discover.add_argument(
        "--output",
        "-o",
        help="Write discovery JSON to this file",
    )
    discover.add_argument(
        "--approval-template",
        help="Write a commented CIDR approval template",
    )
    discover.set_defaults(handler=discover_command)

    scan = subparsers.add_parser(
        "scan",
        help="Scan explicitly approved CIDRs and DNS names",
    )
    scan.add_argument(
        "--cidr-file",
        help="Text file containing one approved CIDR per line",
    )
    scan.add_argument(
        "--hostname",
        action="append",
        help="DNS hostname to scan with correct Host/SNI handling",
    )
    scan.add_argument(
        "--ports",
        default=",".join(str(port) for port in DEFAULT_PORTS),
        help="Comma-separated TCP ports",
    )
    scan.add_argument(
        "--paths",
        default=",".join(DEFAULT_PATHS),
        help="Comma-separated HTTP endpoint paths",
    )
    scan.add_argument(
        "--concurrency",
        type=int,
        default=100,
        help="Maximum concurrent HTTP requests",
    )
    scan.add_argument(
        "--timeout",
        type=float,
        default=4.0,
        help="Per-request timeout in seconds",
    )
    scan.add_argument(
        "--max-hosts",
        type=int,
        default=4096,
        help="Refuse to enumerate more than this many IP addresses",
    )
    scan.add_argument(
        "--output",
        "-o",
        help="Write scan JSON to this file",
    )
    scan.set_defaults(handler=scan_command)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if getattr(args, "concurrency", 1) <= 0:
        parser.error("--concurrency must be positive")

    if getattr(args, "timeout", 1) <= 0:
        parser.error("--timeout must be positive")

    if getattr(args, "max_hosts", 1) <= 0:
        parser.error("--max-hosts must be positive")

    try:
        return args.handler(args)
    except (ValueError, OSError) as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
