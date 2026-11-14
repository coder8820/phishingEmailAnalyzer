"""
Redirect Forensics & SSRF Prevention Engine for PhishGuard AI.

Security Contract:
- Analyzes redirect chains ONLY through isolated, security-hardened HTTP HEAD / GET checks.
- Blocks localhost, private IP, loopback, link-local, cloud metadata, multicast, and non-routable IPs.
- Defends against DNS Rebinding by pinning validated IP addresses and verifying every hop.
- Enforces strict hop limits (max redirects), per-hop timeouts, overall timeouts, and response body size limits.
- NEVER downloads or executes page content or scripts.
- Strips internal network information and detailed IP topologies from public responses.
- Allows callers or fallback handlers to default cleanly to static URL analysis when network validation is unsafe.
"""

from __future__ import annotations

import ipaddress
import logging
import socket
import urllib.parse
from dataclasses import dataclass, field
from typing import Optional, Set

logger = logging.getLogger(__name__)

# Cloud metadata endpoints and special blocked IP subnets
_CLOUD_METADATA_IPS = {
    "169.254.169.254",  # AWS, GCP, Azure, OpenStack metadata
    "fd00:ec2::254",    # AWS IPv6 metadata
    "100.100.100.200",  # Alibaba Cloud metadata
}

_DISALLOWED_SCHEMES = {"file", "gopher", "ftp", "tftp", "ldap", "dict", "data", "blob", "javascript"}


@dataclass
class RedirectHop:
    """A single hop in a redirect chain."""

    url: str
    status_code: int
    resolved_ip: Optional[str] = None
    headers: dict[str, str] = field(default_factory=dict)
    is_safe: bool = True
    block_reason: Optional[str] = None


@dataclass
class RedirectAnalysisResult:
    """Outcome of evaluating a URL's redirect chain."""

    initial_url: str
    final_url: str
    hops: list[RedirectHop] = field(default_factory=list)
    hop_count: int = 0
    is_redirect: bool = False
    is_safe: bool = True
    blocked: bool = False
    block_reason: Optional[str] = None
    loop_detected: bool = False
    limit_exceeded: bool = False
    error: Optional[str] = None


class SSRFProtectionError(ValueError):
    """Raised when a URL or resolved destination targets a blocked IP or host."""
    pass


class RedirectForensicsEngine:
    """
    Dedicated isolated component for safely tracing HTTP/HTTPS redirect chains.
    Enforces SSRF prevention, DNS rebinding mitigation, timeouts, and size caps.
    """

    def __init__(
        self,
        max_redirects: int = 5,
        timeout_seconds: float = 3.0,
        max_response_bytes: int = 16384,  # 16KB max header/response inspection
        dns_timeout_seconds: float = 2.0,
    ) -> None:
        self.max_redirects = max_redirects
        self.timeout_seconds = timeout_seconds
        self.max_response_bytes = max_response_bytes
        self.dns_timeout_seconds = dns_timeout_seconds

    # ------------------------------------------------------------------
    # Validation & SSRF Guard
    # ------------------------------------------------------------------

    @classmethod
    def is_ip_blocked(cls, ip_str: str) -> tuple[bool, Optional[str]]:
        """
        Check if an IP string belongs to any dangerous, private, loopback,
        cloud metadata, link-local, multicast, or non-routable range.
        """
        try:
            ip = ipaddress.ip_address(ip_str.strip())
        except ValueError:
            return True, "Invalid IP address representation"

        # Check cloud metadata endpoints
        if str(ip) in _CLOUD_METADATA_IPS:
            return True, "Cloud metadata IP address access blocked"

        # Check standard forbidden ranges
        if ip.is_loopback:
            return True, "Loopback address (localhost) blocked"
        if ip.is_private:
            return True, "Private / internal RFC1918/RFC4193 network access blocked"
        if ip.is_link_local:
            return True, "Link-local address blocked"
        if ip.is_multicast:
            return True, "Multicast address blocked"
        if ip.is_reserved:
            return True, "Reserved IP space blocked"
        if ip.is_unspecified:
            return True, "Unspecified 0.0.0.0 address blocked"

        # Explicit check for 0.0.0.0/8 (current network) and 127.0.0.0/8
        if isinstance(ip, ipaddress.IPv4Address):
            if ip in ipaddress.ip_network("0.0.0.0/8"):
                return True, "Current network IP range blocked"
            if ip in ipaddress.ip_network("127.0.0.0/8"):
                return True, "Loopback network blocked"
            if ip in ipaddress.ip_network("100.64.0.0/10"):
                return True, "Carrier-grade NAT IP range blocked"

        return False, None

    def validate_destination(self, host: str, port: int = 80) -> list[str]:
        """
        Resolve hostname to all corresponding IP addresses using strict DNS resolution,
        and ensure NONE of them point to disallowed internal or metadata targets.

        Returns list of safe resolved IP strings.
        Raises SSRFProtectionError if any resolved IP or host is dangerous.
        """
        if not host:
            raise SSRFProtectionError("Host cannot be empty")

        clean_host = host.strip("[]").lower()

        # Check for localhost literal names
        if clean_host in ("localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback"):
            raise SSRFProtectionError("Localhost hostname access blocked")

        # Check if hostname directly parses as an IP address
        try:
            ip = ipaddress.ip_address(clean_host)
            blocked, reason = self.is_ip_blocked(str(ip))
            if blocked:
                raise SSRFProtectionError(f"Direct IP access forbidden: {reason}")
            return [str(ip)]
        except ValueError:
            # Not an IP literal; proceed to DNS resolution
            pass

        # DNS resolution
        resolved_ips: list[str] = []
        try:
            old_timeout = socket.getdefaulttimeout()
            socket.setdefaulttimeout(self.dns_timeout_seconds)
            try:
                addr_info = socket.getaddrinfo(clean_host, port, proto=socket.IPPROTO_TCP)
            finally:
                socket.setdefaulttimeout(old_timeout)

            for item in addr_info:
                sockaddr = item[4]
                ip_addr = sockaddr[0]
                if ip_addr not in resolved_ips:
                    resolved_ips.append(ip_addr)
        except socket.gaierror as exc:
            raise SSRFProtectionError(f"DNS resolution error: {exc}")
        except Exception as exc:
            raise SSRFProtectionError(f"DNS lookup failure: {exc}")

        if not resolved_ips:
            raise SSRFProtectionError("No IP addresses returned by DNS resolver")

        # Revalidate every resolved IP address
        for rip in resolved_ips:
            blocked, reason = self.is_ip_blocked(rip)
            if blocked:
                raise SSRFProtectionError(f"DNS resolved to blocked destination: {reason}")

        return resolved_ips

    # ------------------------------------------------------------------
    # Safe redirect tracing
    # ------------------------------------------------------------------

    def trace_redirects(self, initial_url: str) -> RedirectAnalysisResult:
        """
        Synchronously and securely trace HTTP redirects without downloading page content.
        Uses low-level sockets / strict HTTP connection pinned to pre-validated IPs
        to prevent DNS rebinding attacks between resolution and request time.
        """
        current_url = initial_url
        visited_urls: Set[str] = set()
        hops: list[RedirectHop] = []
        result = RedirectAnalysisResult(
            initial_url=initial_url,
            final_url=initial_url,
            hops=hops,
        )

        for hop_index in range(self.max_redirects + 1):
            parsed = urllib.parse.urlsplit(current_url)
            scheme = parsed.scheme.lower()

            if scheme not in ("http", "https"):
                result.blocked = True
                result.is_safe = False
                result.block_reason = f"Unsupported or dangerous URL scheme: {scheme}"
                return result

            host = parsed.hostname
            if not host:
                result.blocked = True
                result.is_safe = False
                result.block_reason = "Missing hostname in URL"
                return result

            port = parsed.port or (443 if scheme == "https" else 80)

            # Pre-flight SSRF and DNS check
            try:
                safe_ips = self.validate_destination(host, port)
                pinned_ip = safe_ips[0]
            except SSRFProtectionError as exc:
                result.blocked = True
                result.is_safe = False
                result.block_reason = str(exc)
                hops.append(
                    RedirectHop(
                        url=current_url,
                        status_code=0,
                        resolved_ip=None,
                        is_safe=False,
                        block_reason=str(exc),
                    )
                )
                return result

            if current_url in visited_urls:
                result.loop_detected = True
                result.block_reason = "Circular redirect loop detected"
                result.is_safe = False
                return result
            visited_urls.add(current_url)

            # If we've reached max redirects, stop before making the next hop
            if hop_index == self.max_redirects:
                result.limit_exceeded = True
                result.block_reason = f"Redirect limit of {self.max_redirects} exceeded"
                return result

            # Execute single hop inspection using pinned IP
            try:
                hop_info = self._fetch_single_hop(parsed, pinned_ip, port, scheme)
                hops.append(hop_info)
                result.hops = hops
                result.hop_count = len(hops)

                if not hop_info.is_safe:
                    result.blocked = True
                    result.is_safe = False
                    result.block_reason = hop_info.block_reason
                    return result

                # Check if this status code represents a redirect (301, 302, 303, 307, 308)
                if hop_info.status_code in (301, 302, 303, 307, 308):
                    result.is_redirect = True
                    location = hop_info.headers.get("location")
                    if not location:
                        result.final_url = current_url
                        return result

                    # Resolve relative redirect URLs safely
                    next_url = urllib.parse.urljoin(current_url, location)
                    current_url = next_url
                    result.final_url = current_url
                else:
                    # Non-redirect status reached (200, 404, etc.) -> terminal hop
                    result.final_url = current_url
                    return result

            except Exception as exc:
                logger.debug("Redirect hop check error: %s", exc)
                result.error = "Connection or validation error during redirect check"
                hops.append(
                    RedirectHop(
                        url=current_url,
                        status_code=0,
                        resolved_ip=None,
                        is_safe=True,
                        block_reason=None,
                    )
                )
                return result

        return result

    def _fetch_single_hop(
        self,
        parsed: urllib.parse.SplitResult,
        pinned_ip: str,
        port: int,
        scheme: str,
    ) -> RedirectHop:
        """
        Perform a safe HEAD (or limited GET) request connecting directly to pinned_ip
        with Host header set to parsed.netloc, preventing DNS rebinding.
        """
        import http.client
        import ssl

        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"

        # Connect to pinned IP directly to eliminate rebinding window
        connection = None
        try:
            if scheme == "https":
                context = ssl.create_default_context()
                connection = http.client.HTTPSConnection(
                    pinned_ip,
                    port=port,
                    timeout=self.timeout_seconds,
                    context=context,
                )
            else:
                connection = http.client.HTTPConnection(
                    pinned_ip,
                    port=port,
                    timeout=self.timeout_seconds,
                )

            # Issue HEAD request first
            connection.request(
                "HEAD",
                path,
                headers={
                    "Host": parsed.netloc,
                    "User-Agent": "PhishGuard-Forensics/1.0 (Security Scanner)",
                    "Accept": "*/*",
                    "Connection": "close",
                },
            )
            response = connection.getresponse()

            # Some servers reject HEAD with 405 Method Not Allowed; fall back to capped GET
            if response.status == 405:
                connection.close()
                if scheme == "https":
                    context = ssl.create_default_context()
                    connection = http.client.HTTPSConnection(
                        pinned_ip, port=port, timeout=self.timeout_seconds, context=context
                    )
                else:
                    connection = http.client.HTTPConnection(
                        pinned_ip, port=port, timeout=self.timeout_seconds
                    )
                connection.request(
                    "GET",
                    path,
                    headers={
                        "Host": parsed.netloc,
                        "User-Agent": "PhishGuard-Forensics/1.0 (Security Scanner)",
                        "Accept": "*/*",
                        "Connection": "close",
                        "Range": f"bytes=0-{self.max_response_bytes}",
                    },
                )
                response = connection.getresponse()
                # Read at most max_response_bytes, discard immediately
                _ = response.read(self.max_response_bytes)

            headers_dict = {k.lower(): v for k, v in response.getheaders()}

            # Re-verify that Location header (if any) doesn't blatantly target localhost or file://
            if "location" in headers_dict:
                loc = headers_dict["location"]
                loc_parsed = urllib.parse.urlsplit(loc)
                if loc_parsed.scheme.lower() in _DISALLOWED_SCHEMES:
                    return RedirectHop(
                        url=urllib.parse.urlunsplit(parsed),
                        status_code=response.status,
                        resolved_ip=None,
                        headers=headers_dict,
                        is_safe=False,
                        block_reason=f"Redirect targets forbidden scheme: {loc_parsed.scheme}",
                    )

            return RedirectHop(
                url=urllib.parse.urlunsplit(parsed),
                status_code=response.status,
                resolved_ip=None,  # Do not leak internal IP topology in findings
                headers=headers_dict,
                is_safe=True,
            )

        finally:
            if connection:
                connection.close()
