"""Payload generators for cache poisoning attack vectors.

Enhanced with cryptographic canary tokens that include:
- Version prefix for identification
- Domain hash for context
- Timestamp for uniqueness  
- Random component for security
"""

import hashlib
import secrets
import string
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any
from urllib.parse import urlencode, urlparse, urlunparse, parse_qs

from config import MARKER_PREFIX, MARKER_LENGTH, UNKEYED_HEADERS


# Enhanced marker format: cpv2-{domain_hash}-{timestamp}-{random}
MARKER_VERSION = "cpv2"


class AttackVector(Enum):
    """Types of cache poisoning attack vectors."""
    UNKEYED_HEADER = auto()
    UNKEYED_PARAM = auto()
    METHOD_OVERRIDE = auto()
    FAT_GET = auto()
    PATH_CONFUSION = auto()
    HOST_OVERRIDE = auto()
    HEADER_OVERSIZE = auto()


@dataclass
class Payload:
    """Represents a cache poisoning test payload."""
    
    vector: AttackVector
    marker: str
    headers: dict[str, str] = field(default_factory=dict)
    params: dict[str, str] = field(default_factory=dict)
    body: str | None = None
    method: str = "GET"
    path_suffix: str = ""
    description: str = ""
    header_name: str | None = None  # For tracking which header was used
    param_name: str | None = None   # For tracking which param was used
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for reporting."""
        return {
            "vector": self.vector.name.lower(),
            "marker": self.marker,
            "headers": self.headers,
            "params": self.params,
            "body": self.body,
            "method": self.method,
            "path_suffix": self.path_suffix,
            "description": self.description,
            "header_name": self.header_name,
            "param_name": self.param_name,
        }


class PayloadGenerator:
    """
    Generate payloads for various cache poisoning attack vectors.
    
    Enhanced features:
    - Cryptographic canary tokens with domain context
    - Timestamp-based uniqueness for tracking
    - Version-prefixed markers for easy identification
    """
    
    def __init__(
        self,
        custom_headers: list[str] | None = None,
        domain_context: str | None = None,
    ):
        """
        Initialize payload generator.
        
        Args:
            custom_headers: Additional headers to test beyond defaults
            domain_context: Domain to include in marker hash (optional)
        """
        self.unkeyed_headers = list(UNKEYED_HEADERS)
        if custom_headers:
            self.unkeyed_headers.extend(custom_headers)
        self.domain_context = domain_context
        self._marker_counter = 0
    
    def generate_marker(self, domain: str | None = None) -> str:
        """
        Generate a unique, cryptographic canary marker.
        
        Format: cpv2-{domain_hash}-{timestamp_hex}-{random}
        Example: cpv2-f7a2-18d4c3b0-8c3d9e1f
        
        This format ensures:
        - Version prefix for identification (cpv2)
        - Domain hash for context tracking (4 chars)
        - Timestamp for uniqueness (8 chars hex)
        - Random component for security (8 chars)
        
        Args:
            domain: Optional domain for context hashing
            
        Returns:
            Unique marker string
        """
        # Use provided domain or stored context
        ctx = domain or self.domain_context or "default"
        
        # Domain hash (first 4 chars of MD5)
        domain_hash = hashlib.md5(ctx.encode()).hexdigest()[:4]
        
        # Timestamp (current time as hex, last 8 chars)
        timestamp_hex = format(int(time.time() * 1000), 'x')[-8:]
        
        # Random component (8 hex chars)
        random_part = secrets.token_hex(4)
        
        # Counter to ensure uniqueness within same millisecond
        self._marker_counter += 1
        counter_part = format(self._marker_counter % 256, '02x')
        
        return f"{MARKER_VERSION}-{domain_hash}-{timestamp_hex}-{random_part}{counter_part}"
    
    def generate_marker_simple(self) -> str:
        """
        Generate a simple marker (backwards compatible).
        
        Format: cp-scan-{random}
        """
        random_part = ''.join(
            secrets.choice(string.ascii_lowercase + string.digits)
            for _ in range(MARKER_LENGTH)
        )
        return f"{MARKER_PREFIX}{random_part}"
    
    def set_domain_context(self, domain: str) -> None:
        """Set domain context for marker generation."""
        self.domain_context = domain
    
    def generate_all(self, base_url: str) -> list[Payload]:
        """
        Generate all payload types for a given URL.
        
        Args:
            base_url: The target URL to generate payloads for
            
        Returns:
            List of Payload objects to test
        """
        payloads = []
        
        # Unkeyed header payloads
        payloads.extend(self.generate_unkeyed_header_payloads())
        
        # Host override payloads
        payloads.extend(self.generate_host_override_payloads())
        
        # Unkeyed parameter payloads
        payloads.extend(self.generate_unkeyed_param_payloads(base_url))
        
        # Method override payloads
        payloads.extend(self.generate_method_override_payloads())
        
        # Fat GET payloads
        payloads.extend(self.generate_fat_get_payloads())
        
        # Path confusion payloads
        payloads.extend(self.generate_path_confusion_payloads())
        
        # Oversize header payloads (CPDoS)
        payloads.extend(self.generate_oversize_header_payloads())
        
        return payloads
    
    def generate_unkeyed_header_payloads(self) -> list[Payload]:
        """Generate payloads for unkeyed header injection."""
        payloads = []
        
        for header in self.unkeyed_headers:
            marker = self.generate_marker()
            
            # Test header reflection in response
            payloads.append(Payload(
                vector=AttackVector.UNKEYED_HEADER,
                marker=marker,
                headers={header: marker},
                description=f"Unkeyed header injection via {header}",
                header_name=header,
            ))
            
            # Test with URL value (for forwarded-host type headers)
            if "host" in header.lower() or "url" in header.lower():
                url_marker = self.generate_marker()
                payloads.append(Payload(
                    vector=AttackVector.UNKEYED_HEADER,
                    marker=url_marker,
                    headers={header: f"https://{url_marker}.evil.com"},
                    description=f"Unkeyed header URL injection via {header}",
                    header_name=header,
                ))
        
        return payloads
    
    def generate_host_override_payloads(self) -> list[Payload]:
        """Generate payloads specifically for host header attacks."""
        payloads = []
        host_headers = [
            "X-Forwarded-Host",
            "X-Host",
            "X-Original-Host",
            "X-HTTP-Host-Override",
            "Forwarded",
        ]
        
        for header in host_headers:
            marker = self.generate_marker()
            
            if header == "Forwarded":
                # RFC 7239 format
                value = f"host={marker}.evil.com"
            else:
                value = f"{marker}.evil.com"
            
            payloads.append(Payload(
                vector=AttackVector.HOST_OVERRIDE,
                marker=marker,
                headers={header: value},
                description=f"Host override via {header}",
                header_name=header,
            ))
        
        return payloads
    
    def generate_unkeyed_param_payloads(self, base_url: str) -> list[Payload]:
        """Generate payloads for unkeyed parameter injection."""
        payloads = []
        
        # Common parameters often excluded from cache keys
        unkeyed_params = [
            "utm_source",
            "utm_medium",
            "utm_campaign",
            "utm_content",
            "utm_term",
            "fbclid",
            "gclid",
            "ref",
            "source",
            "callback",
            "jsonp",
            "_",
            "timestamp",
            "nocache",
            "random",
        ]
        
        for param in unkeyed_params:
            marker = self.generate_marker()
            payloads.append(Payload(
                vector=AttackVector.UNKEYED_PARAM,
                marker=marker,
                params={param: marker},
                description=f"Unkeyed parameter injection via {param}",
                param_name=param,
            ))
        
        # Parameter cloaking - duplicate params with different values
        marker = self.generate_marker()
        # Note: The actual parameter cloaking requires special URL construction
        payloads.append(Payload(
            vector=AttackVector.UNKEYED_PARAM,
            marker=marker,
            params={"param": marker},  # Will be handled specially in detector
            description="Parameter cloaking test",
            param_name="param_cloaking",
        ))
        
        return payloads
    
    def generate_method_override_payloads(self) -> list[Payload]:
        """Generate payloads for HTTP method override attacks."""
        payloads = []
        
        method_headers = [
            "X-HTTP-Method-Override",
            "X-HTTP-Method",
            "X-Method-Override",
        ]
        
        methods = ["POST", "PUT", "DELETE", "PATCH"]
        
        for header in method_headers:
            for method in methods:
                marker = self.generate_marker()
                payloads.append(Payload(
                    vector=AttackVector.METHOD_OVERRIDE,
                    marker=marker,
                    headers={header: method},
                    description=f"Method override to {method} via {header}",
                    header_name=header,
                ))
        
        return payloads
    
    def generate_fat_get_payloads(self) -> list[Payload]:
        """Generate payloads for Fat GET attacks (body in GET request)."""
        payloads = []
        
        marker = self.generate_marker()
        
        # JSON body
        payloads.append(Payload(
            vector=AttackVector.FAT_GET,
            marker=marker,
            headers={"Content-Type": "application/json"},
            body=f'{{"test": "{marker}"}}',
            method="GET",
            description="Fat GET with JSON body",
        ))
        
        # Form body
        marker2 = self.generate_marker()
        payloads.append(Payload(
            vector=AttackVector.FAT_GET,
            marker=marker2,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            body=f"test={marker2}",
            method="GET",
            description="Fat GET with form body",
        ))
        
        return payloads
    
    def generate_path_confusion_payloads(self) -> list[Payload]:
        """Generate payloads for path confusion/normalization attacks."""
        payloads = []
        
        # Various path suffixes that might cause confusion
        path_variations = [
            "/..%2f",
            "/%2e%2e/",
            "/./",
            "/../",
            ";/",
            "%00",
            "%0a",
            "%0d",
            ".css",
            ".js",
            ".png",
            ".jpg",
            ".ico",
            ".woff",
            ".svg",
            "/test.css",
            "/a.js",
        ]
        
        for suffix in path_variations:
            marker = self.generate_marker()
            payloads.append(Payload(
                vector=AttackVector.PATH_CONFUSION,
                marker=marker,
                path_suffix=suffix,
                description=f"Path confusion with suffix: {suffix}",
            ))
        
        return payloads
    
    def generate_oversize_header_payloads(self) -> list[Payload]:
        """Generate payloads for CPDoS via oversized headers."""
        payloads = []
        
        # Large header value (HTTP Header Oversize - HHO)
        marker = self.generate_marker()
        large_value = "A" * 8000  # 8KB header
        
        payloads.append(Payload(
            vector=AttackVector.HEADER_OVERSIZE,
            marker=marker,
            headers={"X-Oversized-Header": f"{marker}-{large_value}"},
            description="HTTP Header Oversize (HHO) attack",
            header_name="X-Oversized-Header",
        ))
        
        # Meta character injection
        marker2 = self.generate_marker()
        payloads.append(Payload(
            vector=AttackVector.HEADER_OVERSIZE,
            marker=marker2,
            headers={"X-Meta-Char": f"{marker2}\x00\r\n"},
            description="Meta character injection in header",
            header_name="X-Meta-Char",
        ))
        
        return payloads
    
    def build_url_with_payload(
        self,
        base_url: str,
        payload: Payload,
    ) -> str:
        """
        Construct the full URL with payload parameters applied.
        
        Args:
            base_url: The original URL
            payload: The payload to apply
            
        Returns:
            Modified URL with payload params
        """
        parsed = urlparse(base_url)
        
        # Apply path suffix
        path = parsed.path or "/"
        if payload.path_suffix:
            path = path.rstrip("/") + payload.path_suffix
        
        # Apply query parameters
        existing_params = parse_qs(parsed.query, keep_blank_values=True)
        # Flatten existing params
        flat_params = {k: v[0] if len(v) == 1 else v for k, v in existing_params.items()}
        flat_params.update(payload.params)
        
        query = urlencode(flat_params, doseq=True) if flat_params else ""
        
        # Reconstruct URL
        return urlunparse((
            parsed.scheme,
            parsed.netloc,
            path,
            parsed.params,
            query,
            "",  # Remove fragment
        ))
    
    def generate_cache_buster(self) -> str:
        """Generate a cache-busting query parameter value."""
        return f"cb{int(time.time())}{secrets.token_hex(4)}"
