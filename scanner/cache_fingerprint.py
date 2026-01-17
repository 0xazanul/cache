"""CDN and cache layer fingerprinting from response headers."""

from dataclasses import dataclass
from enum import Enum, auto
from typing import Any

from config import CDN_SIGNATURES, CACHE_HIT_HEADERS, NO_CACHE_DIRECTIVES


class CacheProvider(Enum):
    """Known cache/CDN providers."""
    CLOUDFLARE = auto()
    AKAMAI = auto()
    FASTLY = auto()
    VARNISH = auto()
    CLOUDFRONT = auto()
    NGINX = auto()
    APACHE = auto()
    KEYCDN = auto()
    STACKPATH = auto()
    UNKNOWN = auto()


@dataclass
class CacheInfo:
    """Information about the caching configuration."""
    
    provider: CacheProvider
    is_cached: bool
    is_cacheable: bool
    cache_control: str | None
    vary_headers: list[str]
    max_age: int | None
    age: int | None
    etag: str | None
    last_modified: str | None
    cache_status: str | None
    detected_headers: list[str]
    raw_headers: dict[str, str]
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "provider": self.provider.name.lower(),
            "is_cached": self.is_cached,
            "is_cacheable": self.is_cacheable,
            "cache_control": self.cache_control,
            "vary_headers": self.vary_headers,
            "max_age": self.max_age,
            "age": self.age,
            "cache_status": self.cache_status,
        }


class CacheFingerprinter:
    """Detect and analyze cache/CDN configuration from HTTP responses."""
    
    def __init__(self):
        self._cdn_signatures = CDN_SIGNATURES
        self._cache_hit_headers = CACHE_HIT_HEADERS
    
    def fingerprint(self, headers: dict[str, str]) -> CacheInfo:
        """
        Analyze response headers to determine cache configuration.
        
        Args:
            headers: Response headers dictionary
            
        Returns:
            CacheInfo object with detected configuration
        """
        # Normalize headers to lowercase keys
        headers_lower = {k.lower(): v for k, v in headers.items()}
        
        # Detect provider
        provider = self._detect_provider(headers_lower)
        
        # Check cache status
        is_cached = self._check_cache_hit(headers_lower)
        
        # Parse cache control
        cache_control = headers_lower.get("cache-control", "")
        is_cacheable = self._is_cacheable(cache_control, headers_lower)
        max_age = self._parse_max_age(cache_control)
        
        # Parse other cache headers
        vary_headers = self._parse_vary(headers_lower.get("vary", ""))
        age = self._parse_int_header(headers_lower.get("age"))
        
        # Get cache status header value
        cache_status = self._get_cache_status(headers_lower)
        
        # Find detected CDN headers
        detected_headers = self._get_detected_headers(headers_lower, provider)
        
        return CacheInfo(
            provider=provider,
            is_cached=is_cached,
            is_cacheable=is_cacheable,
            cache_control=cache_control or None,
            vary_headers=vary_headers,
            max_age=max_age,
            age=age,
            etag=headers_lower.get("etag"),
            last_modified=headers_lower.get("last-modified"),
            cache_status=cache_status,
            detected_headers=detected_headers,
            raw_headers=headers,
        )
    
    def _detect_provider(self, headers: dict[str, str]) -> CacheProvider:
        """Detect CDN/cache provider from headers."""
        server = headers.get("server", "").lower()
        
        for provider_name, signatures in self._cdn_signatures.items():
            # Check signature headers
            for sig_header in signatures.get("headers", []):
                if sig_header.lower() in headers:
                    try:
                        return CacheProvider[provider_name.upper()]
                    except KeyError:
                        # Provider in config but not in enum
                        return CacheProvider.UNKNOWN
            
            # Check server header
            for server_sig in signatures.get("server", []):
                if server_sig.lower() in server:
                    try:
                        return CacheProvider[provider_name.upper()]
                    except KeyError:
                        return CacheProvider.UNKNOWN
        
        # Check Via header for proxies
        via = headers.get("via", "").lower()
        if "varnish" in via:
            return CacheProvider.VARNISH
        if "cloudfront" in via:
            return CacheProvider.CLOUDFRONT
        
        return CacheProvider.UNKNOWN
    
    def _check_cache_hit(self, headers: dict[str, str]) -> bool:
        """Check if response was served from cache."""
        for header_name, hit_values in self._cache_hit_headers.items():
            header_value = headers.get(header_name, "").lower()
            if any(hit_val in header_value for hit_val in hit_values):
                return True
        
        # Check Age header (presence often indicates cache)
        if "age" in headers:
            try:
                age = int(headers["age"])
                if age > 0:
                    return True
            except ValueError:
                pass
        
        return False
    
    def _is_cacheable(self, cache_control: str, headers: dict[str, str]) -> bool:
        """
        Determine if response is cacheable by shared caches.
        
        Based on RFC 9111 / RFC 7234 caching rules.
        """
        cc_lower = cache_control.lower()
        
        # Check for explicit no-cache directives
        for directive in NO_CACHE_DIRECTIVES:
            if directive in cc_lower:
                # private is okay for shared cache detection purposes
                # since we're testing shared caches
                if directive == "private":
                    return False
                if directive == "no-store":
                    return False
                # no-cache means revalidation required, not uncacheable
                # for our purposes, this is still a concern
        
        # Check for explicit cacheability
        if "public" in cc_lower:
            return True
        if "max-age" in cc_lower or "s-maxage" in cc_lower:
            return True
        
        # Check Expires header
        if "expires" in headers:
            return True
        
        # Check for Last-Modified or ETag (heuristic caching possible)
        if "last-modified" in headers or "etag" in headers:
            return True
        
        # Default: assume cacheable if no explicit prohibition
        return True
    
    def _parse_max_age(self, cache_control: str) -> int | None:
        """Parse max-age value from Cache-Control header."""
        import re
        
        # Try s-maxage first (shared cache specific)
        match = re.search(r's-maxage\s*=\s*(\d+)', cache_control, re.IGNORECASE)
        if match:
            return int(match.group(1))
        
        # Fall back to max-age
        match = re.search(r'max-age\s*=\s*(\d+)', cache_control, re.IGNORECASE)
        if match:
            return int(match.group(1))
        
        return None
    
    def _parse_vary(self, vary: str) -> list[str]:
        """Parse Vary header into list of header names."""
        if not vary or vary == "*":
            return ["*"] if vary == "*" else []
        
        return [h.strip().lower() for h in vary.split(",") if h.strip()]
    
    def _parse_int_header(self, value: str | None) -> int | None:
        """Parse integer header value."""
        if not value:
            return None
        try:
            return int(value)
        except ValueError:
            return None
    
    def _get_cache_status(self, headers: dict[str, str]) -> str | None:
        """Get cache status from various provider-specific headers."""
        status_headers = [
            "x-cache",
            "x-cache-status",
            "cf-cache-status",
            "x-varnish-cache",
            "x-proxy-cache",
            "fastly-cache-status",
            "akamai-cache-status",
            "x-rack-cache",
            "x-drupal-cache",
        ]
        
        for header in status_headers:
            if header in headers:
                return headers[header]
        
        return None
    
    def _get_detected_headers(
        self,
        headers: dict[str, str],
        provider: CacheProvider,
    ) -> list[str]:
        """Get list of CDN-specific headers found in response."""
        detected = []
        
        if provider == CacheProvider.UNKNOWN:
            return detected
        
        provider_name = provider.name.lower()
        if provider_name in self._cdn_signatures:
            sig_headers = self._cdn_signatures[provider_name].get("headers", [])
            for header in sig_headers:
                if header.lower() in headers:
                    detected.append(header)
        
        return detected
    
    def get_cache_key_components(self, headers: dict[str, str]) -> list[str]:
        """
        Infer which request components might be part of the cache key.
        
        This is based on the Vary header and common CDN behaviors.
        """
        headers_lower = {k.lower(): v for k, v in headers.items()}
        
        # Start with standard components
        components = ["host", "path", "query-string"]
        
        # Add Vary headers
        vary = self._parse_vary(headers_lower.get("vary", ""))
        for header in vary:
            if header != "*" and header not in components:
                components.append(header)
        
        return components
    
    def is_shared_cache(self, cache_info: CacheInfo) -> bool:
        """
        Determine if the cache is likely a shared cache (CDN, reverse proxy).
        
        This is important for cache poisoning - we only care about shared caches.
        """
        # Known CDN providers are shared caches
        if cache_info.provider not in (CacheProvider.UNKNOWN, CacheProvider.APACHE):
            return True
        
        # Check for shared cache indicators
        if cache_info.cache_control:
            cc_lower = cache_info.cache_control.lower()
            if "public" in cc_lower:
                return True
            if "s-maxage" in cc_lower:
                return True
        
        # Age header often indicates shared cache
        if cache_info.age is not None and cache_info.age > 0:
            return True
        
        # Cache status headers indicate CDN/proxy
        if cache_info.cache_status:
            return True
        
        return False
