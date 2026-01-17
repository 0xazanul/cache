"""Baseline response capture and normalization for comparison."""

import hashlib
import re
from dataclasses import dataclass, field
from typing import Any

from .http_client import HTTPResponse
from .cache_fingerprint import CacheFingerprinter, CacheInfo


@dataclass
class BaselineResponse:
    """Captured baseline response for comparison."""
    
    url: str
    status_code: int
    content_hash: str
    normalized_body: str
    body_length: int
    headers: dict[str, str]
    cache_info: CacheInfo
    response_time_ms: float
    content_type: str | None = None
    is_dynamic: bool = False
    dynamic_patterns: list[str] = field(default_factory=list)
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "url": self.url,
            "status_code": self.status_code,
            "content_hash": self.content_hash,
            "body_length": self.body_length,
            "cache_info": self.cache_info.to_dict(),
            "response_time_ms": self.response_time_ms,
            "content_type": self.content_type,
            "is_dynamic": self.is_dynamic,
        }


class BaselineCapture:
    """Capture and normalize baseline responses for comparison."""
    
    # Patterns for dynamic content that should be normalized
    DYNAMIC_PATTERNS = [
        # Timestamps
        (r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}', '{{TIMESTAMP}}'),
        (r'\d{10,13}', '{{UNIX_TIMESTAMP}}'),
        
        # UUIDs
        (r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', '{{UUID}}'),
        
        # Session/Token IDs
        (r'[a-zA-Z0-9]{32,}', '{{TOKEN}}'),
        
        # CSRF tokens
        (r'csrf[_-]?token["\'\s:=]+["\']?[a-zA-Z0-9+/=]{20,}', '{{CSRF}}'),
        
        # Nonces
        (r'nonce["\'\s:=]+["\']?[a-zA-Z0-9+/=]{10,}', '{{NONCE}}'),
        
        # Analytics/tracking IDs
        (r'_ga=[^&;"\'\s]+', '_ga={{ANALYTICS}}'),
        (r'_gid=[^&;"\'\s]+', '_gid={{ANALYTICS}}'),
        
        # Request IDs in headers
        (r'x-request-id["\'\s:]+[a-zA-Z0-9-]+', 'x-request-id: {{REQUEST_ID}}'),
    ]
    
    def __init__(self):
        self._fingerprinter = CacheFingerprinter()
        self._compiled_patterns = [
            (re.compile(pattern, re.IGNORECASE), replacement)
            for pattern, replacement in self.DYNAMIC_PATTERNS
        ]
    
    def capture(self, response: HTTPResponse) -> BaselineResponse:
        """
        Capture a baseline response with normalization.
        
        Args:
            response: The HTTP response to capture
            
        Returns:
            BaselineResponse with normalized content
        """
        # Get cache info
        cache_info = self._fingerprinter.fingerprint(response.headers)
        
        # Normalize body
        normalized_body, dynamic_patterns = self._normalize_body(response.body)
        
        # Calculate content hash
        content_hash = self._hash_content(normalized_body)
        
        # Get content type
        content_type = response.get_header("content-type")
        
        # Determine if response is dynamic
        is_dynamic = bool(dynamic_patterns) or self._is_likely_dynamic(response)
        
        return BaselineResponse(
            url=response.url,
            status_code=response.status_code,
            content_hash=content_hash,
            normalized_body=normalized_body,
            body_length=len(response.body),
            headers=response.headers,
            cache_info=cache_info,
            response_time_ms=response.elapsed_ms,
            content_type=content_type,
            is_dynamic=is_dynamic,
            dynamic_patterns=dynamic_patterns,
        )
    
    def _normalize_body(self, body: str) -> tuple[str, list[str]]:
        """
        Normalize response body by replacing dynamic content.
        
        Args:
            body: Raw response body
            
        Returns:
            Tuple of (normalized_body, list of patterns found)
        """
        normalized = body
        found_patterns = []
        
        for pattern, replacement in self._compiled_patterns:
            if pattern.search(normalized):
                found_patterns.append(replacement)
                normalized = pattern.sub(replacement, normalized)
        
        # Remove whitespace variations
        normalized = re.sub(r'\s+', ' ', normalized)
        
        return normalized, found_patterns
    
    def _hash_content(self, content: str) -> str:
        """Calculate SHA-256 hash of content."""
        return hashlib.sha256(content.encode('utf-8', errors='ignore')).hexdigest()
    
    def _is_likely_dynamic(self, response: HTTPResponse) -> bool:
        """
        Heuristically determine if response is likely dynamic.
        
        Dynamic responses are less reliable for cache poisoning detection.
        """
        # Check Cache-Control header
        cache_control = response.get_header("cache-control", "").lower()
        if any(directive in cache_control for directive in ["no-cache", "no-store", "private", "max-age=0"]):
            return True
        
        # Check for Set-Cookie (session-specific)
        if response.get_header("set-cookie"):
            return True
        
        # Check content type
        content_type = response.get_header("content-type", "").lower()
        dynamic_types = ["application/json", "text/xml", "application/xml"]
        if any(dt in content_type for dt in dynamic_types):
            # JSON/XML APIs are often dynamic
            return True
        
        return False
    
    def compare(
        self,
        baseline: BaselineResponse,
        response: HTTPResponse,
        marker: str,
    ) -> dict[str, Any]:
        """
        Compare a response against baseline to detect injection.
        
        Args:
            baseline: The original baseline response
            response: The response to compare
            marker: The injection marker to look for
            
        Returns:
            Dictionary with comparison results
        """
        # Normalize the new response
        normalized_body, _ = self._normalize_body(response.body)
        new_hash = self._hash_content(normalized_body)
        
        # Check for marker in response
        marker_in_body = marker.lower() in response.body.lower()
        marker_in_headers = any(
            marker.lower() in str(v).lower()
            for v in response.headers.values()
        )
        
        # Calculate body difference
        body_changed = new_hash != baseline.content_hash
        length_diff = abs(len(response.body) - baseline.body_length)
        
        # Status code comparison
        status_changed = response.status_code != baseline.status_code
        
        return {
            "marker_reflected_body": marker_in_body,
            "marker_reflected_headers": marker_in_headers,
            "marker_reflected": marker_in_body or marker_in_headers,
            "body_changed": body_changed,
            "length_difference": length_diff,
            "status_changed": status_changed,
            "baseline_hash": baseline.content_hash,
            "response_hash": new_hash,
            "baseline_length": baseline.body_length,
            "response_length": len(response.body),
        }
    
    def find_marker_context(
        self,
        body: str,
        marker: str,
        context_chars: int = 100,
    ) -> list[dict[str, Any]]:
        """
        Find all occurrences of marker in body with surrounding context.
        
        Args:
            body: Response body to search
            marker: Marker string to find
            context_chars: Number of characters of context to include
            
        Returns:
            List of matches with context
        """
        matches = []
        marker_lower = marker.lower()
        body_lower = body.lower()
        
        start = 0
        while True:
            pos = body_lower.find(marker_lower, start)
            if pos == -1:
                break
            
            # Get context
            context_start = max(0, pos - context_chars)
            context_end = min(len(body), pos + len(marker) + context_chars)
            
            matches.append({
                "position": pos,
                "context": body[context_start:context_end],
                "before": body[context_start:pos],
                "after": body[pos + len(marker):context_end],
            })
            
            start = pos + 1
        
        return matches
    
    async def capture_multiple(
        self,
        url: str,
        client,
        count: int = 3,
    ) -> tuple[BaselineResponse | None, bool]:
        """
        Capture multiple baseline responses to detect dynamic content.
        
        Args:
            url: URL to capture
            client: AsyncHTTPClient instance
            count: Number of requests to make
            
        Returns:
            Tuple of (baseline, is_stable) where is_stable indicates
            whether responses were consistent
        """
        responses = []
        hashes = set()
        
        for _ in range(count):
            response = await client.get(url)
            if response.error:
                continue
            
            baseline = self.capture(response)
            responses.append(baseline)
            hashes.add(baseline.content_hash)
        
        if not responses:
            return None, False
        
        # If all hashes are the same, content is stable
        is_stable = len(hashes) == 1
        
        # Return the first baseline
        baseline = responses[0]
        baseline.is_dynamic = not is_stable
        
        return baseline, is_stable
