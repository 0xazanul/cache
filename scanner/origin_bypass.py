"""Origin Bypass Comparator - Compare cached vs origin server responses.

This module verifies cache poisoning by comparing:
1. Normal request (served from cache) - should contain poisoned marker
2. Cache-bypassed request (from origin) - should be clean

If origin is clean but cache is poisoned = CONFIRMED CACHE POISONING
"""

import asyncio
import hashlib
import secrets
from dataclasses import dataclass, field
from typing import Any


@dataclass
class OriginComparisonResult:
    """Result of origin vs cache comparison."""
    
    url: str
    marker: str
    cache_response_poisoned: bool
    origin_response_clean: bool
    is_confirmed_poisoning: bool
    confidence: str
    bypass_method_used: str
    evidence: dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "marker": self.marker,
            "cache_response_poisoned": self.cache_response_poisoned,
            "origin_response_clean": self.origin_response_clean,
            "is_confirmed_poisoning": self.is_confirmed_poisoning,
            "confidence": self.confidence,
            "bypass_method_used": self.bypass_method_used,
            "evidence": self.evidence,
        }


class OriginBypassComparator:
    """
    Compare cached responses vs origin server to confirm poisoning.
    
    Uses multiple cache bypass techniques to reach the origin directly:
    1. Cache-Control: no-cache header
    2. Pragma: no-cache header
    3. Cache-busting query parameters
    4. Unique URL variations
    """
    
    # Cache bypass methods to try
    BYPASS_METHODS = [
        {
            "name": "cache_control_no_cache",
            "headers": {"Cache-Control": "no-cache", "Pragma": "no-cache"},
            "param": None,
        },
        {
            "name": "cache_buster_param",
            "headers": {},
            "param": "_nocache",
        },
        {
            "name": "unique_query",
            "headers": {},
            "param": "__cb",
        },
        {
            "name": "max_age_zero",
            "headers": {"Cache-Control": "max-age=0"},
            "param": None,
        },
        {
            "name": "combined",
            "headers": {"Cache-Control": "no-cache, no-store", "Pragma": "no-cache"},
            "param": "_bypass",
        },
    ]
    
    def __init__(self, client):
        """
        Initialize origin bypass comparator.
        
        Args:
            client: AsyncHTTPClient instance
        """
        self.client = client
    
    async def compare(
        self,
        url: str,
        marker: str,
    ) -> OriginComparisonResult:
        """
        Compare cached response vs origin to confirm poisoning.
        
        Args:
            url: The URL to test
            marker: The poisoning marker to look for
            
        Returns:
            OriginComparisonResult with comparison details
        """
        evidence = {
            "bypass_attempts": [],
            "cache_check": None,
            "origin_checks": [],
        }
        
        # Step 1: Check if normal (cached) response contains marker
        cache_response = await self.client.get(url)
        
        if cache_response.error:
            return OriginComparisonResult(
                url=url,
                marker=marker,
                cache_response_poisoned=False,
                origin_response_clean=False,
                is_confirmed_poisoning=False,
                confidence="none",
                bypass_method_used="none",
                evidence={"error": cache_response.error},
            )
        
        cache_poisoned = marker.lower() in cache_response.body.lower()
        cache_hash = hashlib.sha256(cache_response.body.encode()).hexdigest()[:16]
        
        evidence["cache_check"] = {
            "marker_found": cache_poisoned,
            "status_code": cache_response.status_code,
            "content_hash": cache_hash,
            "cache_hit": self._check_cache_hit(cache_response),
        }
        
        if not cache_poisoned:
            # If cache isn't poisoned, nothing to confirm
            return OriginComparisonResult(
                url=url,
                marker=marker,
                cache_response_poisoned=False,
                origin_response_clean=True,
                is_confirmed_poisoning=False,
                confidence="none",
                bypass_method_used="none",
                evidence=evidence,
            )
        
        # Step 2: Try to reach origin using various bypass methods
        origin_clean = False
        successful_bypass_method = "none"
        
        for method in self.BYPASS_METHODS:
            bypass_result = await self._try_bypass(url, marker, method)
            evidence["bypass_attempts"].append(bypass_result)
            
            if bypass_result["success"] and bypass_result["origin_clean"]:
                origin_clean = True
                successful_bypass_method = method["name"]
                evidence["origin_checks"].append(bypass_result)
                break
            
            await asyncio.sleep(0.3)
        
        # Step 3: Determine if this is confirmed poisoning
        # Confirmed if: cache has marker AND origin doesn't
        is_confirmed = cache_poisoned and origin_clean
        
        # Calculate confidence
        if is_confirmed:
            # Additional confirmation: re-check cache still has marker
            await asyncio.sleep(0.5)
            recheck_response = await self.client.get(url)
            recheck_poisoned = (
                not recheck_response.error and 
                marker.lower() in recheck_response.body.lower()
            )
            
            if recheck_poisoned:
                confidence = "high"
            else:
                confidence = "medium"  # Marker disappeared, might be TTL
        else:
            confidence = "low" if cache_poisoned else "none"
        
        return OriginComparisonResult(
            url=url,
            marker=marker,
            cache_response_poisoned=cache_poisoned,
            origin_response_clean=origin_clean,
            is_confirmed_poisoning=is_confirmed,
            confidence=confidence,
            bypass_method_used=successful_bypass_method,
            evidence=evidence,
        )
    
    async def _try_bypass(
        self,
        url: str,
        marker: str,
        method: dict,
    ) -> dict[str, Any]:
        """Try a single cache bypass method."""
        # Build request
        headers = dict(method["headers"])
        target_url = url
        
        if method["param"]:
            # Add cache-busting parameter
            separator = "&" if "?" in url else "?"
            buster_value = secrets.token_hex(8)
            target_url = f"{url}{separator}{method['param']}={buster_value}"
        
        # Make request
        response = await self.client.get(target_url, headers=headers)
        
        if response.error:
            return {
                "method": method["name"],
                "success": False,
                "origin_clean": False,
                "error": response.error,
            }
        
        # Check if we reached origin (not cache)
        cache_miss = self._check_cache_miss(response)
        marker_found = marker.lower() in response.body.lower()
        
        return {
            "method": method["name"],
            "success": True,
            "origin_clean": not marker_found,
            "cache_miss": cache_miss,
            "marker_found": marker_found,
            "status_code": response.status_code,
            "content_hash": hashlib.sha256(response.body.encode()).hexdigest()[:16],
        }
    
    def _check_cache_hit(self, response) -> bool:
        """Check if response was served from cache."""
        hit_indicators = {
            "x-cache": ["hit"],
            "cf-cache-status": ["hit", "stale", "revalidated"],
            "x-cache-status": ["hit"],
            "age": None,
        }
        
        for header, values in hit_indicators.items():
            header_value = response.get_header(header, "").lower()
            
            if header == "age":
                if header_value.isdigit() and int(header_value) > 0:
                    return True
            elif values and any(v in header_value for v in values):
                return True
        
        return False
    
    def _check_cache_miss(self, response) -> bool:
        """Check if response indicates cache miss (from origin)."""
        miss_indicators = {
            "x-cache": ["miss"],
            "cf-cache-status": ["miss", "bypass", "dynamic", "expired"],
            "x-cache-status": ["miss", "bypass"],
        }
        
        for header, values in miss_indicators.items():
            header_value = response.get_header(header, "").lower()
            if any(v in header_value for v in values):
                return True
        
        # No cache-related headers at all might indicate origin
        has_cache_headers = any(
            response.get_header(h) 
            for h in ["x-cache", "cf-cache-status", "x-cache-status", "age"]
        )
        
        # Check for Age: 0 (fresh from origin)
        age = response.get_header("age", "")
        if age == "0":
            return True
        
        return not has_cache_headers
    
    async def verify_poisoning_isolation(
        self,
        url: str,
        marker: str,
    ) -> dict[str, Any]:
        """
        Verify that poisoning is isolated to cache, not affecting origin.
        
        This is a more thorough check that makes multiple comparisons.
        """
        results = {
            "total_cache_checks": 3,
            "total_origin_checks": 3,
            "cache_poisoned_count": 0,
            "origin_clean_count": 0,
            "is_isolated": False,
        }
        
        # Multiple cache checks
        for i in range(3):
            response = await self.client.get(url)
            if not response.error and marker.lower() in response.body.lower():
                results["cache_poisoned_count"] += 1
            await asyncio.sleep(0.5)
        
        # Multiple origin checks with different bypass methods
        for i, method in enumerate(self.BYPASS_METHODS[:3]):
            bypass_result = await self._try_bypass(url, marker, method)
            if bypass_result["success"] and bypass_result["origin_clean"]:
                results["origin_clean_count"] += 1
            await asyncio.sleep(0.5)
        
        # Poisoning is isolated if cache is consistently poisoned
        # but origin is consistently clean
        results["is_isolated"] = (
            results["cache_poisoned_count"] >= 2 and
            results["origin_clean_count"] >= 2
        )
        
        return results
    
    async def quick_origin_check(self, url: str, marker: str) -> bool:
        """
        Quick check if origin is clean while cache is poisoned.
        
        Returns True if confirmed (cache poisoned, origin clean).
        """
        # Check cache
        cache_response = await self.client.get(url)
        if cache_response.error:
            return False
        
        cache_poisoned = marker.lower() in cache_response.body.lower()
        if not cache_poisoned:
            return False
        
        # Try to reach origin
        separator = "&" if "?" in url else "?"
        origin_url = f"{url}{separator}_origin={secrets.token_hex(4)}"
        
        origin_response = await self.client.get(
            origin_url,
            headers={"Cache-Control": "no-cache"},
        )
        
        if origin_response.error:
            return False
        
        origin_clean = marker.lower() not in origin_response.body.lower()
        
        return cache_poisoned and origin_clean
