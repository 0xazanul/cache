"""Cache Key Oracle - Discover which inputs are part of the cache key.

This module determines which headers and parameters actually affect the cache key.
Only inputs that are NOT in the cache key can be used for cache poisoning.

Methodology:
1. Send request A with header X = "value1", get response hash
2. Send request B with header X = "value2", get response hash  
3. If hashes match and cache headers indicate HIT -> header NOT in key (vulnerable)
4. If hashes differ or cache MISS -> header IS in key (not vulnerable to this header)
"""

import asyncio
import hashlib
import secrets
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any

from config import UNKEYED_HEADERS


class KeyStatus(Enum):
    """Whether an input is part of the cache key."""
    IN_KEY = auto()         # Input IS part of cache key (not exploitable)
    NOT_IN_KEY = auto()     # Input NOT in cache key (potentially exploitable)
    UNCERTAIN = auto()      # Could not determine
    NOT_CACHED = auto()     # Response is not cached at all


@dataclass
class KeyOracleResult:
    """Result of cache key oracle test for a single input."""
    
    input_name: str
    input_type: str  # "header" or "param"
    status: KeyStatus
    evidence: dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "input_name": self.input_name,
            "input_type": self.input_type,
            "status": self.status.name.lower(),
            "evidence": self.evidence,
        }


@dataclass
class CacheKeyProfile:
    """Complete cache key profile for a URL."""
    
    url: str
    is_cached: bool
    vary_headers: list[str]
    keyed_inputs: list[str]
    unkeyed_inputs: list[str]
    uncertain_inputs: list[str]
    oracle_results: list[KeyOracleResult]
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "is_cached": self.is_cached,
            "vary_headers": self.vary_headers,
            "keyed_inputs": self.keyed_inputs,
            "unkeyed_inputs": self.unkeyed_inputs,
            "uncertain_inputs": self.uncertain_inputs,
        }
    
    def get_exploitable_headers(self) -> list[str]:
        """Get headers that are not in cache key (exploitable)."""
        return [
            r.input_name for r in self.oracle_results
            if r.input_type == "header" and r.status == KeyStatus.NOT_IN_KEY
        ]


class CacheKeyOracle:
    """
    Discover cache key components through differential analysis.
    
    This helps avoid false positives by only testing inputs that
    are confirmed to NOT be part of the cache key.
    """
    
    def __init__(self, client):
        """
        Initialize cache key oracle.
        
        Args:
            client: AsyncHTTPClient instance
        """
        self.client = client
        self._response_cache: dict[str, str] = {}
    
    async def analyze_url(
        self,
        url: str,
        headers_to_test: list[str] | None = None,
        params_to_test: list[str] | None = None,
    ) -> CacheKeyProfile:
        """
        Analyze a URL to determine cache key components.
        
        Args:
            url: Target URL
            headers_to_test: Headers to test (default: common unkeyed headers)
            params_to_test: Query params to test
            
        Returns:
            CacheKeyProfile with discovered key components
        """
        if headers_to_test is None:
            headers_to_test = UNKEYED_HEADERS[:15]  # Test top 15 for speed
        
        if params_to_test is None:
            params_to_test = ["utm_source", "callback", "_"]
        
        # First, check if URL is cached at all
        is_cached, vary_headers = await self._check_caching(url)
        
        if not is_cached:
            return CacheKeyProfile(
                url=url,
                is_cached=False,
                vary_headers=vary_headers,
                keyed_inputs=[],
                unkeyed_inputs=[],
                uncertain_inputs=list(headers_to_test),
                oracle_results=[],
            )
        
        # Test each header
        oracle_results = []
        
        # Run header tests concurrently (with limit)
        semaphore = asyncio.Semaphore(5)
        
        async def test_header(header: str) -> KeyOracleResult:
            async with semaphore:
                return await self._test_header_in_key(url, header)
        
        header_tasks = [test_header(h) for h in headers_to_test]
        header_results = await asyncio.gather(*header_tasks)
        oracle_results.extend(header_results)
        
        # Test parameters
        for param in params_to_test:
            result = await self._test_param_in_key(url, param)
            oracle_results.append(result)
        
        # Categorize results
        keyed = []
        unkeyed = []
        uncertain = []
        
        for result in oracle_results:
            if result.status == KeyStatus.IN_KEY:
                keyed.append(result.input_name)
            elif result.status == KeyStatus.NOT_IN_KEY:
                unkeyed.append(result.input_name)
            else:
                uncertain.append(result.input_name)
        
        return CacheKeyProfile(
            url=url,
            is_cached=is_cached,
            vary_headers=vary_headers,
            keyed_inputs=keyed,
            unkeyed_inputs=unkeyed,
            uncertain_inputs=uncertain,
            oracle_results=oracle_results,
        )
    
    async def _check_caching(self, url: str) -> tuple[bool, list[str]]:
        """Check if URL responses are cached and get Vary headers."""
        # Send two identical requests
        response1 = await self.client.get(url)
        await asyncio.sleep(0.5)
        response2 = await self.client.get(url)
        
        if response1.error or response2.error:
            return False, []
        
        # Check for cache indicators
        is_cached = False
        
        # Check cache status headers
        cache_headers = ["x-cache", "cf-cache-status", "x-cache-status", "age"]
        for header in cache_headers:
            value = response2.get_header(header, "").lower()
            if "hit" in value or (header == "age" and value.isdigit() and int(value) > 0):
                is_cached = True
                break
        
        # Also check if responses are identical (suggests caching)
        if not is_cached:
            hash1 = hashlib.sha256(response1.body.encode()).hexdigest()
            hash2 = hashlib.sha256(response2.body.encode()).hexdigest()
            if hash1 == hash2 and response2.elapsed_ms < response1.elapsed_ms * 0.8:
                is_cached = True
        
        # Get Vary headers
        vary = response1.get_header("vary", "")
        vary_headers = [h.strip().lower() for h in vary.split(",") if h.strip()]
        
        return is_cached, vary_headers
    
    async def _test_header_in_key(self, url: str, header: str) -> KeyOracleResult:
        """
        Test if a specific header is part of the cache key.
        
        If two requests with different header values return the same
        cached response, the header is NOT in the cache key.
        """
        # Generate unique test values
        value1 = f"oracle-test-{secrets.token_hex(4)}"
        value2 = f"oracle-test-{secrets.token_hex(4)}"
        
        # First request with value1
        response1 = await self.client.get(url, headers={header: value1})
        
        if response1.error:
            return KeyOracleResult(
                input_name=header,
                input_type="header",
                status=KeyStatus.UNCERTAIN,
                evidence={"error": response1.error},
            )
        
        # Wait for cache propagation
        await asyncio.sleep(1)
        
        # Second request with value2
        response2 = await self.client.get(url, headers={header: value2})
        
        if response2.error:
            return KeyOracleResult(
                input_name=header,
                input_type="header",
                status=KeyStatus.UNCERTAIN,
                evidence={"error": response2.error},
            )
        
        # Compare responses
        hash1 = hashlib.sha256(response1.body.encode()).hexdigest()
        hash2 = hashlib.sha256(response2.body.encode()).hexdigest()
        
        # Check cache status on second response
        cache_hit = self._is_cache_hit(response2)
        
        evidence = {
            "value1": value1,
            "value2": value2,
            "hash1": hash1[:16],
            "hash2": hash2[:16],
            "cache_hit": cache_hit,
            "response1_status": response1.status_code,
            "response2_status": response2.status_code,
        }
        
        # Determine key status
        if hash1 == hash2 and cache_hit:
            # Same response served from cache = header NOT in key
            return KeyOracleResult(
                input_name=header,
                input_type="header",
                status=KeyStatus.NOT_IN_KEY,
                evidence=evidence,
            )
        elif hash1 != hash2:
            # Different responses = header IS in key
            return KeyOracleResult(
                input_name=header,
                input_type="header",
                status=KeyStatus.IN_KEY,
                evidence=evidence,
            )
        else:
            # Same response but no cache hit indicator
            return KeyOracleResult(
                input_name=header,
                input_type="header",
                status=KeyStatus.UNCERTAIN,
                evidence=evidence,
            )
    
    async def _test_param_in_key(self, url: str, param: str) -> KeyOracleResult:
        """Test if a query parameter is part of the cache key."""
        value1 = f"oracle{secrets.token_hex(4)}"
        value2 = f"oracle{secrets.token_hex(4)}"
        
        # Build URLs with different param values
        separator = "&" if "?" in url else "?"
        url1 = f"{url}{separator}{param}={value1}"
        url2 = f"{url}{separator}{param}={value2}"
        
        response1 = await self.client.get(url1)
        await asyncio.sleep(1)
        response2 = await self.client.get(url2)
        
        if response1.error or response2.error:
            return KeyOracleResult(
                input_name=param,
                input_type="param",
                status=KeyStatus.UNCERTAIN,
                evidence={"error": response1.error or response2.error},
            )
        
        hash1 = hashlib.sha256(response1.body.encode()).hexdigest()
        hash2 = hashlib.sha256(response2.body.encode()).hexdigest()
        cache_hit = self._is_cache_hit(response2)
        
        evidence = {
            "value1": value1,
            "value2": value2,
            "hash1": hash1[:16],
            "hash2": hash2[:16],
            "cache_hit": cache_hit,
        }
        
        if hash1 == hash2 and cache_hit:
            return KeyOracleResult(
                input_name=param,
                input_type="param",
                status=KeyStatus.NOT_IN_KEY,
                evidence=evidence,
            )
        elif hash1 != hash2:
            return KeyOracleResult(
                input_name=param,
                input_type="param",
                status=KeyStatus.IN_KEY,
                evidence=evidence,
            )
        else:
            return KeyOracleResult(
                input_name=param,
                input_type="param",
                status=KeyStatus.UNCERTAIN,
                evidence=evidence,
            )
    
    def _is_cache_hit(self, response) -> bool:
        """Check if response indicates a cache hit."""
        hit_indicators = {
            "x-cache": ["hit"],
            "cf-cache-status": ["hit", "stale", "revalidated"],
            "x-cache-status": ["hit"],
            "x-varnish-cache": ["hit"],
            "fastly-cache-status": ["hit"],
            "akamai-cache-status": ["hit"],
        }
        
        for header, values in hit_indicators.items():
            header_value = response.get_header(header, "").lower()
            if any(v in header_value for v in values):
                return True
        
        # Check Age header
        age = response.get_header("age", "")
        if age.isdigit() and int(age) > 0:
            return True
        
        return False
    
    async def quick_check_header(self, url: str, header: str) -> bool:
        """
        Quick check if a header is likely not in cache key.
        
        Returns True if header appears exploitable (not in key).
        """
        result = await self._test_header_in_key(url, header)
        return result.status == KeyStatus.NOT_IN_KEY
