"""Multi-Vantage Validator - Verify poisoning affects other users.

This module ensures that detected cache poisoning actually affects
OTHER users and is not just local/session-specific behavior.

Key validations:
1. Different User-Agent sees poisoned response
2. Fresh session (no cookies) sees poisoned response  
3. Randomized non-essential headers still see poisoning
4. Optional: Different source IPs via proxy
"""

import asyncio
import random
import secrets
from dataclasses import dataclass, field
from typing import Any


# Diverse User-Agent strings to simulate different clients
USER_AGENT_POOL = [
    # Desktop browsers
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/120.0.0.0 Safari/537.36",
    # Mobile browsers
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (iPad; CPU OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
    # Bots/crawlers (sometimes cached differently)
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
]

# Accept-Language variations
ACCEPT_LANGUAGE_POOL = [
    "en-US,en;q=0.9",
    "en-GB,en;q=0.9",
    "de-DE,de;q=0.9,en;q=0.8",
    "fr-FR,fr;q=0.9,en;q=0.8",
    "es-ES,es;q=0.9,en;q=0.8",
    "ja-JP,ja;q=0.9,en;q=0.8",
    "zh-CN,zh;q=0.9,en;q=0.8",
]

# Accept-Encoding variations
ACCEPT_ENCODING_POOL = [
    "gzip, deflate, br",
    "gzip, deflate",
    "gzip",
    "identity",
    "br, gzip, deflate",
]


@dataclass
class VantagePoint:
    """Represents a simulated different user/client."""
    
    name: str
    user_agent: str
    accept_language: str
    accept_encoding: str
    extra_headers: dict[str, str] = field(default_factory=dict)
    
    def get_headers(self) -> dict[str, str]:
        """Get all headers for this vantage point."""
        headers = {
            "User-Agent": self.user_agent,
            "Accept-Language": self.accept_language,
            "Accept-Encoding": self.accept_encoding,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            # No cookies - fresh session
            "Cache-Control": "no-cache",  # Tell browser not to use local cache
        }
        headers.update(self.extra_headers)
        return headers


@dataclass
class MultiVantageResult:
    """Result of multi-vantage validation."""
    
    marker: str
    url: str
    vantage_points_tested: int
    vantage_points_affected: int
    is_globally_cached: bool
    confidence: str  # "high", "medium", "low", "none"
    details: list[dict[str, Any]] = field(default_factory=list)
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "marker": self.marker,
            "url": self.url,
            "vantage_points_tested": self.vantage_points_tested,
            "vantage_points_affected": self.vantage_points_affected,
            "is_globally_cached": self.is_globally_cached,
            "confidence": self.confidence,
            "details": self.details,
        }


class MultiVantageValidator:
    """
    Validate that cache poisoning affects multiple different users/sessions.
    
    This is critical for confirming real vulnerabilities vs local artifacts.
    """
    
    def __init__(self, client, num_vantage_points: int = 5):
        """
        Initialize multi-vantage validator.
        
        Args:
            client: AsyncHTTPClient instance
            num_vantage_points: Number of different clients to simulate
        """
        self.client = client
        self.num_vantage_points = num_vantage_points
    
    def _generate_vantage_points(self, count: int) -> list[VantagePoint]:
        """Generate diverse vantage points for testing."""
        vantage_points = []
        
        # Ensure we use different User-Agents
        user_agents = random.sample(
            USER_AGENT_POOL,
            min(count, len(USER_AGENT_POOL))
        )
        
        for i, ua in enumerate(user_agents):
            # Randomize other headers too
            vantage_points.append(VantagePoint(
                name=f"vantage_{i+1}",
                user_agent=ua,
                accept_language=random.choice(ACCEPT_LANGUAGE_POOL),
                accept_encoding=random.choice(ACCEPT_ENCODING_POOL),
                extra_headers={
                    # Add randomized non-essential headers
                    "X-Request-ID": secrets.token_hex(8),
                    "DNT": random.choice(["0", "1"]),
                },
            ))
        
        return vantage_points
    
    async def validate(
        self,
        url: str,
        marker: str,
        delay_between_tests: float = 0.5,
    ) -> MultiVantageResult:
        """
        Validate that poisoning is visible from multiple vantage points.
        
        Args:
            url: The URL to test
            marker: The poisoning marker to look for
            delay_between_tests: Delay between vantage point tests
            
        Returns:
            MultiVantageResult with validation details
        """
        vantage_points = self._generate_vantage_points(self.num_vantage_points)
        details = []
        affected_count = 0
        
        for vp in vantage_points:
            # Small delay between tests
            await asyncio.sleep(delay_between_tests)
            
            # Make request from this vantage point
            response = await self.client.get(
                url,
                headers=vp.get_headers(),
            )
            
            if response.error:
                details.append({
                    "vantage_point": vp.name,
                    "user_agent": vp.user_agent[:50] + "...",
                    "marker_found": False,
                    "error": response.error,
                })
                continue
            
            # Check for marker in response
            marker_found = marker.lower() in response.body.lower()
            
            # Check cache status
            cache_hit = self._check_cache_hit(response)
            
            details.append({
                "vantage_point": vp.name,
                "user_agent": vp.user_agent[:50] + "...",
                "marker_found": marker_found,
                "cache_hit": cache_hit,
                "status_code": response.status_code,
                "response_time_ms": response.elapsed_ms,
            })
            
            if marker_found:
                affected_count += 1
        
        # Determine confidence based on how many vantage points see the poisoning
        total = len(vantage_points)
        ratio = affected_count / total if total > 0 else 0
        
        if ratio >= 0.8:  # 80%+ affected
            confidence = "high"
            is_global = True
        elif ratio >= 0.5:  # 50%+ affected
            confidence = "medium"
            is_global = True
        elif ratio >= 0.2:  # At least some affected
            confidence = "low"
            is_global = False
        else:
            confidence = "none"
            is_global = False
        
        return MultiVantageResult(
            marker=marker,
            url=url,
            vantage_points_tested=total,
            vantage_points_affected=affected_count,
            is_globally_cached=is_global,
            confidence=confidence,
            details=details,
        )
    
    async def quick_validate(
        self,
        url: str,
        marker: str,
        min_affected: int = 2,
    ) -> bool:
        """
        Quick validation that poisoning is global.
        
        Returns True if at least min_affected vantage points see the marker.
        """
        vantage_points = self._generate_vantage_points(3)  # Quick test with 3
        affected = 0
        
        for vp in vantage_points:
            response = await self.client.get(url, headers=vp.get_headers())
            
            if not response.error and marker.lower() in response.body.lower():
                affected += 1
                if affected >= min_affected:
                    return True
            
            await asyncio.sleep(0.3)
        
        return affected >= min_affected
    
    def _check_cache_hit(self, response) -> bool:
        """Check if response indicates cache hit."""
        hit_headers = {
            "x-cache": ["hit"],
            "cf-cache-status": ["hit", "stale"],
            "x-cache-status": ["hit"],
            "age": None,  # Any positive age
        }
        
        for header, values in hit_headers.items():
            header_value = response.get_header(header, "").lower()
            
            if header == "age":
                if header_value.isdigit() and int(header_value) > 0:
                    return True
            elif values and any(v in header_value for v in values):
                return True
        
        return False
    
    async def test_session_isolation(
        self,
        url: str,
        marker: str,
    ) -> dict[str, Any]:
        """
        Test if poisoning crosses session boundaries.
        
        This verifies that the cache poisoning affects users
        without the attacker's session/cookies.
        """
        results = {
            "fresh_session_affected": False,
            "different_browser_affected": False,
            "mobile_affected": False,
        }
        
        # Test 1: Completely fresh session (no cookies, different UA)
        fresh_headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Fresh/1.0",
            "Accept": "text/html",
            # Explicitly no Cookie header
        }
        response = await self.client.get(url, headers=fresh_headers)
        if not response.error and marker.lower() in response.body.lower():
            results["fresh_session_affected"] = True
        
        # Test 2: Different browser type
        await asyncio.sleep(0.5)
        firefox_headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
            "Accept": "text/html,application/xhtml+xml",
        }
        response = await self.client.get(url, headers=firefox_headers)
        if not response.error and marker.lower() in response.body.lower():
            results["different_browser_affected"] = True
        
        # Test 3: Mobile user
        await asyncio.sleep(0.5)
        mobile_headers = {
            "User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 Mobile",
            "Accept": "text/html",
        }
        response = await self.client.get(url, headers=mobile_headers)
        if not response.error and marker.lower() in response.body.lower():
            results["mobile_affected"] = True
        
        return results
