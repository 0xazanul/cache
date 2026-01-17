"""Enhanced cache poisoning detection engine with multi-checkpoint persistence."""

import asyncio
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from config import (
    CACHE_PROPAGATION_DELAY,
    VERIFICATION_ROUNDS,
    CACHEABLE_STATUS_CODES,
)
from .http_client import AsyncHTTPClient, HTTPResponse
from .cache_fingerprint import CacheFingerprinter, CacheInfo
from .baseline import BaselineCapture, BaselineResponse
from .payloads import PayloadGenerator, Payload, AttackVector


# Multi-checkpoint persistence delays (in seconds)
PERSISTENCE_CHECKPOINTS = [2, 5, 10, 30]


@dataclass
class CheckpointResult:
    """Result of a single persistence checkpoint."""
    delay_seconds: int
    marker_found: bool
    cache_hit: bool
    response_time_ms: float
    error: str | None = None


@dataclass
class DetectionResult:
    """Result of a cache poisoning detection attempt."""
    
    url: str
    payload: Payload
    is_vulnerable: bool
    confidence: str  # "high", "medium", "low", "none"
    
    # Evidence
    marker_reflected: bool = False
    marker_persisted: bool = False
    cache_hit_confirmed: bool = False
    persistence_count: int = 0
    
    # Enhanced: Multi-checkpoint results
    checkpoint_results: list[CheckpointResult] = field(default_factory=list)
    checkpoints_passed: int = 0
    
    # Response data
    baseline_response: BaselineResponse | None = None
    injection_response: HTTPResponse | None = None
    verification_responses: list[HTTPResponse] = field(default_factory=list)
    
    # Cache info
    cache_info: CacheInfo | None = None
    
    # Timing
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")
    
    # Error if any
    error: str | None = None
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "url": self.url,
            "payload": self.payload.to_dict(),
            "is_vulnerable": self.is_vulnerable,
            "confidence": self.confidence,
            "evidence": {
                "marker_reflected": self.marker_reflected,
                "marker_persisted": self.marker_persisted,
                "cache_hit_confirmed": self.cache_hit_confirmed,
                "persistence_count": self.persistence_count,
                "verification_rounds": len(self.verification_responses),
                "checkpoints_passed": self.checkpoints_passed,
                "checkpoint_results": [
                    {
                        "delay": cp.delay_seconds,
                        "marker_found": cp.marker_found,
                        "cache_hit": cp.cache_hit,
                    }
                    for cp in self.checkpoint_results
                ],
            },
            "cache_info": self.cache_info.to_dict() if self.cache_info else None,
            "timestamp": self.timestamp,
            "error": self.error,
        }


class CachePoisonDetector:
    """
    Enhanced detection engine for cache poisoning vulnerabilities.
    
    Detection flow:
    1. Capture baseline response (clean request)
    2. Send request with payload (injection attempt)
    3. Check if marker is reflected in response
    4. Multi-checkpoint persistence verification (2s, 5s, 10s, 30s)
    5. Confirm cache hit via headers or timing
    6. Apply enhanced validation rules
    
    Enhanced features:
    - Multi-checkpoint time-based persistence validation
    - Stricter confidence scoring
    - Better cache hit detection
    """
    
    def __init__(
        self,
        client: AsyncHTTPClient,
        propagation_delay: float = CACHE_PROPAGATION_DELAY,
        verification_rounds: int = VERIFICATION_ROUNDS,
        use_multi_checkpoint: bool = True,
        checkpoint_delays: list[int] | None = None,
    ):
        """
        Initialize enhanced detector.
        
        Args:
            client: HTTP client for requests
            propagation_delay: Initial delay for cache propagation
            verification_rounds: Number of verification requests
            use_multi_checkpoint: Use multi-checkpoint persistence validation
            checkpoint_delays: Custom checkpoint delays (default: [2, 5, 10, 30])
        """
        self.client = client
        self.propagation_delay = propagation_delay
        self.verification_rounds = verification_rounds
        self.use_multi_checkpoint = use_multi_checkpoint
        self.checkpoint_delays = checkpoint_delays or PERSISTENCE_CHECKPOINTS
        
        self._baseline_capture = BaselineCapture()
        self._fingerprinter = CacheFingerprinter()
        self._payload_generator = PayloadGenerator()
    
    async def detect(
        self,
        url: str,
        payload: Payload,
        quick_mode: bool = False,
    ) -> DetectionResult:
        """
        Test a URL for cache poisoning with a specific payload.
        
        Args:
            url: Target URL
            payload: Payload to test
            quick_mode: Skip multi-checkpoint for speed
            
        Returns:
            DetectionResult with vulnerability assessment
        """
        result = DetectionResult(
            url=url,
            payload=payload,
            is_vulnerable=False,
            confidence="none",
        )
        
        try:
            # Generate a unique test ID for this payload to avoid cache contamination
            # Each payload test gets its own cache slot
            test_id = self._payload_generator.generate_cache_buster()
            test_url = f"{url}{'&' if '?' in url else '?'}_t={test_id}"
            
            # Step 1: Capture baseline (uses different cache buster)
            baseline_response = await self._capture_baseline(url)
            if baseline_response is None:
                result.error = "Failed to capture baseline response"
                return result
            
            result.baseline_response = baseline_response
            result.cache_info = baseline_response.cache_info
            
            # Check if response is cacheable
            if not self._is_response_cacheable(baseline_response):
                result.error = "Response is not cacheable"
                return result
            
            # Step 2: Send injection request to unique test URL
            injection_response = await self._send_injection(test_url, payload)
            if injection_response.error:
                result.error = f"Injection request failed: {injection_response.error}"
                return result
            
            result.injection_response = injection_response
            
            # Step 3: Check for reflection
            comparison = self._baseline_capture.compare(
                baseline_response,
                injection_response,
                payload.marker,
            )
            
            result.marker_reflected = comparison["marker_reflected"]
            
            if not result.marker_reflected:
                # No reflection, not vulnerable to this payload
                return result
            
            # Step 4: Wait for initial cache propagation
            await asyncio.sleep(self.propagation_delay)
            
            # Step 5: Verify persistence at the same test URL (without the header)
            if self.use_multi_checkpoint and not quick_mode:
                # Enhanced: Multi-checkpoint persistence
                persistence_results = await self._verify_persistence_multi_checkpoint(
                    test_url,
                    payload.marker,
                )
                result.checkpoint_results = persistence_results["checkpoint_results"]
                result.checkpoints_passed = persistence_results["checkpoints_passed"]
            else:
                # Standard verification
                persistence_results = await self._verify_persistence_standard(
                    test_url,
                    payload.marker,
                )
            
            result.verification_responses = persistence_results["responses"]
            result.marker_persisted = persistence_results["persisted"]
            result.persistence_count = persistence_results["persistence_count"]
            result.cache_hit_confirmed = persistence_results["cache_hits"]
            
            # Step 6: Determine vulnerability status with enhanced scoring
            result.is_vulnerable, result.confidence = self._assess_vulnerability_enhanced(
                result,
                baseline_response,
            )
            
        except Exception as e:
            result.error = str(e)
        
        return result
    
    async def _capture_baseline(self, url: str) -> BaselineResponse | None:
        """Capture a clean baseline response with cache buster."""
        cache_buster = self._payload_generator.generate_cache_buster()
        buster_url = f"{url}{'&' if '?' in url else '?'}_cb={cache_buster}"
        
        response = await self.client.get(buster_url)
        
        if response.error or response.status_code == 0:
            return None
        
        return self._baseline_capture.capture(response)
    
    async def _send_injection(
        self,
        url: str,
        payload: Payload,
    ) -> HTTPResponse:
        """Send request with payload injected."""
        target_url = self._payload_generator.build_url_with_payload(url, payload)
        headers = dict(payload.headers)
        
        if payload.body:
            return await self.client.request(
                method=payload.method,
                url=target_url,
                headers=headers,
                data=payload.body,
            )
        else:
            return await self.client.get(
                url=target_url,
                headers=headers,
            )
    
    async def _verify_persistence_multi_checkpoint(
        self,
        url: str,
        marker: str,
    ) -> dict[str, Any]:
        """
        Enhanced multi-checkpoint persistence verification.
        
        Tests at multiple time intervals to ensure marker truly persists
        in cache and isn't just a temporary artifact.
        
        Checkpoints: 2s, 5s, 10s, 30s
        """
        responses = []
        checkpoint_results = []
        checkpoints_passed = 0
        cache_hit_count = 0
        total_persistence = 0
        
        for delay in self.checkpoint_delays:
            # Wait for this checkpoint
            await asyncio.sleep(delay)
            
            # Send clean request
            response = await self.client.get(url)
            responses.append(response)
            
            if response.error:
                checkpoint_results.append(CheckpointResult(
                    delay_seconds=delay,
                    marker_found=False,
                    cache_hit=False,
                    response_time_ms=0,
                    error=response.error,
                ))
                continue
            
            # Check for marker
            marker_found = marker.lower() in response.body.lower()
            
            # Check for cache hit
            cache_hit = self._check_cache_hit(response)
            
            checkpoint_results.append(CheckpointResult(
                delay_seconds=delay,
                marker_found=marker_found,
                cache_hit=cache_hit,
                response_time_ms=response.elapsed_ms,
            ))
            
            if marker_found:
                total_persistence += 1
                if cache_hit:
                    checkpoints_passed += 1
                    cache_hit_count += 1
        
        return {
            "responses": responses,
            "persisted": total_persistence > 0,
            "persistence_count": total_persistence,
            "cache_hits": cache_hit_count > 0,
            "cache_hit_count": cache_hit_count,
            "checkpoint_results": checkpoint_results,
            "checkpoints_passed": checkpoints_passed,
        }
    
    async def _verify_persistence_standard(
        self,
        url: str,
        marker: str,
    ) -> dict[str, Any]:
        """
        Standard persistence verification (faster, less thorough).
        """
        responses = []
        persistence_count = 0
        cache_hit_count = 0
        
        for _ in range(self.verification_rounds):
            response = await self.client.get(url)
            responses.append(response)
            
            if response.error:
                continue
            
            if marker.lower() in response.body.lower():
                persistence_count += 1
            
            if self._check_cache_hit(response):
                cache_hit_count += 1
            
            await asyncio.sleep(0.5)
        
        return {
            "responses": responses,
            "persisted": persistence_count > 0,
            "persistence_count": persistence_count,
            "cache_hits": cache_hit_count > 0,
            "cache_hit_count": cache_hit_count,
            "checkpoint_results": [],
            "checkpoints_passed": 0,
        }
    
    def _check_cache_hit(self, response: HTTPResponse) -> bool:
        """Check if response indicates cache hit."""
        # Check cache status headers
        cache_headers = {
            "x-cache": ["hit"],
            "cf-cache-status": ["hit", "stale", "revalidated"],
            "x-cache-status": ["hit"],
            "x-varnish-cache": ["hit"],
            "fastly-cache-status": ["hit"],
            "akamai-cache-status": ["hit"],
            "x-proxy-cache": ["hit"],
        }
        
        for header, hit_values in cache_headers.items():
            value = response.get_header(header, "").lower()
            if any(hv in value for hv in hit_values):
                return True
        
        # Check Age header
        age = response.get_header("age", "")
        if age.isdigit() and int(age) > 0:
            return True
        
        # Check response timing (< 50ms suggests cache)
        if response.elapsed_ms < 50:
            return True
        
        return False
    
    def _is_response_cacheable(self, baseline: BaselineResponse) -> bool:
        """Check if the baseline response is cacheable."""
        if baseline.status_code not in CACHEABLE_STATUS_CODES:
            return False
        
        if not baseline.cache_info.is_cacheable:
            return False
        
        return True
    
    def _assess_vulnerability_enhanced(
        self,
        result: DetectionResult,
        baseline: BaselineResponse,
    ) -> tuple[bool, str]:
        """
        Enhanced vulnerability assessment with stricter criteria.
        
        Scoring:
        - Marker reflected: +1
        - Marker persisted: +2
        - Multiple checkpoints passed: +1 per checkpoint (max +4)
        - Cache hit confirmed: +2
        - Shared cache detected: +1
        - Status 200: +1
        
        Confidence:
        - High: score >= 8
        - Medium: score >= 5
        - Low: score >= 3
        - None: score < 3
        """
        if not result.marker_reflected:
            return False, "none"
        
        if not result.marker_persisted:
            return False, "none"
        
        score = 0
        
        # Base: reflection and persistence
        score += 1  # Reflection
        score += 2  # Persistence
        
        # Multi-checkpoint bonus
        if result.checkpoints_passed > 0:
            # +1 for each checkpoint passed (max 4)
            score += min(result.checkpoints_passed, 4)
        else:
            # Fall back to persistence count
            if result.persistence_count >= self.verification_rounds:
                score += 2
            elif result.persistence_count >= 2:
                score += 1
        
        # Cache hit confirmation
        if result.cache_hit_confirmed:
            score += 2
        
        # Shared cache indicators
        if baseline.cache_info and self._fingerprinter.is_shared_cache(baseline.cache_info):
            score += 1
        
        # Cacheable status code
        if baseline.status_code == 200:
            score += 1
        
        # Explicit cache headers
        if baseline.cache_info and baseline.cache_info.max_age:
            if baseline.cache_info.max_age >= 60:
                score += 1
        
        # Determine confidence
        if score >= 8:
            return True, "high"
        elif score >= 5:
            return True, "medium"
        elif score >= 3:
            return True, "low"
        
        return False, "none"
    
    async def detect_quick(
        self,
        url: str,
        payload: Payload,
    ) -> DetectionResult:
        """
        Quick detection mode - faster but less thorough.
        
        Skips multi-checkpoint validation for speed.
        """
        return await self.detect(url, payload, quick_mode=True)
    
    async def scan_url(
        self,
        url: str,
        payloads: list[Payload] | None = None,
        stop_on_first: bool = False,
    ) -> list[DetectionResult]:
        """
        Scan a URL with multiple payloads.
        
        Args:
            url: Target URL to scan
            payloads: List of payloads to test (or None for all)
            stop_on_first: Stop after finding first vulnerability
            
        Returns:
            List of DetectionResult objects
        """
        if payloads is None:
            payloads = self._payload_generator.generate_all(url)
        
        results = []
        
        for payload in payloads:
            result = await self.detect(url, payload)
            results.append(result)
            
            if result.is_vulnerable and stop_on_first:
                break
        
        return results
    
    async def scan_url_quick(
        self,
        url: str,
        payloads: list[Payload] | None = None,
    ) -> list[DetectionResult]:
        """Quick scan without multi-checkpoint validation."""
        if payloads is None:
            payloads = self._payload_generator.generate_all(url)
        
        results = []
        
        for payload in payloads:
            result = await self.detect_quick(url, payload)
            results.append(result)
        
        return results
    
    async def scan_domain(
        self,
        domain: str,
        paths: list[str] | None = None,
        payloads: list[Payload] | None = None,
    ) -> list[DetectionResult]:
        """
        Scan a domain with optional specific paths.
        
        Args:
            domain: Target domain
            paths: List of paths to test (or None for just root)
            payloads: List of payloads to test (or None for all)
            
        Returns:
            List of DetectionResult objects
        """
        if paths is None:
            paths = ["/"]
        
        scheme = "https"
        results = []
        
        for path in paths:
            url = f"{scheme}://{domain}{path}"
            path_results = await self.scan_url(url, payloads)
            results.extend(path_results)
        
        return results
