"""Enhanced multi-stage false positive validation for cache poisoning detection.

This module implements a 7-stage validation pipeline:
1. Cache Key Oracle - Verify header/param is NOT in cache key
2. Reflection Check - Verify marker in exploitable context
3. Persistence Check - Multi-checkpoint time-based validation
4. Multi-Session Check - Different clients see poisoned response
5. Origin Comparison - Cache poisoned but origin clean
6. Cache Headers Check - Strict cacheability validation
7. Content Analysis - Marker in meaningful/exploitable context

All 7 pass = HIGH confidence (definitely vulnerable)
5-6 pass = MEDIUM confidence (likely vulnerable)
3-4 pass = LOW confidence (needs manual review)
<3 pass = REJECTED (false positive)
"""

import asyncio
import re
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any

from config import (
    CACHEABLE_STATUS_CODES,
    NO_CACHE_DIRECTIVES,
    VERIFICATION_ROUNDS,
)
from .detector import DetectionResult
from .http_client import AsyncHTTPClient
from .cache_fingerprint import CacheFingerprinter, CacheInfo


class ValidationStatus(Enum):
    """Status of validation check."""
    PASSED = auto()
    FAILED = auto()
    SKIPPED = auto()
    WARNING = auto()


@dataclass
class ValidationCheck:
    """Result of a single validation check."""
    
    name: str
    stage: int  # 1-7
    status: ValidationStatus
    message: str
    is_critical: bool = False  # Critical checks must pass
    details: dict[str, Any] | None = None
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "stage": self.stage,
            "status": self.status.name.lower(),
            "message": self.message,
            "is_critical": self.is_critical,
            "details": self.details,
        }


@dataclass
class ValidationReport:
    """Complete validation report for a detection result."""
    
    checks: list[ValidationCheck]
    stages_passed: int
    total_stages: int
    is_valid: bool
    confidence_adjustment: int
    final_confidence: str
    summary: str
    rejection_reasons: list[str] = field(default_factory=list)
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "checks": [c.to_dict() for c in self.checks],
            "stages_passed": self.stages_passed,
            "total_stages": self.total_stages,
            "is_valid": self.is_valid,
            "confidence_adjustment": self.confidence_adjustment,
            "final_confidence": self.final_confidence,
            "summary": self.summary,
            "rejection_reasons": self.rejection_reasons,
        }


class Validator:
    """
    Enhanced 7-stage validation pipeline for cache poisoning detection.
    
    Validation Stages:
    1. CACHE KEY ORACLE - Header/param confirmed NOT in cache key
    2. REFLECTION CHECK - Canary appears in response body in exploitable context
    3. PERSISTENCE CHECK - Multi-checkpoint time-based validation (2s, 5s, 10s)
    4. MULTI-SESSION CHECK - Different User-Agent/session sees poisoned response
    5. ORIGIN COMPARISON - Cache-bypassed request returns clean response
    6. CACHE HEADERS CHECK - Response is explicitly public cacheable
    7. CONTENT ANALYSIS - Marker in meaningful/exploitable context
    """
    
    TOTAL_STAGES = 7
    
    def __init__(
        self,
        client: AsyncHTTPClient | None = None,
        strict_mode: bool = True,
        min_stages_to_pass: int = 5,
    ):
        """
        Initialize enhanced validator.
        
        Args:
            client: HTTP client for additional verification requests
            strict_mode: If True, require critical checks to pass
            min_stages_to_pass: Minimum stages that must pass for validity
        """
        self.client = client
        self.strict_mode = strict_mode
        self.min_stages_to_pass = min_stages_to_pass
        self._fingerprinter = CacheFingerprinter()
        
        # Lazy-loaded validators
        self._cache_key_oracle = None
        self._multi_vantage = None
        self._origin_bypass = None
        self._content_analyzer = None
    
    def _get_cache_key_oracle(self):
        """Lazy load cache key oracle."""
        if self._cache_key_oracle is None:
            from .cache_key_oracle import CacheKeyOracle
            self._cache_key_oracle = CacheKeyOracle(self.client)
        return self._cache_key_oracle
    
    def _get_multi_vantage(self):
        """Lazy load multi-vantage validator."""
        if self._multi_vantage is None:
            from .multi_vantage import MultiVantageValidator
            self._multi_vantage = MultiVantageValidator(self.client)
        return self._multi_vantage
    
    def _get_origin_bypass(self):
        """Lazy load origin bypass comparator."""
        if self._origin_bypass is None:
            from .origin_bypass import OriginBypassComparator
            self._origin_bypass = OriginBypassComparator(self.client)
        return self._origin_bypass
    
    def _get_content_analyzer(self):
        """Lazy load content analyzer."""
        if self._content_analyzer is None:
            from .content_analyzer import ContentAnalyzer
            self._content_analyzer = ContentAnalyzer()
        return self._content_analyzer
    
    async def validate(
        self,
        result: DetectionResult,
        full_validation: bool = True,
    ) -> ValidationReport:
        """
        Perform comprehensive 7-stage validation on a detection result.
        
        Args:
            result: The detection result to validate
            full_validation: Whether to run all stages (requires HTTP client)
            
        Returns:
            ValidationReport with all check results
        """
        checks = []
        rejection_reasons = []
        
        # Stage 1: Cache Key Oracle (requires client)
        if full_validation and self.client:
            stage1 = await self._validate_cache_key_oracle(result)
        else:
            stage1 = ValidationCheck(
                name="cache_key_oracle",
                stage=1,
                status=ValidationStatus.SKIPPED,
                message="Cache key oracle requires HTTP client",
            )
        checks.append(stage1)
        if stage1.status == ValidationStatus.FAILED:
            rejection_reasons.append("Header/param is part of cache key")
        
        # Stage 2: Reflection Check
        stage2 = self._validate_reflection(result)
        checks.append(stage2)
        if stage2.status == ValidationStatus.FAILED:
            rejection_reasons.append("Marker not reflected in response")
        
        # Stage 3: Persistence Check (multi-checkpoint)
        if full_validation and self.client:
            stage3 = await self._validate_persistence_multi_checkpoint(result)
        else:
            stage3 = self._validate_persistence_basic(result)
        checks.append(stage3)
        if stage3.status == ValidationStatus.FAILED:
            rejection_reasons.append("Marker did not persist in cache")
        
        # Stage 4: Multi-Session Check (requires client)
        if full_validation and self.client:
            stage4 = await self._validate_multi_session(result)
        else:
            stage4 = ValidationCheck(
                name="multi_session",
                stage=4,
                status=ValidationStatus.SKIPPED,
                message="Multi-session check requires HTTP client",
            )
        checks.append(stage4)
        if stage4.status == ValidationStatus.FAILED:
            rejection_reasons.append("Poisoning not visible to other sessions")
        
        # Stage 5: Origin Comparison (requires client)
        if full_validation and self.client:
            stage5 = await self._validate_origin_comparison(result)
        else:
            stage5 = ValidationCheck(
                name="origin_comparison",
                stage=5,
                status=ValidationStatus.SKIPPED,
                message="Origin comparison requires HTTP client",
            )
        checks.append(stage5)
        if stage5.status == ValidationStatus.FAILED:
            rejection_reasons.append("Origin also contains marker (not cache-specific)")
        
        # Stage 6: Cache Headers Check
        stage6 = self._validate_cache_headers_strict(result)
        checks.append(stage6)
        if stage6.status == ValidationStatus.FAILED:
            rejection_reasons.append("Response not cacheable by shared caches")
        
        # Stage 7: Content Analysis
        stage7 = self._validate_content_context(result)
        checks.append(stage7)
        if stage7.status == ValidationStatus.FAILED:
            rejection_reasons.append("Marker not in exploitable context")
        
        # Calculate final status
        stages_passed = sum(
            1 for c in checks
            if c.status == ValidationStatus.PASSED
        )
        
        # Check critical failures in strict mode
        critical_failed = any(
            c.status == ValidationStatus.FAILED and c.is_critical
            for c in checks
        )
        
        # Determine validity
        if self.strict_mode and critical_failed:
            is_valid = False
        elif stages_passed >= self.min_stages_to_pass:
            is_valid = True
        elif stages_passed >= 3:
            is_valid = True  # Low confidence but valid
        else:
            is_valid = False
        
        # Calculate confidence adjustment
        confidence_adjustment = self._calculate_confidence_adjustment(checks, stages_passed)
        
        # Adjust confidence
        final_confidence = self._adjust_confidence(
            result.confidence,
            confidence_adjustment,
            stages_passed,
        )
        
        # Generate summary
        summary = self._generate_summary(
            checks, is_valid, final_confidence, stages_passed, rejection_reasons
        )
        
        return ValidationReport(
            checks=checks,
            stages_passed=stages_passed,
            total_stages=self.TOTAL_STAGES,
            is_valid=is_valid,
            confidence_adjustment=confidence_adjustment,
            final_confidence=final_confidence,
            summary=summary,
            rejection_reasons=rejection_reasons,
        )
    
    async def _validate_cache_key_oracle(self, result: DetectionResult) -> ValidationCheck:
        """Stage 1: Verify the input is NOT part of cache key."""
        try:
            oracle = self._get_cache_key_oracle()
            
            header_name = result.payload.header_name
            if not header_name:
                return ValidationCheck(
                    name="cache_key_oracle",
                    stage=1,
                    status=ValidationStatus.SKIPPED,
                    message="No header to test for cache key",
                )
            
            # Quick check if header is in cache key
            is_exploitable = await oracle.quick_check_header(result.url, header_name)
            
            if is_exploitable:
                return ValidationCheck(
                    name="cache_key_oracle",
                    stage=1,
                    status=ValidationStatus.PASSED,
                    is_critical=True,
                    message=f"Confirmed: {header_name} is NOT in cache key",
                    details={"header": header_name, "in_cache_key": False},
                )
            else:
                return ValidationCheck(
                    name="cache_key_oracle",
                    stage=1,
                    status=ValidationStatus.FAILED,
                    is_critical=True,
                    message=f"Header {header_name} appears to be IN cache key",
                    details={"header": header_name, "in_cache_key": True},
                )
                
        except Exception as e:
            return ValidationCheck(
                name="cache_key_oracle",
                stage=1,
                status=ValidationStatus.WARNING,
                message=f"Cache key oracle error: {str(e)}",
            )
    
    def _validate_reflection(self, result: DetectionResult) -> ValidationCheck:
        """Stage 2: Verify marker is reflected in response."""
        if not result.marker_reflected:
            return ValidationCheck(
                name="reflection_check",
                stage=2,
                status=ValidationStatus.FAILED,
                is_critical=True,
                message="Marker not reflected in response",
                details={"marker": result.payload.marker},
            )
        
        return ValidationCheck(
            name="reflection_check",
            stage=2,
            status=ValidationStatus.PASSED,
            is_critical=True,
            message="Marker successfully reflected in response",
            details={"marker": result.payload.marker},
        )
    
    def _validate_persistence_basic(self, result: DetectionResult) -> ValidationCheck:
        """Stage 3 (basic): Validate persistence without additional requests."""
        persistence_count = result.persistence_count
        total_rounds = VERIFICATION_ROUNDS
        
        if persistence_count == 0:
            return ValidationCheck(
                name="persistence_check",
                stage=3,
                status=ValidationStatus.FAILED,
                is_critical=True,
                message="Marker did not persist in any verification request",
                details={"persistence_count": 0, "total_rounds": total_rounds},
            )
        
        if persistence_count >= total_rounds:
            return ValidationCheck(
                name="persistence_check",
                stage=3,
                status=ValidationStatus.PASSED,
                is_critical=True,
                message=f"Marker persisted in all {total_rounds} verification requests",
                details={"persistence_count": persistence_count, "total_rounds": total_rounds},
            )
        
        if persistence_count >= 2:
            return ValidationCheck(
                name="persistence_check",
                stage=3,
                status=ValidationStatus.WARNING,
                message=f"Marker persisted in {persistence_count}/{total_rounds} requests",
                details={"persistence_count": persistence_count, "total_rounds": total_rounds},
            )
        
        return ValidationCheck(
            name="persistence_check",
            stage=3,
            status=ValidationStatus.FAILED,
            is_critical=True,
            message=f"Insufficient persistence: {persistence_count}/{total_rounds}",
            details={"persistence_count": persistence_count, "total_rounds": total_rounds},
        )
    
    async def _validate_persistence_multi_checkpoint(self, result: DetectionResult) -> ValidationCheck:
        """Stage 3 (enhanced): Multi-checkpoint time-based persistence validation."""
        CHECKPOINTS = [2, 5, 10]  # seconds
        marker = result.payload.marker
        url = result.url
        
        checkpoints_passed = 0
        checkpoint_results = []
        
        for delay in CHECKPOINTS:
            await asyncio.sleep(delay)
            
            response = await self.client.get(url)
            
            if response.error:
                checkpoint_results.append({
                    "delay_seconds": delay,
                    "passed": False,
                    "error": response.error,
                })
                continue
            
            marker_found = marker.lower() in response.body.lower()
            checkpoint_results.append({
                "delay_seconds": delay,
                "passed": marker_found,
                "cache_hit": self._check_cache_hit(response),
            })
            
            if marker_found:
                checkpoints_passed += 1
        
        total_checkpoints = len(CHECKPOINTS)
        
        if checkpoints_passed >= total_checkpoints:
            return ValidationCheck(
                name="persistence_multi_checkpoint",
                stage=3,
                status=ValidationStatus.PASSED,
                is_critical=True,
                message=f"Marker persisted at all {total_checkpoints} checkpoints",
                details={
                    "checkpoints_passed": checkpoints_passed,
                    "total_checkpoints": total_checkpoints,
                    "checkpoint_results": checkpoint_results,
                },
            )
        
        if checkpoints_passed >= 2:
            return ValidationCheck(
                name="persistence_multi_checkpoint",
                stage=3,
                status=ValidationStatus.WARNING,
                message=f"Marker persisted at {checkpoints_passed}/{total_checkpoints} checkpoints",
                details={
                    "checkpoints_passed": checkpoints_passed,
                    "total_checkpoints": total_checkpoints,
                    "checkpoint_results": checkpoint_results,
                },
            )
        
        return ValidationCheck(
            name="persistence_multi_checkpoint",
            stage=3,
            status=ValidationStatus.FAILED,
            is_critical=True,
            message=f"Insufficient persistence: {checkpoints_passed}/{total_checkpoints} checkpoints",
            details={
                "checkpoints_passed": checkpoints_passed,
                "total_checkpoints": total_checkpoints,
                "checkpoint_results": checkpoint_results,
            },
        )
    
    async def _validate_multi_session(self, result: DetectionResult) -> ValidationCheck:
        """Stage 4: Verify poisoning affects different sessions/clients."""
        try:
            validator = self._get_multi_vantage()
            
            vantage_result = await validator.quick_validate(
                result.url,
                result.payload.marker,
                min_affected=2,
            )
            
            if vantage_result:
                return ValidationCheck(
                    name="multi_session",
                    stage=4,
                    status=ValidationStatus.PASSED,
                    message="Poisoning confirmed visible to multiple different clients",
                )
            else:
                return ValidationCheck(
                    name="multi_session",
                    stage=4,
                    status=ValidationStatus.FAILED,
                    message="Poisoning not consistently visible to different clients",
                )
                
        except Exception as e:
            return ValidationCheck(
                name="multi_session",
                stage=4,
                status=ValidationStatus.WARNING,
                message=f"Multi-session validation error: {str(e)}",
            )
    
    async def _validate_origin_comparison(self, result: DetectionResult) -> ValidationCheck:
        """Stage 5: Verify origin returns clean response."""
        try:
            comparator = self._get_origin_bypass()
            
            is_confirmed = await comparator.quick_origin_check(
                result.url,
                result.payload.marker,
            )
            
            if is_confirmed:
                return ValidationCheck(
                    name="origin_comparison",
                    stage=5,
                    status=ValidationStatus.PASSED,
                    message="Confirmed: Cache poisoned, origin clean",
                )
            else:
                return ValidationCheck(
                    name="origin_comparison",
                    stage=5,
                    status=ValidationStatus.WARNING,
                    message="Could not confirm origin vs cache difference",
                )
                
        except Exception as e:
            return ValidationCheck(
                name="origin_comparison",
                stage=5,
                status=ValidationStatus.WARNING,
                message=f"Origin comparison error: {str(e)}",
            )
    
    def _validate_cache_headers_strict(self, result: DetectionResult) -> ValidationCheck:
        """Stage 6: Strict cache header validation."""
        if result.cache_info is None:
            return ValidationCheck(
                name="cache_headers",
                stage=6,
                status=ValidationStatus.WARNING,
                message="No cache info available",
            )
        
        cache_control = result.cache_info.cache_control or ""
        cc_lower = cache_control.lower()
        
        issues = []
        
        # Must NOT have these directives
        if "no-store" in cc_lower:
            issues.append("contains no-store")
        if "private" in cc_lower:
            issues.append("contains private")
        
        # Should have explicit cacheability
        has_explicit_cache = (
            "public" in cc_lower or
            "max-age" in cc_lower or
            "s-maxage" in cc_lower
        )
        
        # Check TTL if available
        max_age = result.cache_info.max_age
        if max_age is not None and max_age < 10:
            issues.append(f"TTL too short ({max_age}s < 10s)")
        
        # Check status code
        if result.baseline_response:
            status = result.baseline_response.status_code
            # Strict: only 200, 301, 302, 304
            if status not in {200, 301, 302, 304}:
                issues.append(f"status code {status} not typically cached")
        
        if issues:
            return ValidationCheck(
                name="cache_headers",
                stage=6,
                status=ValidationStatus.FAILED,
                message=f"Cache headers issues: {', '.join(issues)}",
                details={
                    "cache_control": cache_control,
                    "issues": issues,
                    "max_age": max_age,
                },
            )
        
        if has_explicit_cache:
            return ValidationCheck(
                name="cache_headers",
                stage=6,
                status=ValidationStatus.PASSED,
                message="Response explicitly cacheable by shared caches",
                details={
                    "cache_control": cache_control,
                    "max_age": max_age,
                },
            )
        
        return ValidationCheck(
            name="cache_headers",
            stage=6,
            status=ValidationStatus.WARNING,
            message="No explicit cache directive; heuristic caching possible",
            details={"cache_control": cache_control},
        )
    
    def _validate_content_context(self, result: DetectionResult) -> ValidationCheck:
        """Stage 7: Validate marker is in exploitable context."""
        # Get response body from verification responses
        body = ""
        headers = {}
        
        if result.injection_response and not result.injection_response.error:
            body = result.injection_response.body
            headers = result.injection_response.headers
        elif result.verification_responses:
            for resp in result.verification_responses:
                if not resp.error and result.payload.marker.lower() in resp.body.lower():
                    body = resp.body
                    headers = resp.headers
                    break
        
        if not body:
            return ValidationCheck(
                name="content_context",
                stage=7,
                status=ValidationStatus.SKIPPED,
                message="No response body available for content analysis",
            )
        
        try:
            analyzer = self._get_content_analyzer()
            analysis = analyzer.analyze(body, headers, result.payload.marker)
            
            if analysis.is_exploitable:
                return ValidationCheck(
                    name="content_context",
                    stage=7,
                    status=ValidationStatus.PASSED,
                    message=analysis.exploitation_details,
                    details={
                        "severity": analysis.highest_severity.name,
                        "exploit_type": analysis.primary_exploit_type.name,
                        "contexts_found": len(analysis.contexts),
                    },
                )
            else:
                return ValidationCheck(
                    name="content_context",
                    stage=7,
                    status=ValidationStatus.FAILED,
                    message="Marker not in exploitable context",
                    details={
                        "severity": analysis.highest_severity.name,
                        "contexts_found": len(analysis.contexts),
                    },
                )
                
        except Exception as e:
            return ValidationCheck(
                name="content_context",
                stage=7,
                status=ValidationStatus.WARNING,
                message=f"Content analysis error: {str(e)}",
            )
    
    def _check_cache_hit(self, response) -> bool:
        """Check if response indicates cache hit."""
        hit_headers = ["x-cache", "cf-cache-status", "x-cache-status"]
        
        for header in hit_headers:
            value = response.get_header(header, "").lower()
            if "hit" in value:
                return True
        
        age = response.get_header("age", "")
        if age.isdigit() and int(age) > 0:
            return True
        
        return False
    
    def _calculate_confidence_adjustment(
        self,
        checks: list[ValidationCheck],
        stages_passed: int,
    ) -> int:
        """Calculate confidence adjustment based on validation results."""
        adjustment = 0
        
        # Base adjustment on stages passed
        if stages_passed >= 7:
            adjustment = 2
        elif stages_passed >= 5:
            adjustment = 1
        elif stages_passed >= 3:
            adjustment = 0
        else:
            adjustment = -2
        
        # Penalties for critical failures
        critical_failures = sum(
            1 for c in checks
            if c.status == ValidationStatus.FAILED and c.is_critical
        )
        adjustment -= critical_failures
        
        # Warnings reduce slightly
        warnings = sum(1 for c in checks if c.status == ValidationStatus.WARNING)
        if warnings >= 3:
            adjustment -= 1
        
        return max(-2, min(2, adjustment))
    
    def _adjust_confidence(
        self,
        original: str,
        adjustment: int,
        stages_passed: int,
    ) -> str:
        """Adjust confidence level based on validation results."""
        # Override based on stages
        if stages_passed >= 7:
            return "high"
        elif stages_passed >= 5:
            return "medium" if adjustment >= 0 else "low"
        elif stages_passed >= 3:
            return "low"
        else:
            return "none"
    
    def _generate_summary(
        self,
        checks: list[ValidationCheck],
        is_valid: bool,
        final_confidence: str,
        stages_passed: int,
        rejection_reasons: list[str],
    ) -> str:
        """Generate a human-readable summary."""
        if is_valid:
            if final_confidence == "high":
                return f"CONFIRMED: {stages_passed}/{self.TOTAL_STAGES} stages passed. High confidence cache poisoning."
            elif final_confidence == "medium":
                return f"LIKELY: {stages_passed}/{self.TOTAL_STAGES} stages passed. Medium confidence."
            else:
                return f"POSSIBLE: {stages_passed}/{self.TOTAL_STAGES} stages passed. Manual review recommended."
        else:
            reasons = "; ".join(rejection_reasons[:3]) if rejection_reasons else "Multiple checks failed"
            return f"REJECTED: {stages_passed}/{self.TOTAL_STAGES} stages passed. Reason: {reasons}"
    
    def quick_validate(self, result: DetectionResult) -> bool:
        """
        Quick synchronous validation without HTTP requests.
        
        Returns True if result passes basic validation.
        """
        # Must have marker reflected and persisted
        if not result.marker_reflected or not result.marker_persisted:
            return False
        
        # Must have valid status code
        if result.baseline_response:
            if result.baseline_response.status_code not in CACHEABLE_STATUS_CODES:
                return False
        
        # Must have reasonable persistence
        if result.persistence_count < 2:
            return False
        
        # Must have cache confirmation
        if not result.cache_hit_confirmed:
            return False
        
        return True
