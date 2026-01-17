"""JSON reporter with PoC generation for cache poisoning findings."""

import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from scanner.detector import DetectionResult
from scanner.validator import ValidationReport
from scanner.payloads import AttackVector


@dataclass
class Vulnerability:
    """A validated cache poisoning vulnerability."""
    
    domain: str
    url: str
    vector: str
    header_or_param: str | None
    cache_type: str
    confidence: str
    evidence: dict[str, Any]
    poc: dict[str, Any]
    validation: ValidationReport | None
    raw_result: DetectionResult
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "domain": self.domain,
            "url": self.url,
            "vector": self.vector,
            "injection_point": self.header_or_param,
            "cache_type": self.cache_type,
            "confidence": self.confidence,
            "evidence": self.evidence,
            "poc": self.poc,
            "validation": self.validation.to_dict() if self.validation else None,
        }


@dataclass
class ScanReport:
    """Complete scan report."""
    
    scan_metadata: dict[str, Any]
    vulnerabilities: list[Vulnerability]
    statistics: dict[str, Any]
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "scan_metadata": self.scan_metadata,
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
            "statistics": self.statistics,
        }
    
    def to_json(self, indent: int = 2) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=indent, default=str)


class JSONReporter:
    """Generate JSON reports with PoC for cache poisoning vulnerabilities."""
    
    def __init__(self):
        self._start_time: datetime | None = None
        self._end_time: datetime | None = None
        self._total_domains: int = 0
        self._total_urls: int = 0
        self._results: list[DetectionResult] = []
        self._validations: dict[str, ValidationReport] = {}
    
    def start_scan(self, total_domains: int) -> None:
        """Mark the start of a scan."""
        self._start_time = datetime.utcnow()
        self._total_domains = total_domains
        self._results = []
        self._validations = {}
    
    def end_scan(self) -> None:
        """Mark the end of a scan."""
        self._end_time = datetime.utcnow()
    
    def add_result(
        self,
        result: DetectionResult,
        validation: ValidationReport | None = None,
    ) -> None:
        """Add a detection result to the report."""
        self._results.append(result)
        self._total_urls += 1
        
        if validation:
            # Use a unique key for the result
            key = f"{result.url}:{result.payload.marker}"
            self._validations[key] = validation
    
    def generate_poc(self, result: DetectionResult) -> dict[str, Any]:
        """
        Generate a Proof of Concept for a vulnerability.
        
        Args:
            result: The detection result
            
        Returns:
            Dictionary with PoC details
        """
        payload = result.payload
        parsed_url = urlparse(result.url)
        
        # Build the malicious request
        request_lines = [
            f"{payload.method} {parsed_url.path or '/'} HTTP/1.1",
            f"Host: {parsed_url.netloc}",
        ]
        
        # Add payload headers
        for header, value in payload.headers.items():
            request_lines.append(f"{header}: {value}")
        
        # Add standard headers
        request_lines.extend([
            "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "",
        ])
        
        # Add body if present
        if payload.body:
            request_lines.append(payload.body)
        
        raw_request = "\r\n".join(request_lines)
        
        # Build curl command
        curl_parts = ["curl", "-i", "-s"]
        
        for header, value in payload.headers.items():
            # Escape special characters in header value
            escaped_value = value.replace("'", "'\\''")
            curl_parts.append(f"-H '{header}: {escaped_value}'")
        
        if payload.body:
            curl_parts.append(f"-d '{payload.body}'")
        
        if payload.method != "GET":
            curl_parts.append(f"-X {payload.method}")
        
        # Build URL with params if any
        target_url = result.url
        if payload.params:
            params_str = "&".join(f"{k}={v}" for k, v in payload.params.items())
            target_url = f"{result.url}{'&' if '?' in result.url else '?'}{params_str}"
        
        curl_parts.append(f"'{target_url}'")
        curl_command = " ".join(curl_parts)
        
        # Reproduction steps
        steps = [
            f"1. Send the following malicious request to poison the cache:",
            f"   {curl_command}",
            f"2. Wait 2-3 seconds for cache propagation",
            f"3. Access the URL normally (without malicious headers): {result.url}",
            f"4. Observe that the response contains the injected marker: {payload.marker}",
        ]
        
        # Additional notes based on vector type
        notes = []
        
        if payload.vector == AttackVector.UNKEYED_HEADER:
            notes.append(f"The '{payload.header_name}' header is not included in the cache key but affects the response.")
        elif payload.vector == AttackVector.HOST_OVERRIDE:
            notes.append("The Host header can be overridden via proxy headers, allowing cache poisoning.")
        elif payload.vector == AttackVector.UNKEYED_PARAM:
            notes.append(f"The '{payload.param_name}' parameter is ignored in cache key computation.")
        elif payload.vector == AttackVector.METHOD_OVERRIDE:
            notes.append("HTTP method override headers allow treating GET requests as different methods.")
        elif payload.vector == AttackVector.FAT_GET:
            notes.append("The server processes request body in GET requests, which caches may not key on.")
        elif payload.vector == AttackVector.PATH_CONFUSION:
            notes.append("Path normalization differences between cache and origin allow key confusion.")
        
        return {
            "request": raw_request,
            "curl_command": curl_command,
            "steps": steps,
            "notes": notes,
            "marker": payload.marker,
            "verification_url": result.url,
        }
    
    def _create_vulnerability(
        self,
        result: DetectionResult,
    ) -> Vulnerability:
        """Create a Vulnerability object from a DetectionResult."""
        parsed_url = urlparse(result.url)
        
        # Get validation if available
        key = f"{result.url}:{result.payload.marker}"
        validation = self._validations.get(key)
        
        # Determine final confidence
        confidence = result.confidence
        if validation:
            confidence = validation.final_confidence
        
        # Get injection point
        header_or_param = result.payload.header_name or result.payload.param_name
        
        # Get cache type
        cache_type = "unknown"
        if result.cache_info:
            cache_type = result.cache_info.provider.name.lower()
        
        # Build evidence
        evidence = {
            "injected_marker": result.payload.marker,
            "marker_reflected": result.marker_reflected,
            "marker_persisted": result.marker_persisted,
            "cache_hit_confirmed": result.cache_hit_confirmed,
            "persistence_count": result.persistence_count,
            "verification_rounds": len(result.verification_responses),
        }
        
        # Generate PoC
        poc = self.generate_poc(result)
        
        return Vulnerability(
            domain=parsed_url.netloc,
            url=result.url,
            vector=result.payload.vector.name.lower(),
            header_or_param=header_or_param,
            cache_type=cache_type,
            confidence=confidence,
            evidence=evidence,
            poc=poc,
            validation=validation,
            raw_result=result,
        )
    
    def generate_report(self) -> ScanReport:
        """
        Generate the final scan report.
        
        Returns:
            ScanReport object with all findings
        """
        # Filter for actual vulnerabilities
        vulnerable_results = [
            r for r in self._results
            if r.is_vulnerable and r.confidence in ("high", "medium", "low")
        ]
        
        # Apply validation filtering
        validated_vulnerabilities = []
        for result in vulnerable_results:
            key = f"{result.url}:{result.payload.marker}"
            validation = self._validations.get(key)
            
            # If validation exists, use its determination
            if validation and not validation.is_valid:
                continue  # Skip invalid results
            
            vuln = self._create_vulnerability(result)
            validated_vulnerabilities.append(vuln)
        
        # Calculate statistics
        stats = self._calculate_statistics(validated_vulnerabilities)
        
        # Build metadata
        metadata = {
            "start_time": self._start_time.isoformat() + "Z" if self._start_time else None,
            "end_time": self._end_time.isoformat() + "Z" if self._end_time else None,
            "duration_seconds": (
                (self._end_time - self._start_time).total_seconds()
                if self._start_time and self._end_time else None
            ),
            "total_domains": self._total_domains,
            "total_urls_tested": self._total_urls,
            "vulnerable_count": len(validated_vulnerabilities),
            "scanner_version": "1.0.0",
        }
        
        return ScanReport(
            scan_metadata=metadata,
            vulnerabilities=validated_vulnerabilities,
            statistics=stats,
        )
    
    def _calculate_statistics(
        self,
        vulnerabilities: list[Vulnerability],
    ) -> dict[str, Any]:
        """Calculate statistics for the report."""
        stats = {
            "total_vulnerabilities": len(vulnerabilities),
            "by_confidence": {
                "high": 0,
                "medium": 0,
                "low": 0,
            },
            "by_vector": {},
            "by_cache_type": {},
            "unique_domains": len(set(v.domain for v in vulnerabilities)),
        }
        
        for vuln in vulnerabilities:
            # By confidence
            if vuln.confidence in stats["by_confidence"]:
                stats["by_confidence"][vuln.confidence] += 1
            
            # By vector
            if vuln.vector not in stats["by_vector"]:
                stats["by_vector"][vuln.vector] = 0
            stats["by_vector"][vuln.vector] += 1
            
            # By cache type
            if vuln.cache_type not in stats["by_cache_type"]:
                stats["by_cache_type"][vuln.cache_type] = 0
            stats["by_cache_type"][vuln.cache_type] += 1
        
        return stats
    
    def save_report(
        self,
        filepath: str | Path,
        indent: int = 2,
    ) -> None:
        """
        Save the report to a JSON file.
        
        Args:
            filepath: Output file path
            indent: JSON indentation level
        """
        report = self.generate_report()
        
        filepath = Path(filepath)
        filepath.parent.mkdir(parents=True, exist_ok=True)
        
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(report.to_json(indent=indent))
    
    def get_summary(self) -> str:
        """Get a human-readable summary of the scan results."""
        report = self.generate_report()
        
        lines = [
            "=" * 60,
            "CACHE POISONING SCAN SUMMARY",
            "=" * 60,
            f"Total Domains Scanned: {report.scan_metadata['total_domains']}",
            f"Total URLs Tested: {report.scan_metadata['total_urls_tested']}",
            f"Vulnerabilities Found: {report.statistics['total_vulnerabilities']}",
            f"  - High Confidence: {report.statistics['by_confidence']['high']}",
            f"  - Medium Confidence: {report.statistics['by_confidence']['medium']}",
            f"  - Low Confidence: {report.statistics['by_confidence']['low']}",
            "",
            "Vulnerabilities by Vector:",
        ]
        
        for vector, count in report.statistics.get("by_vector", {}).items():
            lines.append(f"  - {vector}: {count}")
        
        lines.extend([
            "",
            "Vulnerabilities by Cache Type:",
        ])
        
        for cache_type, count in report.statistics.get("by_cache_type", {}).items():
            lines.append(f"  - {cache_type}: {count}")
        
        if report.scan_metadata.get("duration_seconds"):
            lines.extend([
                "",
                f"Scan Duration: {report.scan_metadata['duration_seconds']:.2f} seconds",
            ])
        
        lines.append("=" * 60)
        
        return "\n".join(lines)
