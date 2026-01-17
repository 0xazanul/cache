"""Content Context Analyzer - Determine marker location and exploitability.

This module analyzes WHERE in the response the marker appears to determine:
1. Is it in an exploitable context (script, href, src)?
2. What is the potential impact (XSS, redirect, content injection)?
3. Is it just a benign reflection (comment, hidden field)?

Context severity mapping:
- Inside <script> tag -> XSS possible -> Critical
- In href/src attribute -> Redirect/Resource hijack -> High  
- In HTML body text -> Content injection -> Medium
- In HTTP header -> Header injection -> Medium
- In comment/hidden -> Low impact -> Low
- Not reflected meaningfully -> False positive -> None
"""

import re
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any
from html.parser import HTMLParser


class ContextSeverity(Enum):
    """Severity levels based on marker context."""
    CRITICAL = auto()  # XSS possible
    HIGH = auto()      # Redirect/resource hijack
    MEDIUM = auto()    # Content injection
    LOW = auto()       # Minimal impact
    NONE = auto()      # False positive / not exploitable


class ExploitType(Enum):
    """Type of potential exploit."""
    XSS = auto()
    OPEN_REDIRECT = auto()
    RESOURCE_HIJACK = auto()
    CONTENT_INJECTION = auto()
    HEADER_INJECTION = auto()
    LINK_INJECTION = auto()
    META_INJECTION = auto()
    NONE = auto()


@dataclass
class ContextMatch:
    """A single context where marker was found."""
    
    context_type: str
    severity: ContextSeverity
    exploit_type: ExploitType
    position: int
    surrounding_code: str
    tag_name: str | None = None
    attribute_name: str | None = None
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "context_type": self.context_type,
            "severity": self.severity.name.lower(),
            "exploit_type": self.exploit_type.name.lower(),
            "position": self.position,
            "surrounding_code": self.surrounding_code[:200],
            "tag_name": self.tag_name,
            "attribute_name": self.attribute_name,
        }


@dataclass
class ContentAnalysisResult:
    """Result of content context analysis."""
    
    marker: str
    total_occurrences: int
    contexts: list[ContextMatch]
    highest_severity: ContextSeverity
    primary_exploit_type: ExploitType
    is_exploitable: bool
    exploitation_details: str
    header_contexts: list[dict[str, Any]] = field(default_factory=list)
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "marker": self.marker,
            "total_occurrences": self.total_occurrences,
            "contexts": [c.to_dict() for c in self.contexts],
            "highest_severity": self.highest_severity.name.lower(),
            "primary_exploit_type": self.primary_exploit_type.name.lower(),
            "is_exploitable": self.is_exploitable,
            "exploitation_details": self.exploitation_details,
            "header_contexts": self.header_contexts,
        }


class MarkerContextParser(HTMLParser):
    """HTML parser to find marker context."""
    
    def __init__(self, marker: str):
        super().__init__()
        self.marker = marker.lower()
        self.contexts = []
        self.current_tag = None
        self.current_attrs = {}
        self.in_script = False
        self.in_style = False
        self.tag_stack = []
    
    def handle_starttag(self, tag, attrs):
        self.current_tag = tag.lower()
        self.current_attrs = dict(attrs)
        self.tag_stack.append(tag.lower())
        
        if tag.lower() == "script":
            self.in_script = True
        elif tag.lower() == "style":
            self.in_style = True
        
        # Check if marker is in any attribute
        for attr_name, attr_value in attrs:
            if attr_value and self.marker in attr_value.lower():
                self._add_attribute_context(tag, attr_name, attr_value)
    
    def handle_endtag(self, tag):
        if tag.lower() == "script":
            self.in_script = False
        elif tag.lower() == "style":
            self.in_style = False
        
        if self.tag_stack and self.tag_stack[-1] == tag.lower():
            self.tag_stack.pop()
    
    def handle_data(self, data):
        if self.marker in data.lower():
            self._add_data_context(data)
    
    def handle_comment(self, data):
        if self.marker in data.lower():
            self.contexts.append(ContextMatch(
                context_type="html_comment",
                severity=ContextSeverity.LOW,
                exploit_type=ExploitType.NONE,
                position=self.getpos()[0],
                surrounding_code=f"<!--{data[:100]}-->",
            ))
    
    def _add_attribute_context(self, tag: str, attr_name: str, attr_value: str):
        """Add context for marker found in attribute."""
        tag = tag.lower()
        attr_name = attr_name.lower()
        
        # Determine severity based on attribute type
        if attr_name in ("href", "src", "action", "formaction"):
            if tag in ("a", "link"):
                severity = ContextSeverity.HIGH
                exploit_type = ExploitType.OPEN_REDIRECT
            elif tag in ("script", "img", "iframe", "embed", "object"):
                severity = ContextSeverity.CRITICAL
                exploit_type = ExploitType.RESOURCE_HIJACK
            else:
                severity = ContextSeverity.MEDIUM
                exploit_type = ExploitType.LINK_INJECTION
        elif attr_name.startswith("on"):  # Event handlers
            severity = ContextSeverity.CRITICAL
            exploit_type = ExploitType.XSS
        elif attr_name == "style":
            severity = ContextSeverity.MEDIUM
            exploit_type = ExploitType.CONTENT_INJECTION
        elif attr_name in ("content",) and tag == "meta":
            severity = ContextSeverity.MEDIUM
            exploit_type = ExploitType.META_INJECTION
        else:
            severity = ContextSeverity.LOW
            exploit_type = ExploitType.CONTENT_INJECTION
        
        self.contexts.append(ContextMatch(
            context_type=f"attribute_{attr_name}",
            severity=severity,
            exploit_type=exploit_type,
            position=self.getpos()[0],
            surrounding_code=f'<{tag} {attr_name}="{attr_value[:50]}...">',
            tag_name=tag,
            attribute_name=attr_name,
        ))
    
    def _add_data_context(self, data: str):
        """Add context for marker found in text content."""
        if self.in_script:
            self.contexts.append(ContextMatch(
                context_type="script_content",
                severity=ContextSeverity.CRITICAL,
                exploit_type=ExploitType.XSS,
                position=self.getpos()[0],
                surrounding_code=data[:100],
                tag_name="script",
            ))
        elif self.in_style:
            self.contexts.append(ContextMatch(
                context_type="style_content",
                severity=ContextSeverity.LOW,
                exploit_type=ExploitType.CONTENT_INJECTION,
                position=self.getpos()[0],
                surrounding_code=data[:100],
                tag_name="style",
            ))
        else:
            # Regular text content
            parent_tag = self.tag_stack[-1] if self.tag_stack else "body"
            self.contexts.append(ContextMatch(
                context_type="text_content",
                severity=ContextSeverity.MEDIUM,
                exploit_type=ExploitType.CONTENT_INJECTION,
                position=self.getpos()[0],
                surrounding_code=data[:100],
                tag_name=parent_tag,
            ))


class ContentAnalyzer:
    """
    Analyze response content to determine marker context and exploitability.
    
    This is crucial for reducing false positives - a marker that only
    appears in a comment or hidden field is not a real vulnerability.
    """
    
    # Patterns for quick context detection
    CONTEXT_PATTERNS = {
        "script_inline": re.compile(r'<script[^>]*>.*?{marker}.*?</script>', re.IGNORECASE | re.DOTALL),
        "script_src": re.compile(r'<script[^>]*src=["\'][^"\']*{marker}[^"\']*["\']', re.IGNORECASE),
        "href": re.compile(r'href=["\'][^"\']*{marker}[^"\']*["\']', re.IGNORECASE),
        "src": re.compile(r'src=["\'][^"\']*{marker}[^"\']*["\']', re.IGNORECASE),
        "action": re.compile(r'action=["\'][^"\']*{marker}[^"\']*["\']', re.IGNORECASE),
        "event_handler": re.compile(r'on\w+=["\'][^"\']*{marker}[^"\']*["\']', re.IGNORECASE),
        "meta_content": re.compile(r'<meta[^>]*content=["\'][^"\']*{marker}[^"\']*["\']', re.IGNORECASE),
        "comment": re.compile(r'<!--[^>]*{marker}[^>]*-->', re.IGNORECASE),
        "hidden_input": re.compile(r'<input[^>]*type=["\']hidden["\'][^>]*value=["\'][^"\']*{marker}', re.IGNORECASE),
    }
    
    def analyze(
        self,
        body: str,
        headers: dict[str, str],
        marker: str,
    ) -> ContentAnalysisResult:
        """
        Analyze response content to find marker contexts.
        
        Args:
            body: Response body
            headers: Response headers
            marker: The marker to look for
            
        Returns:
            ContentAnalysisResult with context analysis
        """
        contexts = []
        header_contexts = []
        
        # Check headers first
        header_contexts = self._analyze_headers(headers, marker)
        
        # Count total occurrences
        total_occurrences = body.lower().count(marker.lower())
        
        if total_occurrences == 0:
            return ContentAnalysisResult(
                marker=marker,
                total_occurrences=0,
                contexts=[],
                highest_severity=ContextSeverity.NONE,
                primary_exploit_type=ExploitType.NONE,
                is_exploitable=False,
                exploitation_details="Marker not found in response",
                header_contexts=header_contexts,
            )
        
        # Quick pattern matching first
        quick_contexts = self._quick_pattern_analysis(body, marker)
        contexts.extend(quick_contexts)
        
        # Detailed HTML parsing
        try:
            parser = MarkerContextParser(marker)
            parser.feed(body)
            contexts.extend(parser.contexts)
        except Exception:
            # HTML parsing failed, rely on regex patterns
            pass
        
        # Deduplicate contexts by position
        seen_positions = set()
        unique_contexts = []
        for ctx in contexts:
            if ctx.position not in seen_positions:
                seen_positions.add(ctx.position)
                unique_contexts.append(ctx)
        
        # Determine highest severity
        if unique_contexts:
            highest_severity = min(
                (c.severity for c in unique_contexts),
                key=lambda s: s.value
            )
            # Get primary exploit type from highest severity context
            primary_exploit = next(
                (c.exploit_type for c in unique_contexts if c.severity == highest_severity),
                ExploitType.NONE
            )
        else:
            highest_severity = ContextSeverity.NONE
            primary_exploit = ExploitType.NONE
        
        # Determine exploitability
        is_exploitable = highest_severity in (
            ContextSeverity.CRITICAL,
            ContextSeverity.HIGH,
            ContextSeverity.MEDIUM,
        )
        
        # Generate exploitation details
        exploitation_details = self._generate_exploitation_details(
            unique_contexts,
            highest_severity,
            primary_exploit,
        )
        
        return ContentAnalysisResult(
            marker=marker,
            total_occurrences=total_occurrences,
            contexts=unique_contexts,
            highest_severity=highest_severity,
            primary_exploit_type=primary_exploit,
            is_exploitable=is_exploitable,
            exploitation_details=exploitation_details,
            header_contexts=header_contexts,
        )
    
    def _analyze_headers(
        self,
        headers: dict[str, str],
        marker: str,
    ) -> list[dict[str, Any]]:
        """Analyze if marker appears in response headers."""
        header_contexts = []
        marker_lower = marker.lower()
        
        for name, value in headers.items():
            if marker_lower in str(value).lower():
                # Determine severity based on header type
                name_lower = name.lower()
                
                if name_lower in ("location", "refresh"):
                    severity = "high"
                    exploit = "open_redirect"
                elif name_lower in ("set-cookie",):
                    severity = "high"
                    exploit = "cookie_injection"
                elif name_lower in ("content-type", "content-disposition"):
                    severity = "medium"
                    exploit = "header_injection"
                else:
                    severity = "low"
                    exploit = "header_reflection"
                
                header_contexts.append({
                    "header_name": name,
                    "severity": severity,
                    "exploit_type": exploit,
                    "value_preview": str(value)[:100],
                })
        
        return header_contexts
    
    def _quick_pattern_analysis(
        self,
        body: str,
        marker: str,
    ) -> list[ContextMatch]:
        """Quick regex-based context detection."""
        contexts = []
        
        for pattern_name, pattern in self.CONTEXT_PATTERNS.items():
            # Replace {marker} placeholder with actual marker
            regex = re.compile(
                pattern.pattern.replace("{marker}", re.escape(marker)),
                pattern.flags
            )
            
            for match in regex.finditer(body):
                severity, exploit_type = self._get_pattern_severity(pattern_name)
                
                contexts.append(ContextMatch(
                    context_type=pattern_name,
                    severity=severity,
                    exploit_type=exploit_type,
                    position=match.start(),
                    surrounding_code=match.group()[:150],
                ))
        
        return contexts
    
    def _get_pattern_severity(
        self,
        pattern_name: str,
    ) -> tuple[ContextSeverity, ExploitType]:
        """Get severity and exploit type for a pattern match."""
        severity_map = {
            "script_inline": (ContextSeverity.CRITICAL, ExploitType.XSS),
            "script_src": (ContextSeverity.CRITICAL, ExploitType.RESOURCE_HIJACK),
            "event_handler": (ContextSeverity.CRITICAL, ExploitType.XSS),
            "href": (ContextSeverity.HIGH, ExploitType.OPEN_REDIRECT),
            "src": (ContextSeverity.HIGH, ExploitType.RESOURCE_HIJACK),
            "action": (ContextSeverity.HIGH, ExploitType.OPEN_REDIRECT),
            "meta_content": (ContextSeverity.MEDIUM, ExploitType.META_INJECTION),
            "comment": (ContextSeverity.LOW, ExploitType.NONE),
            "hidden_input": (ContextSeverity.LOW, ExploitType.NONE),
        }
        
        return severity_map.get(
            pattern_name,
            (ContextSeverity.MEDIUM, ExploitType.CONTENT_INJECTION)
        )
    
    def _generate_exploitation_details(
        self,
        contexts: list[ContextMatch],
        severity: ContextSeverity,
        exploit_type: ExploitType,
    ) -> str:
        """Generate human-readable exploitation details."""
        if severity == ContextSeverity.NONE:
            return "No exploitable context found"
        
        if severity == ContextSeverity.CRITICAL:
            if exploit_type == ExploitType.XSS:
                return "CRITICAL: Marker found in JavaScript context. Direct XSS possible via cache poisoning."
            elif exploit_type == ExploitType.RESOURCE_HIJACK:
                return "CRITICAL: Marker found in script/resource src. Can load malicious scripts for all users."
        
        if severity == ContextSeverity.HIGH:
            if exploit_type == ExploitType.OPEN_REDIRECT:
                return "HIGH: Marker found in href/action. Can redirect users to malicious sites."
            elif exploit_type == ExploitType.RESOURCE_HIJACK:
                return "HIGH: Marker found in resource URL. Can inject malicious content."
        
        if severity == ContextSeverity.MEDIUM:
            return f"MEDIUM: Marker found in {len(contexts)} location(s). Content injection possible."
        
        if severity == ContextSeverity.LOW:
            return f"LOW: Marker found but only in low-impact contexts (comments, hidden fields)."
        
        return "Unable to determine exploitation potential"
    
    def quick_check_exploitable(
        self,
        body: str,
        marker: str,
    ) -> tuple[bool, str]:
        """
        Quick check if marker is in an exploitable context.
        
        Returns:
            Tuple of (is_exploitable, reason)
        """
        marker_lower = marker.lower()
        body_lower = body.lower()
        
        if marker_lower not in body_lower:
            return False, "Marker not found"
        
        # Check critical contexts
        critical_patterns = [
            (r'<script[^>]*>' + re.escape(marker_lower), "Script content"),
            (r'on\w+=["\'][^"\']*' + re.escape(marker_lower), "Event handler"),
        ]
        
        for pattern, context in critical_patterns:
            if re.search(pattern, body_lower):
                return True, f"Critical: {context}"
        
        # Check high severity contexts
        high_patterns = [
            (r'href=["\'][^"\']*' + re.escape(marker_lower), "href attribute"),
            (r'src=["\'][^"\']*' + re.escape(marker_lower), "src attribute"),
        ]
        
        for pattern, context in high_patterns:
            if re.search(pattern, body_lower):
                return True, f"High: {context}"
        
        # Check if only in comments or hidden fields
        low_only_patterns = [
            r'<!--[^>]*' + re.escape(marker_lower) + r'[^>]*-->',
            r'type=["\']hidden["\'][^>]*' + re.escape(marker_lower),
        ]
        
        # If marker is only in low-impact contexts
        all_low = all(
            re.search(p, body_lower) for p in low_only_patterns
            if re.search(re.escape(marker_lower), body_lower)
        )
        
        if all_low:
            return False, "Only in low-impact context"
        
        # Default: medium severity
        return True, "Medium: Text content"
