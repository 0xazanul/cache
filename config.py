"""Configuration constants for the cache poisoning scanner.

Enhanced configuration with:
- Stricter cache validation requirements
- Multi-checkpoint persistence settings
- Confidence scoring thresholds
- False positive prevention parameters
"""

from typing import Final

# =============================================================================
# HTTP Client Settings
# =============================================================================
DEFAULT_TIMEOUT: Final[int] = 10
DEFAULT_CONCURRENCY: Final[int] = 50
DEFAULT_DOMAIN_CONCURRENCY: Final[int] = 10
DEFAULT_DELAY: Final[float] = 0.1
MAX_RETRIES: Final[int] = 3
BACKOFF_FACTOR: Final[float] = 2.0

# =============================================================================
# Basic Validation Settings
# =============================================================================
CACHE_PROPAGATION_DELAY: Final[float] = 2.0
VERIFICATION_ROUNDS: Final[int] = 3
CACHE_HIT_THRESHOLD_MS: Final[int] = 50

# =============================================================================
# Enhanced Multi-Checkpoint Persistence Settings
# =============================================================================
# Time checkpoints for persistence validation (in seconds)
PERSISTENCE_CHECKPOINTS: Final[list] = [2, 5, 10, 30]

# Minimum checkpoints that must pass for each confidence level
MIN_CHECKPOINTS_HIGH: Final[int] = 4    # All checkpoints for high confidence
MIN_CHECKPOINTS_MEDIUM: Final[int] = 3  # 3+ checkpoints for medium
MIN_CHECKPOINTS_LOW: Final[int] = 2     # 2+ checkpoints for low

# =============================================================================
# Strict Cache Requirements (for --strict mode)
# =============================================================================
STRICT_CACHE_REQUIREMENTS: Final[dict] = {
    # Status codes that are reliably cacheable
    "status_codes": frozenset({200, 301, 302, 304}),
    
    # Must have at least one of these directives
    "must_have_one": ["public", "s-maxage", "max-age"],
    
    # Must NOT have any of these directives
    "must_not_have": ["private", "no-store"],
    
    # Minimum TTL in seconds for shared caching
    "min_ttl_seconds": 10,
    
    # Maximum TTL to consider (very long TTLs might be config errors)
    "max_ttl_seconds": 86400 * 7,  # 7 days
}

# =============================================================================
# Confidence Scoring Thresholds
# =============================================================================
CONFIDENCE_THRESHOLDS: Final[dict] = {
    "high": {
        "min_score": 8,
        "min_checkpoints": 4,
        "requires_cache_hit": True,
        "requires_multi_session": True,
    },
    "medium": {
        "min_score": 5,
        "min_checkpoints": 2,
        "requires_cache_hit": True,
        "requires_multi_session": False,
    },
    "low": {
        "min_score": 3,
        "min_checkpoints": 1,
        "requires_cache_hit": False,
        "requires_multi_session": False,
    },
}

# =============================================================================
# 7-Stage Validation Settings
# =============================================================================
VALIDATION_STAGES: Final[dict] = {
    1: {"name": "cache_key_oracle", "critical": True},
    2: {"name": "reflection_check", "critical": True},
    3: {"name": "persistence_check", "critical": True},
    4: {"name": "multi_session", "critical": False},
    5: {"name": "origin_comparison", "critical": False},
    6: {"name": "cache_headers", "critical": True},
    7: {"name": "content_context", "critical": False},
}

# Minimum stages to pass for validity
MIN_STAGES_STRICT: Final[int] = 6
MIN_STAGES_NORMAL: Final[int] = 5
MIN_STAGES_LAX: Final[int] = 3

# =============================================================================
# Marker/Canary Token Settings
# =============================================================================
MARKER_PREFIX: Final[str] = "cp-scan-"
MARKER_LENGTH: Final[int] = 8

# Enhanced marker version (cpv2 format)
MARKER_VERSION: Final[str] = "cpv2"
MARKER_DOMAIN_HASH_LENGTH: Final[int] = 4
MARKER_TIMESTAMP_LENGTH: Final[int] = 8
MARKER_RANDOM_LENGTH: Final[int] = 8

# =============================================================================
# Cacheable Status Codes (RFC 7231 / RFC 9110)
# =============================================================================
# Full set of cacheable status codes
CACHEABLE_STATUS_CODES: Final[frozenset] = frozenset({
    200, 203, 204, 206,
    300, 301, 302, 303, 307, 308,
    404, 405, 410, 414,
    501
})

# Strict set (most commonly cached)
STRICT_CACHEABLE_STATUS_CODES: Final[frozenset] = frozenset({
    200, 301, 302, 304
})

# =============================================================================
# Cache Hit Detection Headers
# =============================================================================
CACHE_HIT_HEADERS: Final[dict] = {
    "x-cache": ["hit", "hit from"],
    "cf-cache-status": ["hit", "stale", "revalidated"],
    "x-cache-status": ["hit"],
    "x-varnish-cache": ["hit"],
    "x-proxy-cache": ["hit"],
    "x-drupal-cache": ["hit"],
    "x-rack-cache": ["hit", "fresh"],
    "fastly-cache-status": ["hit"],
    "akamai-cache-status": ["hit"],
}

# Cache miss indicators (for origin comparison)
CACHE_MISS_HEADERS: Final[dict] = {
    "x-cache": ["miss"],
    "cf-cache-status": ["miss", "bypass", "dynamic", "expired"],
    "x-cache-status": ["miss", "bypass"],
    "fastly-cache-status": ["miss", "pass"],
}

# =============================================================================
# Cache-Control Directives
# =============================================================================
# Directives that prevent shared caching
NO_CACHE_DIRECTIVES: Final[frozenset] = frozenset({
    "private",
    "no-store",
    "no-cache",
})

# Directives that explicitly allow shared caching
PUBLIC_CACHE_DIRECTIVES: Final[frozenset] = frozenset({
    "public",
    "s-maxage",
})

# =============================================================================
# Unkeyed Headers to Test (Attack Vectors)
# =============================================================================
UNKEYED_HEADERS: Final[list] = [
    # Forwarding headers (highest priority)
    "X-Forwarded-Host",
    "X-Forwarded-Scheme",
    "X-Forwarded-Proto",
    "X-Forwarded-Server",
    "X-Forwarded-For",
    "X-Forwarded-Port",
    
    # URL rewriting
    "X-Original-URL",
    "X-Rewrite-URL",
    "X-Original-Host",
    
    # Host variations
    "X-Host",
    "X-HTTP-Host-Override",
    "Forwarded",
    
    # Method override
    "X-HTTP-Method-Override",
    "X-HTTP-Method",
    "X-Method-Override",
    
    # Client IP headers
    "X-Requested-With",
    "X-Custom-IP-Authorization",
    "True-Client-IP",
    "Client-IP",
    "X-Real-IP",
    "X-Client-IP",
    "CF-Connecting-IP",
    "Fastly-Client-IP",
    
    # Debug/internal
    "X-Debug",
    "X-Forwarded-SSL",
    "X-URL-Scheme",
    
    # Additional vectors
    "X-Forwarded-Prefix",
    "X-Original-Forwarded-For",
    "X-ProxyUser-Ip",
    "X-Remote-IP",
    "X-Remote-Addr",
]

# Priority headers (test these first for speed)
PRIORITY_HEADERS: Final[list] = [
    "X-Forwarded-Host",
    "X-Original-URL",
    "X-Rewrite-URL",
    "X-Host",
    "X-Forwarded-Scheme",
    "X-Forwarded-Proto",
]

# =============================================================================
# CDN/Cache Fingerprint Signatures
# =============================================================================
CDN_SIGNATURES: Final[dict] = {
    "cloudflare": {
        "headers": ["cf-ray", "cf-cache-status"],
        "server": ["cloudflare"],
    },
    "akamai": {
        "headers": ["x-akamai-transformed", "akamai-grn"],
        "server": ["akamaighost"],
    },
    "fastly": {
        "headers": ["x-fastly-request-id", "fastly-debug-path"],
        "server": ["fastly"],
    },
    "varnish": {
        "headers": ["x-varnish", "via"],
        "server": ["varnish"],
    },
    "cloudfront": {
        "headers": ["x-amz-cf-id", "x-amz-cf-pop"],
        "server": ["cloudfront", "amazon"],
    },
    "nginx": {
        "headers": [],
        "server": ["nginx"],
    },
    "apache": {
        "headers": [],
        "server": ["apache"],
    },
    "keycdn": {
        "headers": ["x-cache", "x-edge-location"],
        "server": ["keycdn"],
    },
    "stackpath": {
        "headers": ["x-hw"],
        "server": ["stackpath", "highwinds"],
    },
}

# =============================================================================
# User Agents for Requests
# =============================================================================
USER_AGENTS: Final[list] = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
]

# =============================================================================
# Content Analysis Settings
# =============================================================================
# Contexts considered exploitable (for content_analyzer)
EXPLOITABLE_CONTEXTS: Final[dict] = {
    "critical": ["script_content", "script_src", "event_handler"],
    "high": ["href", "src", "action", "formaction"],
    "medium": ["text_content", "meta_content", "style_content"],
    "low": ["html_comment", "hidden_input"],
}

# =============================================================================
# Output/Reporting Settings
# =============================================================================
# Minimum confidence to include in report
MIN_REPORT_CONFIDENCE: Final[str] = "low"

# Include rejected results in detailed output
INCLUDE_REJECTED_IN_REPORT: Final[bool] = False
