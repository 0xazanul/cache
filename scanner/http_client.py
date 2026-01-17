"""Async HTTP client wrapper with rate limiting and retries."""

import asyncio
import random
import time
from dataclasses import dataclass, field
from typing import Any

import httpx

from config import (
    DEFAULT_TIMEOUT,
    DEFAULT_CONCURRENCY,
    DEFAULT_DOMAIN_CONCURRENCY,
    DEFAULT_DELAY,
    MAX_RETRIES,
    BACKOFF_FACTOR,
    USER_AGENTS,
)


@dataclass
class HTTPResponse:
    """Wrapper for HTTP response data."""
    
    url: str
    status_code: int
    headers: dict[str, str]
    body: str
    elapsed_ms: float
    from_cache: bool = False
    request_headers: dict[str, str] = field(default_factory=dict)
    error: str | None = None
    
    @property
    def is_success(self) -> bool:
        return 200 <= self.status_code < 400
    
    def get_header(self, name: str, default: str | None = None) -> str | None:
        """Get header value case-insensitively."""
        name_lower = name.lower()
        for key, value in self.headers.items():
            if key.lower() == name_lower:
                return value
        return default


class RateLimiter:
    """Token bucket rate limiter for controlling request rates."""
    
    def __init__(
        self,
        rate: float = 10.0,  # requests per second
        burst: int = 20,      # max burst size
    ):
        self.rate = rate
        self.burst = burst
        self.tokens = burst
        self.last_update = time.monotonic()
        self._lock = asyncio.Lock()
    
    async def acquire(self) -> None:
        """Acquire a token, waiting if necessary."""
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self.last_update
            self.tokens = min(self.burst, self.tokens + elapsed * self.rate)
            self.last_update = now
            
            if self.tokens < 1:
                wait_time = (1 - self.tokens) / self.rate
                await asyncio.sleep(wait_time)
                self.tokens = 0
            else:
                self.tokens -= 1


class DomainRateLimiter:
    """Per-domain rate limiting."""
    
    def __init__(self, requests_per_second: float = 5.0):
        self._limiters: dict[str, RateLimiter] = {}
        self._rate = requests_per_second
        self._lock = asyncio.Lock()
    
    async def acquire(self, domain: str) -> None:
        """Acquire rate limit token for a specific domain."""
        async with self._lock:
            if domain not in self._limiters:
                self._limiters[domain] = RateLimiter(rate=self._rate, burst=10)
        
        await self._limiters[domain].acquire()


class AsyncHTTPClient:
    """
    Async HTTP client with rate limiting, retries, and connection pooling.
    
    Features:
    - Global and per-domain rate limiting
    - Automatic retries with exponential backoff
    - Connection pooling via httpx
    - Random user agent rotation
    - Configurable timeouts
    """
    
    def __init__(
        self,
        timeout: int = DEFAULT_TIMEOUT,
        max_concurrency: int = DEFAULT_CONCURRENCY,
        domain_concurrency: int = DEFAULT_DOMAIN_CONCURRENCY,
        delay: float = DEFAULT_DELAY,
        max_retries: int = MAX_RETRIES,
        verify_ssl: bool = False,
    ):
        self.timeout = timeout
        self.max_concurrency = max_concurrency
        self.domain_concurrency = domain_concurrency
        self.delay = delay
        self.max_retries = max_retries
        self.verify_ssl = verify_ssl
        
        self._client: httpx.AsyncClient | None = None
        self._global_semaphore = asyncio.Semaphore(max_concurrency)
        self._domain_semaphores: dict[str, asyncio.Semaphore] = {}
        self._domain_rate_limiter = DomainRateLimiter(requests_per_second=1.0 / delay if delay > 0 else 10.0)
        self._lock = asyncio.Lock()
    
    async def __aenter__(self) -> "AsyncHTTPClient":
        """Async context manager entry."""
        await self.start()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        """Async context manager exit."""
        await self.close()
    
    async def start(self) -> None:
        """Initialize the HTTP client."""
        if self._client is None:
            self._client = httpx.AsyncClient(
                timeout=httpx.Timeout(self.timeout),
                verify=self.verify_ssl,
                http2=True,
                follow_redirects=False,  # We want to see redirects
                limits=httpx.Limits(
                    max_connections=self.max_concurrency,
                    max_keepalive_connections=self.max_concurrency // 2,
                ),
            )
    
    async def close(self) -> None:
        """Close the HTTP client."""
        if self._client:
            await self._client.aclose()
            self._client = None
    
    def _get_domain(self, url: str) -> str:
        """Extract domain from URL."""
        from urllib.parse import urlparse
        parsed = urlparse(url)
        return parsed.netloc or parsed.path.split("/")[0]
    
    async def _get_domain_semaphore(self, domain: str) -> asyncio.Semaphore:
        """Get or create per-domain semaphore."""
        async with self._lock:
            if domain not in self._domain_semaphores:
                self._domain_semaphores[domain] = asyncio.Semaphore(self.domain_concurrency)
            return self._domain_semaphores[domain]
    
    def _get_random_user_agent(self) -> str:
        """Get a random user agent."""
        return random.choice(USER_AGENTS)
    
    async def request(
        self,
        method: str,
        url: str,
        headers: dict[str, str] | None = None,
        params: dict[str, str] | None = None,
        data: Any = None,
        json: Any = None,
        follow_redirects: bool = False,
    ) -> HTTPResponse:
        """
        Make an HTTP request with rate limiting and retries.
        
        Args:
            method: HTTP method (GET, POST, etc.)
            url: Target URL
            headers: Optional request headers
            params: Optional query parameters
            data: Optional form data
            json: Optional JSON body
            follow_redirects: Whether to follow redirects
            
        Returns:
            HTTPResponse object with response data
        """
        if self._client is None:
            await self.start()
        
        domain = self._get_domain(url)
        domain_semaphore = await self._get_domain_semaphore(domain)
        
        # Prepare headers
        request_headers = {
            "User-Agent": self._get_random_user_agent(),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
        }
        if headers:
            request_headers.update(headers)
        
        last_error = None
        
        for attempt in range(self.max_retries):
            async with self._global_semaphore:
                async with domain_semaphore:
                    # Apply rate limiting
                    await self._domain_rate_limiter.acquire(domain)
                    
                    try:
                        start_time = time.monotonic()
                        
                        response = await self._client.request(
                            method=method,
                            url=url,
                            headers=request_headers,
                            params=params,
                            data=data,
                            json=json,
                            follow_redirects=follow_redirects,
                        )
                        
                        elapsed_ms = (time.monotonic() - start_time) * 1000
                        
                        # Read body
                        try:
                            body = response.text
                        except Exception:
                            body = ""
                        
                        return HTTPResponse(
                            url=str(response.url),
                            status_code=response.status_code,
                            headers=dict(response.headers),
                            body=body,
                            elapsed_ms=elapsed_ms,
                            request_headers=request_headers,
                        )
                        
                    except httpx.HTTPStatusError as e:
                        # Check if we should retry (429, 503)
                        if e.response.status_code in (429, 503):
                            last_error = str(e)
                            backoff = BACKOFF_FACTOR ** attempt
                            await asyncio.sleep(backoff)
                            continue
                        
                        return HTTPResponse(
                            url=url,
                            status_code=e.response.status_code,
                            headers=dict(e.response.headers),
                            body="",
                            elapsed_ms=0,
                            request_headers=request_headers,
                            error=str(e),
                        )
                        
                    except (httpx.RequestError, Exception) as e:
                        last_error = str(e)
                        if attempt < self.max_retries - 1:
                            backoff = BACKOFF_FACTOR ** attempt
                            await asyncio.sleep(backoff)
                            continue
        
        # All retries exhausted
        return HTTPResponse(
            url=url,
            status_code=0,
            headers={},
            body="",
            elapsed_ms=0,
            request_headers=request_headers,
            error=last_error or "Unknown error",
        )
    
    async def get(
        self,
        url: str,
        headers: dict[str, str] | None = None,
        params: dict[str, str] | None = None,
        follow_redirects: bool = False,
    ) -> HTTPResponse:
        """Make a GET request."""
        return await self.request(
            method="GET",
            url=url,
            headers=headers,
            params=params,
            follow_redirects=follow_redirects,
        )
    
    async def post(
        self,
        url: str,
        headers: dict[str, str] | None = None,
        data: Any = None,
        json: Any = None,
    ) -> HTTPResponse:
        """Make a POST request."""
        return await self.request(
            method="POST",
            url=url,
            headers=headers,
            data=data,
            json=json,
        )
    
    async def head(
        self,
        url: str,
        headers: dict[str, str] | None = None,
    ) -> HTTPResponse:
        """Make a HEAD request."""
        return await self.request(
            method="HEAD",
            url=url,
            headers=headers,
        )
