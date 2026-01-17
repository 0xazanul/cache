"""Domain loader with DNS validation and HTTP probing."""

import asyncio
from dataclasses import dataclass, field
from pathlib import Path
from typing import AsyncIterator, Callable

import dns.resolver
import dns.asyncresolver
import httpx
from rich.console import Console

from config import DEFAULT_TIMEOUT, USER_AGENTS

console = Console()


@dataclass
class Domain:
    """Represents a validated domain with its properties."""
    
    name: str
    resolved_ips: list[str] = field(default_factory=list)
    http_url: str | None = None
    https_url: str | None = None
    is_alive: bool = False
    supports_https: bool = False
    status_code: int | None = None
    redirect_url: str | None = None


class DomainLoader:
    """Load, validate, and probe domains from a file."""
    
    def __init__(
        self,
        timeout: int = DEFAULT_TIMEOUT,
        dns_servers: list[str] | None = None,
    ):
        self.timeout = timeout
        self.dns_servers = dns_servers or ["8.8.8.8", "1.1.1.1"]
        self._resolver: dns.asyncresolver.Resolver | None = None
    
    def _get_resolver(self) -> dns.asyncresolver.Resolver:
        """Get or create async DNS resolver."""
        if self._resolver is None:
            self._resolver = dns.asyncresolver.Resolver()
            self._resolver.nameservers = self.dns_servers
            self._resolver.timeout = self.timeout
            self._resolver.lifetime = self.timeout
        return self._resolver
    
    def load_domains_from_file(self, filepath: str | Path) -> list[str]:
        """Load domain names from a text file (one per line)."""
        filepath = Path(filepath)
        
        if not filepath.exists():
            raise FileNotFoundError(f"Domain file not found: {filepath}")
        
        domains = []
        with open(filepath, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                # Skip empty lines and comments
                if not line or line.startswith("#"):
                    continue
                # Clean up domain - remove protocol if present
                domain = self._clean_domain(line)
                if domain:
                    domains.append(domain)
        
        return list(set(domains))  # Remove duplicates
    
    def _clean_domain(self, domain: str) -> str | None:
        """Clean and validate domain format."""
        domain = domain.lower().strip()
        
        # Remove protocol
        for prefix in ["https://", "http://", "//", "www."]:
            if domain.startswith(prefix):
                domain = domain[len(prefix):]
        
        # Remove path and query
        domain = domain.split("/")[0]
        domain = domain.split("?")[0]
        domain = domain.split("#")[0]
        
        # Remove port
        if ":" in domain:
            domain = domain.split(":")[0]
        
        # Basic validation
        if not domain or len(domain) < 3 or "." not in domain:
            return None
        
        return domain
    
    async def resolve_domain(self, domain: str) -> list[str]:
        """Resolve domain to IP addresses."""
        resolver = self._get_resolver()
        ips = []
        
        try:
            answers = await resolver.resolve(domain, "A")
            ips = [str(rdata) for rdata in answers]
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout, Exception):
            pass
        
        return ips
    
    async def probe_http(
        self,
        domain: str,
        client: httpx.AsyncClient,
    ) -> tuple[bool, str | None, int | None, str | None]:
        """
        Probe domain for HTTP/HTTPS availability.
        
        Returns:
            Tuple of (is_alive, working_url, status_code, redirect_url)
        """
        # Try HTTPS first
        for scheme in ["https", "http"]:
            url = f"{scheme}://{domain}"
            try:
                response = await client.get(
                    url,
                    follow_redirects=True,
                    timeout=self.timeout,
                )
                redirect_url = None
                if response.history:
                    redirect_url = str(response.url)
                
                return True, url, response.status_code, redirect_url
                
            except (httpx.RequestError, httpx.HTTPStatusError):
                continue
        
        return False, None, None, None
    
    async def validate_domain(
        self,
        domain: str,
        client: httpx.AsyncClient,
    ) -> Domain:
        """Fully validate a domain with DNS and HTTP probing."""
        domain_obj = Domain(name=domain)
        
        # DNS resolution
        domain_obj.resolved_ips = await self.resolve_domain(domain)
        
        if not domain_obj.resolved_ips:
            return domain_obj
        
        # HTTP probing
        is_alive, url, status_code, redirect_url = await self.probe_http(domain, client)
        
        domain_obj.is_alive = is_alive
        domain_obj.status_code = status_code
        domain_obj.redirect_url = redirect_url
        
        if url:
            if url.startswith("https://"):
                domain_obj.https_url = url
                domain_obj.supports_https = True
            else:
                domain_obj.http_url = url
        
        return domain_obj
    
    async def load_and_validate(
        self,
        filepath: str | Path,
        concurrency: int = 50,
        progress_callback: Callable | None = None,
    ) -> AsyncIterator[Domain]:
        """
        Load domains from file and validate them concurrently.
        
        Args:
            filepath: Path to the domains file
            concurrency: Maximum concurrent validation tasks
            progress_callback: Optional callback for progress updates
            
        Yields:
            Validated Domain objects
        """
        domains = self.load_domains_from_file(filepath)
        semaphore = asyncio.Semaphore(concurrency)
        
        async with httpx.AsyncClient(
            headers={"User-Agent": USER_AGENTS[0]},
            verify=False,  # Allow self-signed certs
            http2=True,
        ) as client:
            
            async def validate_with_semaphore(domain: str) -> Domain:
                async with semaphore:
                    result = await self.validate_domain(domain, client)
                    if progress_callback:
                        progress_callback()
                    return result
            
            # Create tasks for all domains
            tasks = [validate_with_semaphore(d) for d in domains]
            
            # Process as they complete
            for coro in asyncio.as_completed(tasks):
                domain_obj = await coro
                if domain_obj.is_alive:
                    yield domain_obj
    
    async def get_alive_domains(
        self,
        filepath: str | Path,
        concurrency: int = 50,
    ) -> list[Domain]:
        """Get list of all alive domains from file."""
        domains = []
        async for domain in self.load_and_validate(filepath, concurrency):
            domains.append(domain)
        return domains
