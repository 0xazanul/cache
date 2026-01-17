#!/usr/bin/env python3
"""
Cache Poisoning Scanner v2.0 - Bug Bounty Automation Tool

An enhanced, high-precision scanner for detecting web cache poisoning 
vulnerabilities with 7-stage validation and near-zero false positives.

Features:
- Cache Key Oracle detection
- Multi-checkpoint persistence validation (2s, 5s, 10s, 30s)
- Multi-session/vantage point validation
- Origin vs cache comparison
- Content context analysis for exploitability
- Strict mode for maximum accuracy

Usage:
    # Scan single URL or domain
    python main.py -d https://example.com -o results.json
    python main.py -d example.com -o results.json
    
    # Scan from file
    python main.py -d domains.txt -o results.json
    python main.py -d domains.txt -o results.json --strict --verbose
"""

import asyncio
import sys
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

import click
from rich.console import Console
from rich.progress import (
    Progress,
    SpinnerColumn,
    TextColumn,
    BarColumn,
    TaskProgressColumn,
    TimeRemainingColumn,
)
from rich.panel import Panel
from rich.table import Table

from config import (
    DEFAULT_TIMEOUT,
    DEFAULT_CONCURRENCY,
    DEFAULT_DELAY,
    VERIFICATION_ROUNDS,
    MIN_STAGES_STRICT,
    MIN_STAGES_NORMAL,
    PRIORITY_HEADERS,
)
from scanner import (
    DomainLoader,
    AsyncHTTPClient,
    CachePoisonDetector,
    PayloadGenerator,
    Validator,
)
from reporters import JSONReporter

console = Console()


@dataclass
class TargetInfo:
    """Information about a scan target (URL or domain)."""
    name: str
    url: str
    https_url: str | None = None
    http_url: str | None = None
    is_alive: bool = True


def parse_target(target: str) -> TargetInfo | None:
    """
    Parse a single URL or domain into TargetInfo.
    
    Accepts:
    - https://example.com/path
    - http://example.com
    - example.com
    - www.example.com
    """
    target = target.strip()
    
    if not target:
        return None
    
    # Check if it's a full URL
    if target.startswith(('http://', 'https://')):
        parsed = urlparse(target)
        domain = parsed.netloc
        url = target
        
        if parsed.scheme == 'https':
            return TargetInfo(
                name=domain,
                url=url,
                https_url=url,
            )
        else:
            return TargetInfo(
                name=domain,
                url=url,
                http_url=url,
            )
    
    # It's just a domain/hostname
    # Remove common prefixes if present
    domain = target.lower()
    for prefix in ['www.', '//']:
        if domain.startswith(prefix):
            domain = domain[len(prefix):]
    
    # Remove path if accidentally included
    domain = domain.split('/')[0]
    
    # Default to HTTPS
    url = f"https://{domain}"
    
    return TargetInfo(
        name=domain,
        url=url,
        https_url=url,
    )


def is_file_input(target: str) -> bool:
    """Check if the input is a file path or a URL/domain."""
    # If it looks like a URL, it's not a file
    if target.startswith(('http://', 'https://', 'www.')):
        return False
    
    # If it contains URL-like characters, probably not a file
    if '://' in target:
        return False
    
    # Check if it's an existing file
    path = Path(target)
    if path.exists() and path.is_file():
        return True
    
    # Check if it looks like a domain (has dots but no path separators typical of files)
    # e.g., "example.com" vs "domains.txt"
    if '.' in target:
        # Common file extensions
        file_extensions = {'.txt', '.csv', '.json', '.lst', '.list', '.domains'}
        suffix = path.suffix.lower()
        if suffix in file_extensions:
            return True  # Looks like a file (even if doesn't exist yet - will error later)
        
        # If no common extension and has only one dot with TLD-like ending, it's a domain
        parts = target.split('.')
        if len(parts) == 2 and len(parts[-1]) <= 6:
            return False  # Likely a domain like "example.com"
    
    # Default: if file exists, use it; otherwise assume domain
    return path.exists()


def print_banner(strict_mode: bool = False):
    """Print the tool banner."""
    mode = "STRICT MODE" if strict_mode else "STANDARD MODE"
    banner = f"""
╔═══════════════════════════════════════════════════════════════╗
║        CACHE POISONING SCANNER v2.0 - Enhanced Edition        ║
║                   Bug Bounty Automation                       ║
║                                                               ║
║   7-Stage Validation Pipeline:                                ║
║   1. Cache Key Oracle    5. Origin Comparison                 ║
║   2. Reflection Check    6. Cache Headers                     ║
║   3. Multi-Checkpoint    7. Content Context                   ║
║   4. Multi-Session                                            ║
║                                                               ║
║   Mode: {mode:^20}                              ║
╚═══════════════════════════════════════════════════════════════╝
    """
    style = "bold red" if strict_mode else "bold cyan"
    console.print(Panel(banner, style=style))


async def scan_domain_enhanced(
    domain,
    client: AsyncHTTPClient,
    detector: CachePoisonDetector,
    validator: Validator,
    reporter: JSONReporter,
    payloads: list,
    verbose: bool,
    debug: bool,
    min_confidence: str,
    full_validation: bool,
) -> tuple[int, int]:
    """
    Enhanced domain scanning with 7-stage validation.
    
    Returns:
        Tuple of (vulnerabilities_found, urls_tested)
    """
    vulnerabilities_found = 0
    urls_tested = 0
    
    # Build URL
    url = f"https://{domain.name}"
    if domain.https_url:
        url = domain.https_url
    elif domain.http_url:
        url = domain.http_url
    
    # Set domain context for payload generator
    detector._payload_generator.set_domain_context(domain.name)
    
    try:
        for payload in payloads:
            result = await detector.detect(url, payload)
            urls_tested += 1
            
            # Debug: show every payload result
            if debug:
                header_info = payload.header_name or payload.param_name or "N/A"
                if result.error:
                    console.print(f"  [red]ERR[/red] {header_info}: {result.error}")
                elif result.marker_reflected:
                    if result.marker_persisted:
                        console.print(f"  [green]PERSIST[/green] {header_info}: reflected + persisted ({result.persistence_count}x)")
                    else:
                        console.print(f"  [yellow]REFLECT[/yellow] {header_info}: reflected but not persisted")
                else:
                    console.print(f"  [dim]MISS[/dim] {header_info}: not reflected", style="dim")
            
            if result.is_vulnerable:
                # Run enhanced 7-stage validation
                validation = await validator.validate(
                    result,
                    full_validation=full_validation,
                )
                
                # Check confidence threshold
                confidence_order = {"none": 0, "low": 1, "medium": 2, "high": 3}
                result_confidence = confidence_order.get(validation.final_confidence, 0)
                min_conf_level = confidence_order.get(min_confidence, 1)
                
                if validation.is_valid and result_confidence >= min_conf_level:
                    vulnerabilities_found += 1
                    reporter.add_result(result, validation)
                    
                    if verbose:
                        stages = f"{validation.stages_passed}/{validation.total_stages}"
                        console.print(
                            f"  [green]✓[/green] CONFIRMED: {domain.name} - "
                            f"{payload.vector.name} via {payload.header_name or payload.param_name} "
                            f"[{validation.final_confidence}] ({stages} stages)"
                        )
                elif verbose and validation.stages_passed >= 2:
                    # Show near-misses for debugging
                    console.print(
                        f"  [yellow]![/yellow] Rejected: {domain.name} - "
                        f"{payload.vector.name} ({validation.stages_passed}/{validation.total_stages} stages) "
                        f"- {validation.summary[:60]}"
                    )
                        
    except Exception as e:
        if verbose or debug:
            console.print(f"  [red]✗[/red] Error scanning {domain.name}: {str(e)[:50]}")
    
    return vulnerabilities_found, urls_tested


async def run_scan_enhanced(
    target_input: str,
    output_file: str,
    concurrency: int,
    timeout: int,
    delay: float,
    verbose: bool,
    debug: bool,
    fast_mode: bool,
    strict_mode: bool,
    min_confidence: str,
    origin_check: bool,
    multi_session: bool,
    min_ttl: int,
):
    """Run the enhanced cache poisoning scan with 7-stage validation."""
    print_banner(strict_mode)
    
    # Show configuration
    console.print("\n[bold]Scanner Configuration:[/bold]")
    config_table = Table(show_header=False, box=None)
    config_table.add_column("Setting", style="cyan")
    config_table.add_column("Value", style="yellow")
    config_table.add_row("Mode", "STRICT" if strict_mode else "STANDARD")
    config_table.add_row("Min Confidence", min_confidence.upper())
    config_table.add_row("Origin Check", "✓" if origin_check else "✗")
    config_table.add_row("Multi-Session", "✓" if multi_session else "✗")
    config_table.add_row("Concurrency", str(concurrency))
    console.print(config_table)
    
    # Initialize components
    console.print("\n[bold]Initializing enhanced scanner...[/bold]")
    
    domain_loader = DomainLoader(timeout=timeout)
    payload_generator = PayloadGenerator()
    reporter = JSONReporter()
    
    # Generate payloads based on mode
    if fast_mode:
        console.print("[yellow]Fast mode - testing priority headers only[/yellow]")
        payload_generator.unkeyed_headers = PRIORITY_HEADERS
        payloads = payload_generator.generate_unkeyed_header_payloads()
        payloads.extend(payload_generator.generate_host_override_payloads()[:3])
    else:
        payloads = payload_generator.generate_all("https://example.com")
    
    console.print(f"[dim]Generated {len(payloads)} test payloads[/dim]")
    
    # Determine if input is a file or single target
    is_file = is_file_input(target_input)
    
    if is_file:
        # Load domains from file
        console.print(f"\n[bold]Loading domains from file: {target_input}[/bold]")
        
        try:
            raw_domains = domain_loader.load_domains_from_file(target_input)
            console.print(f"[dim]Loaded {len(raw_domains)} domains from file[/dim]")
        except FileNotFoundError:
            console.print(f"[red]Error: Domain file not found: {target_input}[/red]")
            sys.exit(1)
        
        # Validate domains
        console.print("\n[bold]Validating domains (DNS + HTTP probe)...[/bold]")
        
        alive_domains = []
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            TimeRemainingColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("Probing domains...", total=len(raw_domains))
            
            async for domain in domain_loader.load_and_validate(
                target_input,
                concurrency=concurrency,
                progress_callback=lambda: progress.advance(task),
            ):
                alive_domains.append(domain)
        
        console.print(f"[green]✓[/green] {len(alive_domains)}/{len(raw_domains)} domains are alive")
    else:
        # Single URL/domain input
        console.print(f"\n[bold]Target: {target_input}[/bold]")
        
        target = parse_target(target_input)
        if target is None:
            console.print(f"[red]Error: Invalid target: {target_input}[/red]")
            sys.exit(1)
        
        console.print(f"[dim]Parsed as: {target.url}[/dim]")
        
        # Quick probe to verify target is alive
        console.print("[dim]Verifying target is reachable...[/dim]")
        
        async with AsyncHTTPClient(timeout=timeout) as probe_client:
            response = await probe_client.get(target.url)
            
            if response.error:
                # Try HTTP if HTTPS failed
                if target.https_url:
                    http_url = target.url.replace('https://', 'http://')
                    response = await probe_client.get(http_url)
                    if not response.error:
                        target.url = http_url
                        target.http_url = http_url
                        target.https_url = None
                
                if response.error:
                    console.print(f"[red]Error: Target not reachable: {response.error}[/red]")
                    sys.exit(1)
        
        console.print(f"[green]✓[/green] Target is alive: {target.url}")
        alive_domains = [target]
    
    if not alive_domains:
        console.print("[red]No alive domains found. Exiting.[/red]")
        sys.exit(1)
    
    # Start scan
    reporter.start_scan(len(alive_domains))
    
    console.print(f"\n[bold]Starting enhanced cache poisoning scan...[/bold]")
    console.print(f"[dim]Testing {len(payloads)} payloads × {len(alive_domains)} domains[/dim]")
    console.print(f"[dim]7-stage validation: {'STRICT' if strict_mode else 'STANDARD'} mode[/dim]\n")
    
    total_vulnerabilities = 0
    total_urls_tested = 0
    
    # Determine validation depth
    full_validation = origin_check or multi_session or strict_mode
    min_stages = MIN_STAGES_STRICT if strict_mode else MIN_STAGES_NORMAL
    
    async with AsyncHTTPClient(
        timeout=timeout,
        max_concurrency=concurrency,
        delay=delay,
    ) as client:
        detector = CachePoisonDetector(
            client=client,
            verification_rounds=VERIFICATION_ROUNDS,
            use_multi_checkpoint=True,
        )
        
        validator = Validator(
            client=client,
            strict_mode=strict_mode,
            min_stages_to_pass=min_stages,
        )
        
        semaphore = asyncio.Semaphore(max(1, concurrency // 4))
        
        async def scan_with_semaphore(domain):
            async with semaphore:
                return await scan_domain_enhanced(
                    domain,
                    client,
                    detector,
                    validator,
                    reporter,
                    payloads,
                    verbose,
                    debug,
                    min_confidence,
                    full_validation,
                )
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            TimeRemainingColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("Scanning domains...", total=len(alive_domains))
            
            tasks = [scan_with_semaphore(domain) for domain in alive_domains]
            
            for coro in asyncio.as_completed(tasks):
                vulns, urls = await coro
                total_vulnerabilities += vulns
                total_urls_tested += urls
                progress.advance(task)
                progress.update(
                    task,
                    description=f"Scanning... ({total_vulnerabilities} confirmed vulns)"
                )
    
    # End scan
    reporter.end_scan()
    
    # Save report
    console.print(f"\n[bold]Saving report to {output_file}...[/bold]")
    reporter.save_report(output_file)
    
    # Print summary
    console.print("\n" + reporter.get_summary())
    
    # Print detailed findings
    report = reporter.generate_report()
    if report.vulnerabilities:
        console.print("\n[bold]Confirmed Vulnerabilities:[/bold]\n")
        
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Domain", style="cyan", max_width=30)
        table.add_column("Vector", style="yellow")
        table.add_column("Injection", style="green")
        table.add_column("Cache", style="blue")
        table.add_column("Conf", style="red")
        table.add_column("Stages", style="dim")
        
        for vuln in report.vulnerabilities:
            confidence_style = {
                "high": "bold green",
                "medium": "yellow",
                "low": "dim",
            }.get(vuln.confidence, "dim")
            
            stages = "7/7" if vuln.validation else "N/A"
            if vuln.validation:
                stages = f"{vuln.validation.stages_passed}/7"
            
            table.add_row(
                vuln.domain[:30],
                vuln.vector,
                (vuln.header_or_param or "N/A")[:15],
                vuln.cache_type,
                f"[{confidence_style}]{vuln.confidence.upper()}[/{confidence_style}]",
                stages,
            )
        
        console.print(table)
    else:
        console.print("\n[yellow]No vulnerabilities found meeting confidence threshold.[/yellow]")
    
    # Final stats
    console.print(f"\n[bold green]Scan complete![/bold green]")
    console.print(f"  Domains scanned: {len(alive_domains)}")
    console.print(f"  URLs tested: {total_urls_tested}")
    console.print(f"  Vulnerabilities confirmed: {total_vulnerabilities}")
    console.print(f"  Results saved to: {output_file}")


@click.command()
@click.option(
    "--domains", "-d",
    required=True,
    type=str,
    help="Single URL/domain OR path to file with domains (one per line)",
)
@click.option(
    "--output", "-o",
    required=True,
    type=click.Path(),
    help="Output JSON file path for results",
)
@click.option(
    "--concurrency", "-c",
    default=DEFAULT_CONCURRENCY,
    type=int,
    help=f"Maximum concurrent requests (default: {DEFAULT_CONCURRENCY})",
)
@click.option(
    "--timeout", "-t",
    default=DEFAULT_TIMEOUT,
    type=int,
    help=f"Request timeout in seconds (default: {DEFAULT_TIMEOUT})",
)
@click.option(
    "--delay",
    default=DEFAULT_DELAY,
    type=float,
    help=f"Delay between requests in seconds (default: {DEFAULT_DELAY})",
)
@click.option(
    "--verbose", "-v",
    is_flag=True,
    help="Enable verbose output showing all detections",
)
@click.option(
    "--fast",
    is_flag=True,
    help="Fast mode - test only priority headers",
)
@click.option(
    "--strict",
    is_flag=True,
    help="Strict mode - require 6/7 validation stages to pass",
)
@click.option(
    "--min-confidence",
    type=click.Choice(["low", "medium", "high"]),
    default="low",
    help="Minimum confidence level to report (default: low)",
)
@click.option(
    "--origin-check",
    is_flag=True,
    help="Enable origin vs cache comparison validation",
)
@click.option(
    "--multi-session",
    is_flag=True,
    help="Enable multi-session/vantage point validation",
)
@click.option(
    "--min-ttl",
    default=10,
    type=int,
    help="Minimum cache TTL in seconds to consider (default: 10)",
)
@click.option(
    "--debug",
    is_flag=True,
    help="Debug mode - show result of every payload test",
)
def main(
    domains: str,
    output: str,
    concurrency: int,
    timeout: int,
    delay: float,
    verbose: bool,
    fast: bool,
    strict: bool,
    min_confidence: str,
    origin_check: bool,
    multi_session: bool,
    min_ttl: int,
    debug: bool,
):
    """
    Cache Poisoning Scanner v2.0 - Enhanced Detection with 7-Stage Validation
    
    An advanced scanner for detecting web cache poisoning vulnerabilities
    with near-zero false positives through comprehensive validation.
    
    \b
    INPUT:
    The -d/--domains flag accepts either:
    - A single URL:    https://example.com/path
    - A single domain: example.com
    - A file path:     domains.txt (one domain per line)
    
    \b
    VALIDATION STAGES:
    1. Cache Key Oracle - Verify input NOT in cache key
    2. Reflection Check - Marker appears in response
    3. Persistence Check - Multi-checkpoint (2s, 5s, 10s, 30s)
    4. Multi-Session - Different clients see poisoning
    5. Origin Comparison - Cache poisoned, origin clean
    6. Cache Headers - Response explicitly cacheable
    7. Content Context - Marker in exploitable location
    
    \b
    EXAMPLES:
        # Scan a single URL
        python main.py -d https://example.com -o results.json
        
        # Scan a single domain
        python main.py -d example.com -o results.json --strict -v
        
        # Scan from a file of domains
        python main.py -d domains.txt -o results.json
        
        # Full validation with strict mode
        python main.py -d example.com -o results.json --strict --origin-check --multi-session
        
        # Fast scan with high confidence threshold
        python main.py -d domains.txt -o results.json --fast --min-confidence high
    """
    asyncio.run(run_scan_enhanced(
        target_input=domains,
        output_file=output,
        concurrency=concurrency,
        timeout=timeout,
        delay=delay,
        verbose=verbose,
        debug=debug,
        fast_mode=fast,
        strict_mode=strict,
        min_confidence=min_confidence,
        origin_check=origin_check,
        multi_session=multi_session,
        min_ttl=min_ttl,
    ))


if __name__ == "__main__":
    main()
