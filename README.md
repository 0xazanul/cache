# Cache Poisoning Scanner

A high-precision bug bounty automation tool for detecting web cache poisoning vulnerabilities across thousands of domains with minimal false positives.

## Features

- **Multi-Vector Detection**: Tests for unkeyed headers, parameter cloaking, method override, fat GET, path confusion, and CPDoS attacks
- **False Positive Prevention**: Multi-stage validation with unique markers, persistence verification, and cache hit confirmation
- **CDN/Cache Fingerprinting**: Automatically detects Cloudflare, Akamai, Fastly, Varnish, CloudFront, and more
- **High Performance**: Async HTTP client with rate limiting, connection pooling, and configurable concurrency
- **Detailed Reporting**: JSON reports with PoC generation including curl commands and reproduction steps

## Installation

```bash
# Clone or navigate to the project directory
cd Hack-automation

# Create virtual environment (recommended)
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

## Usage

### Scan a Single URL or Domain

```bash
# Single URL
python main.py -d https://example.com -o results.json

# Single domain (defaults to HTTPS)
python main.py -d example.com -o results.json

# With full URL path
python main.py -d https://example.com/api/v1 -o results.json --strict
```

### Scan Multiple Domains from File

```bash
python main.py --domains domains.txt --output results.json
```

### Enhanced Validation (Strict Mode)

```bash
# Strict mode with all validations
python main.py -d example.com -o results.json --strict --origin-check --multi-session -v

# Only high confidence findings
python main.py -d domains.txt -o results.json --min-confidence high
```

### Fast Mode (Reconnaissance)

```bash
python main.py -d domains.txt -o results.json --fast -c 100
```

### Command Line Options

| Option | Short | Default | Description |
|--------|-------|---------|-------------|
| `--domains` | `-d` | Required | Single URL/domain OR file with domains (one per line) |
| `--output` | `-o` | Required | Output JSON file path for results |
| `--concurrency` | `-c` | 50 | Maximum concurrent requests |
| `--timeout` | `-t` | 10 | Request timeout in seconds |
| `--delay` | | 0.1 | Delay between requests in seconds |
| `--verbose` | `-v` | False | Enable verbose output showing all detections |
| `--fast` | | False | Fast mode - test only priority headers |
| `--strict` | | False | Strict mode - require 6/7 validation stages |
| `--min-confidence` | | low | Minimum confidence level: low, medium, high |
| `--origin-check` | | False | Enable origin vs cache comparison |
| `--multi-session` | | False | Enable multi-session validation |
| `--min-ttl` | | 10 | Minimum cache TTL to consider (seconds) |

## Domain List Format

Create a text file with one domain per line:

```
example.com
test.example.org
subdomain.target.com
```

The scanner will automatically:
- Remove protocols (http://, https://)
- Remove paths and query strings
- Skip invalid entries
- Deduplicate domains

## Attack Vectors Tested

### 1. Unkeyed Headers
Headers not included in cache key but affecting response:
- `X-Forwarded-Host`, `X-Forwarded-Scheme`, `X-Original-URL`
- `X-Rewrite-URL`, `X-Host`, `X-Forwarded-Server`
- And 30+ more headers

### 2. Host Override
Headers that can override the Host header:
- `X-Forwarded-Host`, `X-Host`, `Forwarded`

### 3. Parameter Cloaking
Query parameters excluded from cache keys:
- `utm_*`, `fbclid`, `gclid`, `callback`, `jsonp`

### 4. Method Override
Headers that change request method interpretation:
- `X-HTTP-Method-Override`, `X-HTTP-Method`, `X-Method-Override`

### 5. Fat GET
GET requests with body content:
- JSON and form-encoded bodies

### 6. Path Confusion
Path normalization differences:
- Encoded characters, dot segments, file extensions

### 7. CPDoS (Cache Poisoned Denial of Service)
- Oversized headers
- Meta character injection

## Output Format

Results are saved as JSON:

```json
{
  "scan_metadata": {
    "start_time": "2026-01-16T10:00:00Z",
    "total_domains": 5000,
    "vulnerable_count": 12
  },
  "vulnerabilities": [
    {
      "domain": "example.com",
      "url": "https://example.com/",
      "vector": "unkeyed_header",
      "injection_point": "X-Forwarded-Host",
      "cache_type": "cloudflare",
      "confidence": "high",
      "evidence": {
        "marker_reflected": true,
        "marker_persisted": true,
        "cache_hit_confirmed": true,
        "persistence_count": 3
      },
      "poc": {
        "curl_command": "curl -i -s -H 'X-Forwarded-Host: cp-scan-a1b2c3d4.evil.com' 'https://example.com/'",
        "steps": ["..."]
      }
    }
  ],
  "statistics": {
    "total_vulnerabilities": 12,
    "by_confidence": {"high": 5, "medium": 4, "low": 3},
    "by_vector": {"unkeyed_header": 8, "host_override": 4}
  }
}
```

## False Positive Prevention

The scanner employs multiple validation stages:

1. **Unique Markers**: Each test uses a cryptographic nonce (e.g., `cp-scan-a1b2c3d4`)
2. **Baseline Comparison**: Compare against clean baseline response
3. **Persistence Check**: Verify marker persists WITHOUT the payload
4. **Cache Hit Verification**: Confirm `X-Cache: HIT` or `Age` header
5. **Status Code Validation**: Only flag cacheable status codes (200, 301, 404, etc.)
6. **Cache-Control Validation**: Verify response allows shared caching
7. **Multiple Rounds**: Run 3 verification requests before flagging

## Project Structure

```
Hack-automation/
├── main.py                 # CLI entry point
├── requirements.txt        # Dependencies
├── config.py              # Configuration constants
├── scanner/
│   ├── __init__.py
│   ├── domain_loader.py   # Load and validate domains
│   ├── http_client.py     # Async HTTP client wrapper
│   ├── cache_fingerprint.py # Detect CDN/cache type
│   ├── baseline.py        # Baseline response capture
│   ├── payloads.py        # Attack payload generators
│   ├── detector.py        # Core detection logic
│   └── validator.py       # False positive filtering
├── reporters/
│   ├── __init__.py
│   └── json_reporter.py   # JSON output with PoC
└── wordlists/
    └── headers.txt        # Unkeyed header wordlist
```

## Performance Tips

1. **Rate Limiting**: Adjust `--delay` to avoid being blocked
2. **Concurrency**: Start with lower values (20-30) and increase if stable
3. **Fast Mode**: Use `--fast` for initial reconnaissance
4. **Timeout**: Increase for slow targets

## Responsible Disclosure

This tool is intended for authorized security testing only. Always:
- Obtain proper authorization before testing
- Follow responsible disclosure practices
- Respect rate limits and terms of service
- Report vulnerabilities through proper channels

## References

- [Web Cache Poisoning - PortSwigger](https://portswigger.net/web-security/web-cache-poisoning)
- [Practical Web Cache Poisoning - James Kettle](https://portswigger.net/research/practical-web-cache-poisoning)
- [CPDoS: Cache Poisoned Denial of Service](https://cpdos.org/)
- [RFC 9111: HTTP Caching](https://www.rfc-editor.org/rfc/rfc9111)

## License

For authorized security research and bug bounty hunting only.
