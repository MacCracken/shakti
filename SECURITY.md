# Security Policy

## Reporting a Vulnerability

Shakti is a privilege escalation tool — security vulnerabilities are critical.

Please report security issues privately via GitHub Security Advisories or email to security@agnos.org. Do not open public issues for security vulnerabilities.

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

## Security Properties

- All authentication attempts are audit-logged
- Environment is sanitized before exec (all LD_* variables removed)
- Command arguments validated against shell injection
- Rate-limited authentication (max 3 attempts)
- Timestamp-based credential caching with configurable TTL
