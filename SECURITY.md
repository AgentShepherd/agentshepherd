# Security Policy

## Reporting a Vulnerability

**Do NOT open a public issue for security vulnerabilities.**

If you discover a security bypass, sandbox escape, or any vulnerability in Crust,
please report it privately using one of these methods:

1. **GitHub Private Vulnerability Reporting** (preferred):
   Go to the [Security Advisories](https://github.com/BakeLab/crust-dev/security/advisories) page
   and click "Report a vulnerability"

2. **Email**: security@bakelens.com

### What to include

- Crust version (`crust version`)
- Operating system and version
- Which security layer was bypassed (Layer 0/1/2)
- Steps to reproduce
- Impact assessment

### Response timeline

- **Acknowledgment**: within 48 hours
- **Initial assessment**: within 7 days
- **Fix timeline**: depends on severity, typically within 30 days for critical issues

### Scope

The following are in scope:
- Sandbox escapes (Layer 2 bypass)
- Rule engine bypasses (Layer 0/1)
- Path traversal or glob matching bugs
- Network filter bypasses
- Privilege escalation

### Safe Harbor

We will not pursue legal action against security researchers who:
- Make a good faith effort to avoid privacy violations and data destruction
- Report vulnerabilities privately before any public disclosure
- Give us reasonable time to address the issue before disclosure

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.x     | Yes       |
