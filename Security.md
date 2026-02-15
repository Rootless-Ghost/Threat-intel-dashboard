# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |

## Reporting a Vulnerability

If you discover a security vulnerability in Threat Intel Dashboard, please report it responsibly:

**DO NOT** open a public GitHub issue for security vulnerabilities.

**How to report:**
- **GitHub Security Advisories**: Use the "Report a vulnerability" button in the Security tab

**What to include in your report:**
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

**Response timeline:**
- Initial response: Within 48 hours
- Status update: Within 7 days
- Fix timeline: Depends on severity (Critical: 7 days, High: 14 days, Medium: 30 days)

## Security Best Practices

This project follows these security practices:

- Dependencies are monitored via Dependabot
- All user inputs are validated and sanitized
- API keys and secrets stored in environment variables (never committed)
- Threat intelligence data cached locally with encryption at rest
- Rate limiting on external API calls to prevent abuse
