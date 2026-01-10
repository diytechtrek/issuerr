# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.x.x   | :white_check_mark: |

## Security Features

Issuerr implements multiple layers of security to protect your deployment:

### Authentication & Session Security

| Feature | Implementation |
|---------|---------------|
| Password Hashing | bcrypt with 12 rounds |
| Password Strength | zxcvbn library validation (score ≥ 2 required) |
| Session Cookies | HTTPOnly, SameSite=Lax |
| Secure Flag | Dynamically set based on HTTPS detection |
| Timing Attack Prevention | `secrets.compare_digest()` for credential verification |
| Legacy Hash Migration | Auto-upgrades SHA-256 hashes to bcrypt on login |

### Rate Limiting

| Endpoint | Limit | Purpose |
|----------|-------|---------|
| Login (`/login`) | 5 per minute | Brute force prevention |
| Setup (`/setup`) | 10 per hour | Setup abuse prevention |
| Password Change | 3 per hour | Account takeover prevention |
| General API | 50 per hour / 200 per day | DoS prevention |

### Container Security

- **Non-root execution**: Container runs as specified PUID/PGID user
- **Root prevention**: Explicitly blocks PUID=0 or PGID=0
- **Minimal base image**: Python slim variant
- **No unnecessary packages**: Only required dependencies installed

### Data Protection

- **API Key Masking**: Sensitive keys masked in API responses (shows only last 4 chars)
- **No Credential Exposure**: Password hashes never sent to client
- **Secret Key Generation**: Cryptographically secure (`secrets.token_hex(32)`)

## Security Recommendations

### Required for Production

1. **Use HTTPS**: Deploy behind a reverse proxy with TLS
   - See [REVERSE_PROXY_SETUP.md](REVERSE_PROXY_SETUP.md) for instructions
   
2. **Use Strong Passwords**: The built-in strength checker requires score ≥ 2 (Fair)

3. **Enable Webhook Authentication**: Configure authorization header in both Overseerr and Issuerr

### Recommended Hardening

1. **Firewall Rules**: Block direct access to port 5000 from the internet
   ```bash
   ufw deny 5000/tcp
   ```

2. **Reverse Proxy Headers**: Ensure your proxy sends:
   - `X-Forwarded-Proto` (required for Secure cookie flag)
   - `X-Real-IP` (for accurate rate limiting)

3. **Regular Updates**: Keep Issuerr and dependencies updated

## Security Assessment

### Current Security Status: ✅ Good

The application implements security best practices for its use case. Below is an honest assessment:

#### Strengths

- ✅ Strong password hashing (bcrypt, 12 rounds)
- ✅ Real-time password strength validation
- ✅ Rate limiting on sensitive endpoints
- ✅ Timing-safe credential comparison
- ✅ Secure session cookie configuration
- ✅ Non-root container execution
- ✅ API credential masking
- ✅ CORS disabled (not needed)

#### Areas for Future Enhancement

| Area | Current State | Recommendation |
|------|--------------|----------------|
| CSRF Protection | Not implemented | Consider Flask-WTF for form submissions |
| Content-Security-Policy | Not set (relies on reverse proxy) | Add CSP header in application |
| Username Validation | Minimal validation | Enforce alphanumeric + limited special chars |
| Log Sanitization | Logs may contain IPs/paths | Consider sanitizing sensitive data |

#### Not Security Issues

These are sometimes flagged but are intentional:

- **Password strength endpoint exempt from rate limiting**: Required for real-time UX during typing
- **Health endpoint without authentication**: Required for Docker health checks
- **Session lifetime of 7 days**: Standard for web applications, users can logout manually

## Reporting a Vulnerability

We take security seriously. If you discover a security vulnerability, please report it responsibly.

### How to Report

**DO NOT** create a public GitHub issue for security vulnerabilities.

Instead:

1. **Email**: Send details to `infoy@diytechtrek.com`
2. **GitHub Security Advisory**: Use the [Security Advisory](https://github.com/diytechtrek/issuerr/security/advisories/new) feature

### What to Include

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### Response Timeline

| Action | Timeframe |
|--------|-----------|
| Initial Response | 48 hours |
| Vulnerability Confirmed | 7 days |
| Fix Developed | 14-30 days (depending on complexity) |
| Public Disclosure | After fix is released |

### Recognition

We appreciate security researchers who help us improve Issuerr:

- Credit in release notes (unless you prefer anonymity)
- Listed in SECURITY.md acknowledgments section

## Security Changelog

### v1.0.0
- Initial release with bcrypt, rate limiting, secure sessions

## Acknowledgments

Thanks to the following for security contributions:

*No security researchers to acknowledge yet. Be the first!*

---

## Questions?

For security-related questions that aren't vulnerabilities, please use [GitHub Discussions](https://github.com/diytechtrek/issuerr/discussions).
