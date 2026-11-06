# Security Policy & Responsible Use

## Responsible Use Statement

**authdiff** is an authorization auditing tool intended strictly for authorized security assessments, penetration testing, and academic research on applications you own or have explicit, documented permission to test.

- **Explicit Authorization Required:** Never replay requests against systems or APIs without prior written authorization from the system owner. Replaying requests against unauthorized systems may violate laws including the Computer Fraud and Abuse Act (CFAA) in the United States and similar legislation globally.
- **Defensive Safeguards:** By default, `authdiff` enables strict safety guardrails:
  - Only safe HTTP methods (`GET`, `HEAD`, `OPTIONS`) are replayed unless an explicit unsafe-methods override is enabled.
  - Replays are strictly confined to user-specified target host scopes.
  - Automatic rate-limiting and request caps prevent denial of service.
  - Credential redaction prevents inadvertent disk leakage of authorization tokens.

## Vulnerability Reporting

If you discover a security vulnerability in `authdiff` itself (such as a remote code execution vulnerability, credential leak, or path traversal), please report it responsibly:

1. **Do not open a public issue.**
2. Send an email describing the issue, impact, and reproduction steps to the repository maintainer.
3. Allow reasonable time for investigation and remediation before public disclosure.
