# Security Policy (CFEM - Cloud File Encryption Manager)

CFEM takes security seriously. If you believe you have found a security vulnerability in CFEM, please report it responsibly so it can be addressed.

## Supported Versions

Security updates are provided for the latest release on the `main` branch.

| Version | Supported |
|--------:|:---------|
| Latest release | ✅ Yes |
| Older releases | ❌ No |

> If you are running an older version, please upgrade to the latest release before reporting issues unless the vulnerability prevents upgrading.

## Reporting a Vulnerability

Please **do not** open a public GitHub Issue for suspected security vulnerabilities.

Instead, report privately using one of the following methods:

- **Email:** EMail the author here on Github.  
  
- **GitHub Security Advisories:** If enabled for this repository, use **"Report a vulnerability"** under the Security tab.

## What to Include in a Report

To help reproduce and fix the issue quickly, include:

- CFEM version (shown in the window title and logs)
- Operating system version (e.g., Windows 10/11 build)
- Steps to reproduce (as minimal as possible)
- Expected vs actual behavior
- Any relevant logs (redact sensitive data)
- Proof-of-concept code or files if available (keep it safe and minimal)
- Whether the issue could lead to:
  - plaintext data exposure
  - password/key disclosure
  - incorrect encryption/decryption
  - privilege escalation
  - code execution
  - tampering with output files
  - cloud sync destination manipulation

## Handling Sensitive Information

When sharing logs or examples:

- **Do not** send real passwords or encryption secrets.
- Redact:
  - usernames
  - full file paths if sensitive
  - cloud account identifiers
  - file contents
- If you must share a file to reproduce an issue, use a synthetic sample file with no sensitive content.

## Disclosure Timeline

CFEM follows coordinated disclosure principles:

- We will confirm receipt of your report.
- We will attempt to reproduce and validate the issue.
- If confirmed, we will work on a fix and coordinate a disclosure timeline with you.
- Once a fix is available, we will publish release notes describing the security impact at a high level.

## Security Notes (CFEM-Specific)

### Passwords and Recovery
- CFEM does not provide a password recovery mechanism.
- **If a password is lost, encrypted data cannot be recovered.**

### Cloud Sync Behavior
- CFEM encrypts data **locally** before any cloud copy/sync occurs.
- Cloud providers (e.g., OneDrive/Dropbox/Google Drive) receive only encrypted output files.
- CFEM does not encrypt in-place within cloud folders by default to avoid sync conflicts and partial uploads.

### Threat Model Limitations
CFEM is designed to protect data at rest and during cloud storage by encrypting files locally. It does **not** protect against:

- Malware already running on the system with access to your files and keyboard input
- Attackers who obtain your password
- Compromise of the machine while encryption/decryption is in progress
- Weak passwords that are susceptible to offline guessing

### Recommended Operational Practices
- Use a strong, unique password (consider a password manager).
- Store encryption passwords securely.
- Test decrypting a sample file after configuring a new workflow.
- Keep CFEM updated to the latest release.

## Security Hardening Suggestions (Optional)
If you deploy CFEM in managed environments, consider:
- Running CFEM under least privilege
- Controlling where encrypted outputs are staged
- Monitoring and restricting cloud-sync directories as needed
- Code-signing CFEM scripts and enforcing execution policies

