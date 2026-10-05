# Security Policy

## Supported Versions

Only the latest release of VoidB is actively supported with security updates.

| Version | Supported          |
| ------- | ------------------ |
| 0.3.x   | :white_check_mark: |
| < 0.3.0 | :x:                |

## Reporting a Vulnerability

The VoidB maintainers take security issues seriously. If you discover a security vulnerability, please report it responsibly.

### Disclosure Process

1. **Do not create a public GitHub issue.**
2. Send an email to [limmytian@gmail.com](mailto:limmytian@gmail.com) with the subject tag `[SECURITY] VoidB Vulnerability Report`.
3. Include the following details in your report:
   - Description of the vulnerability and its potential impact.
   - Exact steps or proof-of-concept (PoC) code to reproduce the issue.
   - Affected versions and component/plugin name (e.g. `voidb-core`, `voidb-plugin-ssh`, `voidb-cli`).
   - Any suggested mitigations or patches, if available.

### Response Timeline

- **Initial Response**: Within 48 hours, confirming receipt of your report.
- **Assessment**: Within 7 business days, assessing the severity and impact.
- **Fix & Disclosure**: A fix will be developed and released in a patch release. Public disclosure will be coordinated with the reporter.

## Security Architecture Principles

VoidB is designed with defensive security defaults:
- **Zero Raw Secrets in Profiles**: Connection credentials and master passwords are encrypted with AES-256-GCM.
- **Fail-Closed Authorization**: Agent capability invocations and session handoffs enforce explicit scopes and privilege gates.
- **Redaction by Default**: Diagnostic outputs, error strings, and structured audit logs automatically redact sensitive fields and credentials.
