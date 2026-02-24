# Security Policy

## Supported Versions

zquic is under active development. Security fixes are applied to the latest commit on `main` only.

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, report them privately via [GitHub's private vulnerability reporting](https://github.com/ericsssan/zquic/security/advisories/new).

Include as much of the following as possible:
- Description of the vulnerability and its potential impact
- Affected component (e.g. `crypto.zig`, `tls.zig`)
- Steps to reproduce or a proof-of-concept
- Relevant RFC sections if applicable

You can expect an acknowledgement within 72 hours.

## Scope

This library implements cryptographic and network protocol logic. Areas of particular sensitivity:

- **`crypto.zig`** — AES-128-GCM payload encryption, header protection, HKDF key derivation (RFC 9001)
- **`tls.zig`** — TLS 1.3 handshake state machine
- **`packet.zig`** — packet parsing (untrusted input)
- **`frame.zig`** — frame parsing (untrusted input)

## Disclaimer

zquic is experimental software. It has not been audited. Do not use it in production systems that require security guarantees.
