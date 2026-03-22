# Readium-RS Agent Context

## Project Overview

Readium-RS is a Rust port of the official Readium LCP (Licensed Content Protection) implementation for EPUBs. The project implements the **basic profile** with extension traits designed to support different encryption profiles.

## Purpose

This library provides DRM (Digital Rights Management) functionality for EPUB files using the Readium LCP specification. It handles:
- License parsing and validation
- User passphrase verification
- Content key decryption
- Encrypted EPUB resource decryption

## Architecture

### Core Modules

| Module | Purpose |
|--------|---------|
| `license` | LCP License Document (.lcpl) parsing, manipulation, and builder |
| `license::encoding` | Serde helpers for dates and X.509 certificates |
| `license::profile` | Encryption profile definitions (e.g. Basic) |
| `crypto` | All cryptographic operations |
| `crypto::key` | User passphrase handling and SHA-256 key derivation |
| `crypto::cipher` | AES-256-CBC encryption/decryption operations |
| `crypto::transform` | Extension trait for supporting additional encryption profiles |
| `epub` | EPUB archive handling and encrypted content extraction |
| `epub::xml_utils` | XML/OPF parsing helpers and encryption.xml generation |

### Design Goals

1. **Basic Profile Implementation**: Core LCP functionality following the Readium specification
2. **Extensible Profiles**: Extension traits to support different encryption profiles beyond basic

## Current State

- License parsing: Complete
- Key derivation (SHA-256): Complete
- Content decryption (AES-256-CBC): Complete
- Profile abstraction traits: Complete
- Signature verification: Complete
- LSD (License Status Document): Not implemented


## References

- [Readium LCP Specification](https://readium.org/lcp-specs/)
- [LCP Basic Profile](http://readium.org/lcp/basic-profile)
