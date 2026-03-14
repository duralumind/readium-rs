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
| `license` | LCP License Document (.lcpl) parsing and manipulation |
| `key` | User passphrase handling and SHA-256 key derivation |
| `cipher` | AES-256-CBC encryption/decryption operations |
| `epub` | EPUB archive handling and decrypted content extraction |
| `encoding` | Serde helpers for dates and X.509 certificates |

### Design Goals

1. **Basic Profile Implementation**: Core LCP functionality following the Readium specification
2. **Extensible Profiles**: Extension traits to support different encryption profiles beyond basic
3. **Memory Safety**: Secure memory handling with zeroize for sensitive key material

## Current State

- License parsing: Complete
- Key derivation (SHA-256): Complete
- Content decryption (AES-256-CBC): Complete
- Profile abstraction traits: Planned/In Progress
- Signature verification: Not implemented
- LSD (License Status Document): Not implemented

## Key Files

- `src/lib.rs` - Library entry point
- `src/main.rs` - CLI test tool
- `src/license.rs` - License document structures
- `src/cipher.rs` - Cryptographic operations
- `src/epub.rs` - EPUB file operations

## References

- [Readium LCP Specification](https://readium.org/lcp-specs/)
- [LCP Basic Profile](http://readium.org/lcp/basic-profile)
