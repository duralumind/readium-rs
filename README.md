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
3. **Memory Safety**: Secure memory handling with zeroize for sensitive key material

## Current State

- License parsing: Complete
- Key derivation (SHA-256): Complete
- Content decryption (AES-256-CBC): Complete
- Profile abstraction traits: In Progress
- Signature verification: Not implemented
- LSD (License Status Document): Not implemented

## Key Files

- `src/lib.rs` - Library entry point, top-level encrypt/decrypt API
- `src/main.rs` - CLI test tool
- `src/license/mod.rs` - License document structures and builder
- `src/license/encoding.rs` - Serde helpers for dates and X.509 certificates
- `src/license/profile.rs` - Encryption profile definitions
- `src/crypto/mod.rs` - Crypto module root
- `src/crypto/cipher.rs` - AES-256-CBC cryptographic operations
- `src/crypto/key.rs` - User passphrase and content key handling
- `src/crypto/transform.rs` - Extension trait for encryption profiles
- `src/epub/mod.rs` - EPUB file operations (read, encrypt, write)
- `src/epub/xml_utils.rs` - XML/OPF parsing and encryption.xml generation

## References

- [Readium LCP Specification](https://readium.org/lcp-specs/)
- [LCP Basic Profile](http://readium.org/lcp/basic-profile)
