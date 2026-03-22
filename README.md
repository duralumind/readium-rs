# lcp-rs

This is a Rust implementation of the Readium LCP (Licensed Content Protection) [specification](https://readium.org/lcp-specs/). 
The project implements the **basic profile** with extension traits designed to support different encryption profiles.

This is a personal project that I implemented to understand the specs better. The go implementation in https://github.com/readium/readium-lcp-server seems to have the encryption implementation for the basic profile, but doesn't have decryption.

### Design Goals

1. **Basic Profile Implementation**: Core LCP functionality following the Readium specification
2. **Extensible Profiles**: Extension traits to support different encryption profiles beyond basic. The readium lcp DRM has a secret `Transform` component that transforms the hash of the user key in order to encrypt/decrypt the content of the protected publication. Each `Transform` is associated with a different profile. This library aims to provide a simple `Transform` trait where licensed providers/EDRLabs can simply plugin the implementation of the transform and have an end to end working LCP implementation for the chosen transform.

## Current State

This is still a work in progress. 
Currently has support for:
- Encrypting a epub with a user passphrase for the [Basic profile](https://readium.org/lcp-specs/releases/lcp/latest.html#63-basic-encryption-profile-10).
- Decryptiing an epub encrypted using the basic profile
