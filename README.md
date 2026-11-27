# cose-rust

[![crates.io](https://img.shields.io/crates/v/cose-rust.svg)](https://crates.io/crates/cose-rust) [![API](https://docs.rs/cose-rust/badge.svg)](https://docs.rs/cose-rust)

A Rust implementation of CBOR Object Signing and Encryption (COSE), 
[RFC 9052] and [RFC 9053].

COSE cryptographically protects a payload with signatures, encryption or MACs, in the CBOR format.

## Features

| Area | Supported |
|------|-----------|
| **Messages** | cose-sign1, cose-sign, cose-encrypt0, cose-encrypt, cose-mac0, cose-mac - tagged or untagged, attached or detached content |
| **Signatures** | ECDSA (P-256, P-384, P-521, secp256k1), EdDSA (Ed25519, Ed448), RSA-PSS ([RFC 8230]) |
| **Encryption** | AES-GCM, AES-CCM, ChaCha20/Poly1305 |
| **MAC** | HMAC, AES-MAC |
| **Key distribution** | direct, direct+HKDF, AES key wrap, ECDH-ES/SS (+HKDF, +key wrap), RSA-OAEP ([RFC 8230]) |
| **Keys** | COSE keys and key sets |
| **Headers** | X.509 header certificates ([RFC 9360]) and counter signatures ([RFC 9338]) |

## Usage 

```toml
[dependencies]
cose-rust = "<version>"
```

The cryptographic operations use OpenSSL, built from source by default. To link against the system's
OpenSSL instead, use `default-features = false`.

Documentation and examples for every message type can be found on [docs.rs](https://docs.rs/cose-rust).

## Testing

Every message type is tested both ways, encoding and decoding, against:

- The examples in [RFC 9052] and [RFC 9338].
- The [COSE Working Group test vectors] including the vectors
  meant to fail.
- Malformed input (truncated signatures, ciphertexts and wrapped keys, wrong IV lengths), which must
  return an error instead of panicking.

## License

This project is licensed under the [MIT License](LICENSE).

[RFC 9052]: https://www.rfc-editor.org/info/rfc9052/
[RFC 9053]: https://www.rfc-editor.org/info/rfc9053/
[RFC 9338]: https://www.rfc-editor.org/rfc/rfc9338/
[RFC 8230]: https://datatracker.ietf.org/doc/html/rfc8230
[RFC 9360]: https://www.rfc-editor.org/rfc/rfc9360.html
[COSE Working Group test vectors]: https://github.com/cose-wg/Examples
