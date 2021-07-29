# cose-rust

A Rust crate to encode and decode secured data (Signatures, Encryption or MACed) in CBOR Object Signing and Encryption (COSE) format, [RFC 8152](https://tools.ietf.org/html/rfc8152).

This crate uses the [rust-openssl](https://github.com/sfackler/rust-openssl) for the cryptographic operations and the [cbor-codec](https://gitlab.com/twittner/cbor-codec) for the CBOR encoding/decoding.

# COSE 

COSE is a concise binary data format that protects the payload of the message with a set of cryptographic operations.

A COSE structure is as follows:
 1. **Tag**: A COSE mesage type identifier.
 2. **Protected header**: A CBOR encoded object that contains information to be integrity protected by the cryptographic process.  
 3. **Unprotected header**: An object that contains information that is not integrity protected. 
 4. **Content**: This is specific to each type of message:
    1. **cose-sign1**: payload and its signature. 
    3. **cose-encrypt0**: just the ciphertext.
    2. **cose-mac0**: payload and its tag. 
    4. **cose-sign**: payload and an array of recipient buckets (each similar to cose-sign1).
    5. **cose-encrypt**: ciphertext and an array of recipients buckets (each similar to cose-encrypt0).
    6. **cose-mac**: payload and an array of recipients buckets (each similar to cose-mac0).

This COSE structure is than encoded in CBOR data format, resulting in a compact binary representation.

The COSE [RFC 8152](https://tools.ietf.org/html/rfc8152) specifies the following 6 types of COSE messages:

- **cose-sign1**: A digitally signed COSE message with a single recipient.
- **cose-sign**: A digitally signed COSE message with multiple recipients, each recipient has its own signature.
- **cose-encrypt0**: An encrypted COSE message with a single recipient.
- **cose-encrypt**: An encrypted COSE message with multiple recipients. In this case, for each recipient, the ciphertext is encrypted/decrypted by a shared secret between the recipient and the sender, a derived key from the shared secret or a randomly generated CEK that is derived from the shared secret (KEK).
- **cose-mac0**: A MAC tagged COSE message with a single recipient.
- **cose-encrypt**: A MAC tagged COSE message with multiple recipients. In this case, for each recipient, the tag is created/verified by a shared secret between the recipient and the sender, a derived key from the shared secret or a randomly generated CEK that is derived from the shared secret (KEK).

## Usage

To import cose-rust, add the following to your Cargo.toml:

```toml
[dependencies]
cose-rust = "0.1"
```

and to use it:

```rust
use cose;
```

# License

This crate, cose-rust, is licensed by the MIT License.

# Note

This crate is under development and it has not been tested yet.
