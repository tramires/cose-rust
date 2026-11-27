A Rust implementation of CBOR Object Signing and Encryption (COSE),
[RFC 9052] and [RFC 9053].

COSE cryptographically protects a payload with signatures, encryption or MACs, in the CBOR
format.

# Features

| Area | Supported |
|------|-----------|
| **Messages** | cose-sign1, cose-sign, cose-encrypt0, cose-encrypt, cose-mac0, cose-mac - tagged or untagged, attached or detached content |
| **Signatures** | ECDSA (P-256, P-384, P-521, secp256k1), EdDSA (Ed25519, Ed448), RSA-PSS ([RFC 8230]) |
| **Encryption** | AES-GCM, AES-CCM, ChaCha20/Poly1305 |
| **MAC** | HMAC, AES-MAC |
| **Key distribution** | direct, direct+HKDF, AES key wrap, ECDH-ES/SS (+HKDF, +key wrap), RSA-OAEP ([RFC 8230]) |
| **Keys** | COSE keys and key sets |
| **Headers** | X.509 header certificates ([RFC 9360]) and counter signatures ([RFC 9338]) |

# Structure

- [`message`]:  [`CoseMessage`](message::CoseMessage), the six message types and their
encode/decode methods.
- [`agent`]:  [`CoseAgent`](agent::CoseAgent), the signers, recipients and counter signers.
- [`headers`]:  [`CoseHeader`](headers::CoseHeader), the protected and unprotected headers
parameters.
- [`keys`]:  [`CoseKey`](keys::CoseKey) and [`CoseKeySet`](keys::CoseKeySet), the cose-keys and
  cose-key-sets.
- [`algs`]:  algorithm identifiers.
- [`errors`]:  [`CoseError`](errors::CoseError) and the result types.

# Cryptographic backend

The cryptography operations use OpenSSL through the [openssl](https://crates.io/crates/openssl)
crate. By default, OpenSSL is built from source and linked statically (the `openssl_vendored`
feature). In order to link against the system's OpenSSL instead, disable the default feature:

```toml
cose-rust = {version="<version>", default-features = false }
```

# Example

Signing a payload with a single signer (cose-sign1) and verifying it:

```
use cose::message::CoseMessage;
use cose::headers::Bucket;
use cose::keys;
use cose::algs;
use hex;

let msg = b"This is the content.".to_vec();

let mut signer = CoseMessage::new_sign();
// Prepare message parameters
signer.header.set_alg(algs::ES256, Bucket::Protected);
signer.payload = msg.clone();

// Add a cose-key to the message
let mut key = keys::CoseKey::new();
key.set_kty(keys::EC2);
key.set_alg(algs::ES256);
key.set_crv(keys::P_256);

// The private components
key.set_d(hex::decode(
    "57c92077664146e876760c9520d054aa93c3afb04e306705db6090308507b4d3"
).unwrap());

// The public components
key.set_x(hex::decode(
    "bac5b11cad8f99f9c72b05cf4b9e26d244dc189f745228255a219a86d6a09eff"
).unwrap());
key.set_y(hex::decode(
    "20138bf82dc1b6d562be0fa54ab7804a3a64b6d72ccfed6b6fb6ed28bbfc117e"
).unwrap());

signer.key(&key)?;

// Generate the signature
signer.secure_content(None)?;

// Encode the message
signer.encode()?;

let encoded = signer.bytes;

// Prepare cose-sign1 struct with the bytes to decode
let mut verifier = CoseMessage::new_from_bytes(encoded)?;

// Initial decoding of message parameters
verifier.init_decoder(None)?;

// Add the cose-key
verifier.key(&key)?;

// Verify the cose-sign1 message signature
let decoded_payload = verifier.decode(None, None)?;

assert_eq!(decoded_payload, msg);

# Ok::<(), cose::errors::CoseError>(())
```

[RFC 9052]: https://www.rfc-editor.org/info/rfc9052/
[RFC 9053]: https://www.rfc-editor.org/info/rfc9053/
[RFC 9338]: https://www.rfc-editor.org/rfc/rfc9338/
[RFC 8230]: https://datatracker.ietf.org/doc/html/rfc8230
[RFC 9360]: https://www.rfc-editor.org/rfc/rfc9360.html
[RFC 9338]: https://www.rfc-editor.org/info/rfc9338/
