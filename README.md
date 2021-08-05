# cose-rust

[![crates.io](https://img.shields.io/crates/v/cose-rust.svg)](https://crates.io/crates/cose-rust) [![API](https://docs.rs/cose-rust/badge.svg)](https://docs.rs/cose-rust)

A Rust crate to encode and decode secured data (Signatures, Encryption or MACed) in CBOR Object Signing and Encryption (COSE) format, [RFC 8152](https://tools.ietf.org/html/rfc8152).

This crate uses the [rust-openssl](https://github.com/sfackler/rust-openssl) and [rand](https://github.com/rust-random/rand) for the cryptographic operations and the [cbor-codec](https://gitlab.com/twittner/cbor-codec) for the CBOR encoding/decoding.

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

This COSE structure is then encoded in CBOR data format, resulting in a compact binary representation.

The COSE [RFC 8152](https://tools.ietf.org/html/rfc8152) specifies the following 6 types of COSE messages:

- **cose-sign1**: A digitally signed COSE message with a single recipient.
- **cose-sign**: A digitally signed COSE message with multiple recipients, each recipient has its own signature.
- **cose-encrypt0**: An encrypted COSE message with a single recipient.
- **cose-encrypt**: An encrypted COSE message with multiple recipients. In this case, for each recipient, the ciphertext is encrypted/decrypted by a shared secret between the recipient and the sender, a derived key from the shared secret or a randomly generated CEK that is derived from the shared secret (KEK).
- **cose-mac0**: A MAC tagged COSE message with a single recipient.
- **cose-encrypt**: A MAC tagged COSE message with multiple recipients. In this case, for each recipient, the tag is created/verified by a shared secret between the recipient and the sender, a derived key from the shared secret or a randomly generated CEK that is derived from the shared secret (KEK).

# Usage

To import cose-rust, add the following to your Cargo.toml:

```toml
[dependencies]
cose-rust = "0.1"
```

and to use it:

```rust
use cose;
```

# Examples

### cose-sign1

```rust
use cose::sign;
use cose::keys;
use cose::headers;
use cose::algs;
use hex;

fn main() {
    let msg = b"signed message".to_vec();

    // Prepare cose-sign1 headers
    let mut sign1 = sign::CoseSign::new();
    sign1.header.alg(algs::EDDSA, true, false);
    sign1.header.kid(b"kid1".to_vec(), true, false);

    // Add the payload
    sign1.payload(msg);

    // Prepare the cose-key
    let mut key = keys::CoseKey::new();
    key.kty(keys::EC2);
    key.alg(algs::EDDSA);
    key.crv(keys::ED25519);
    key.x(
        hex::decode("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
            .unwrap(),
    );
    key.d(
        hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
            .unwrap(),
    );
    key.key_ops(vec![keys::KEY_OPS_SIGN, keys::KEY_OPS_VERIFY]);

    // Add key to the cose-sign1 structure
    sign1.key(&key).unwrap();

    // Generate the signature without AAD
    sign1.gen_signature(None).unwrap();
    // Encode the cose-sign1 message with the payload included in the message
    sign1.encode(true).unwrap();

    // Prepare verifier
    let mut verify = sign::CoseSign::new();
    // Add the cose-sign1 message generated
    verify.bytes = sign1.bytes;
    // Initial decoding of the message
    verify.init_decoder(None).unwrap();

    // Add cose-key
    verify.key(&key).unwrap();
    // Verify cose-sign1 signature
    verify.decode(None, None).unwrap();
}
```

### cose-encrypt0

```rust
use cose::encrypt;
use cose::keys;
use cose::headers;
use cose::algs;

fn main() {
    let msg = b"encrypted message".to_vec();
    let k = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F";
    let iv = b"\x00\x01\x02\x03\x04\x05\x06\x07\x00\x01\x02\x03";

    // Prepare cose-encrypt0 headers
    let mut enc0 = encrypt::CoseEncrypt::new();
    enc0.header.alg(algs::CHACHA20, true, false);
    enc0.header.kid(b"kid2".to_vec(), true, false);
    enc0.header.iv(iv.to_vec(), true, false);

    // Add the payload
    enc0.payload(msg);

    // Prepare the cose-key
    let mut key = keys::CoseKey::new();
    key.kty(keys::SYMMETRIC);
    key.alg(algs::CHACHA20);
    key.k(k.to_vec());
    key.key_ops(vec![keys::KEY_OPS_ENCRYPT, keys::KEY_OPS_DECRYPT]);

    // Add cose-key
    enc0.key(&key).unwrap();

    // Generate the ciphertext with no AAD.
    enc0.gen_ciphertext(None).unwrap();
    // Encode the cose-encrypt0 message with the ciphertext included in the message
    enc0.encode(true).unwrap();

    // Prepare decrypter
    let mut dec0 = encrypt::CoseEncrypt::new();
    // Add the cose-encrypt0 message generated
    dec0.bytes = enc0.bytes;
    // Initial decoding of the message
    dec0.init_decoder().unwrap();

    // Add cose-key
    dec0.key(&key).unwrap();

    // Decrypt the cose-encrypt0 message
    let resp = dec0.decode(None, None).unwrap();
    assert_eq!(resp, b"encrypted message".to_vec());
}
```

### cose-mac0

```rust
use cose::mac;
use cose::keys;
use cose::headers;
use cose::algs;

fn main() {
    let msg = b"tagged message".to_vec();

    // Prepare the cose-mac0 headers
    let mut mac0 = mac::CoseMAC::new();
    mac0.header.alg(algs::AES_MAC_256_128, true, false);
    mac0.header.kid(b"kid2".to_vec(), true, false);

    // Add the payload
    mac0.payload(msg);

    // Prepare the cose-key
    let mut key = keys::CoseKey::new();
    key.kty(keys::SYMMETRIC);
    key.alg(algs::AES_MAC_256_128);
    key.k(b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F".to_vec());
    key.key_ops(vec![keys::KEY_OPS_MAC, keys::KEY_OPS_MAC_VERIFY]);

    // Add cose-key
    mac0.key(&key).unwrap();

    // Generate MAC tag without AAD
    mac0.gen_tag(None).unwrap();
    // Encode the cose-mac0 message with the payload included
    mac0.encode(true).unwrap();

    // Prepare the verifier
    let mut verify = mac::CoseMAC::new();
    // Add the cose-mac0 message generated
    verify.bytes = mac0.bytes;
    // Initial decoding of the message
    verify.init_decoder().unwrap();

    // Add cose-key
    verify.key(&key).unwrap();
    // Verify the MAC tag of the cose-mac0 message
    verify.decode(None, None).unwrap();
}
```

# License

This crate, cose-rust, is licensed by the MIT License.

# Note

This crate is under development and it has not been tested yet.
