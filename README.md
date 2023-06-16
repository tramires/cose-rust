# cose-rust

[![crates.io](https://img.shields.io/crates/v/cose-rust.svg)](https://crates.io/crates/cose-rust) [![API](https://docs.rs/cose-rust/badge.svg)](https://docs.rs/cose-rust)

A Rust crate to encode and decode secured data (Signatures, Encryption or MACed) in CBOR Object Signing and Encryption (COSE) format, [RFC 8152](https://tools.ietf.org/html/rfc8152).

This crate uses the [rust-openssl](https://github.com/sfackler/rust-openssl) and [rand](https://github.com/rust-random/rand) for the cryptographic operations and the [cbor-codec](https://gitlab.com/twittner/cbor-codec) for the CBOR encoding/decoding.

# COSE 

COSE is a concise binary data format that protects the payload of the message with a set of cryptographic operations.

The COSE [RFC 8152](https://tools.ietf.org/html/rfc8152) specifies the following 6 types of COSE messages:

- **cose-sign1**: A digitally signed COSE message with a single signer.
- **cose-sign**: A digitally signed COSE message with a signers bucket.
- **cose-encrypt0**: An encrypted COSE message with a single recipient.
- **cose-encrypt**: An encrypted COSE message with a recipients bucket.
- **cose-mac0**: A MAC tagged COSE message with a single recipient.
- **cose-encrypt**: A MAC tagged COSE message with a recipients bucket.

# Examples

The following examples, demonstrate how to encode and decode the basic COSE messages (cose-sign1, cose-encrypt0, cose-mac0), examples of other use cases and cose message types
can be found in the respective documentation.

## cose-sign1

### Encode cose-sign1 message
```rust
use cose::sign::CoseSign;
use cose::keys;
use cose::algs;
use hex;

fn main() {
    let msg = b"This is the content.".to_vec();
    let kid = b"11".to_vec();

    // cose-key to encode the message
    let mut key = keys::CoseKey::new();
    key.kty(keys::EC2);
    key.alg(algs::ES256);
    key.crv(keys::P_256);
    key.x(hex::decode("bac5b11cad8f99f9c72b05cf4b9e26d244dc189f745228255a219a86d6a09eff").unwrap());
    key.y(hex::decode("20138bf82dc1b6d562be0fa54ab7804a3a64b6d72ccfed6b6fb6ed28bbfc117e").unwrap());
    key.d(hex::decode("57c92077664146e876760c9520d054aa93c3afb04e306705db6090308507b4d3").unwrap());
    key.key_ops(vec![keys::KEY_OPS_SIGN]);

    // Prepare cose-sign1 message
    let mut sign1 = CoseSign::new();
    sign1.header.alg(algs::ES256, true, false);
    sign1.header.kid(kid, true, false);
    sign1.payload(msg);
    sign1.key(&key).unwrap();

    // Generate the signature
    sign1.gen_signature(None).unwrap();

    // Encode the message with the payload
    sign1.encode(true).unwrap();
}
```

### Decode cose-sign1 message
```rust
use cose::sign::CoseSign;
use cose::keys;
use cose::algs;
use hex;

fn main() {
    // cose-key to decode the message
    let mut key = keys::CoseKey::new();
    key.kty(keys::EC2);
    key.alg(algs::ES256);
    key.crv(keys::P_256);
    key.x(hex::decode("bac5b11cad8f99f9c72b05cf4b9e26d244dc189f745228255a219a86d6a09eff").unwrap());
    key.y(hex::decode("20138bf82dc1b6d562be0fa54ab7804a3a64b6d72ccfed6b6fb6ed28bbfc117e").unwrap());
    key.d(hex::decode("57c92077664146e876760c9520d054aa93c3afb04e306705db6090308507b4d3").unwrap());
    key.key_ops(vec![keys::KEY_OPS_VERIFY]);
    
    // Generate CoseSign struct with the cose-sign1 message to decode
    let mut verify = CoseSign::new();
    verify.bytes =
    hex::decode("d28447a2012604423131a054546869732069732074686520636f6e74656e742e5840dc93ddf7d5aff58131589087eaa65eeffa0baf2e72201ee91c0ca876ec42fdfb2a67dbc6ea1a95d2257cec645cf789808c0a392af045e2bc1bdb6746d80f221b").unwrap();

    // Initial decoding
    verify.init_decoder(None).unwrap();

    // Add key and verify the signature
    verify.key(&key).unwrap();
    verify.decode(None).unwrap();
}
```

## cose-encrypt0

### Encode cose-encrypt0 message
```rust
use cose::encrypt::CoseEncrypt;
use cose::keys;
use cose::algs;
use hex;

fn main() {
    let msg = b"This is the content.".to_vec();
    let kid = b"secret".to_vec();

    // Prepare the cose-key
    let mut key = keys::CoseKey::new();
    key.kty(keys::SYMMETRIC);
    key.alg(algs::CHACHA20);
    key.k(hex::decode("849b57219dae48de646d07dbb533566e976686457c1491be3a76dcea6c427188").unwrap());
    key.key_ops(vec![keys::KEY_OPS_ENCRYPT]);

    // Prepare cose-encrypt0 message
    let mut enc0 = CoseEncrypt::new();
    enc0.header.alg(algs::CHACHA20, true, false);
    enc0.header.iv(hex::decode("89f52f65a1c580933b5261a7").unwrap(), true, false);
    enc0.payload(msg);
    enc0.key(&key).unwrap();

    // Generate the ciphertext with no AAD.
    enc0.gen_ciphertext(None).unwrap();
    // Encode the cose-encrypt0 message with the ciphertext included
    enc0.encode(true).unwrap();
}

```

### Decode cose-encrypt0 message
```rust
use cose::encrypt::CoseEncrypt;
use cose::keys;
use cose::algs;
use hex;

fn main() {
    let expected_msg = b"This is the content.".to_vec();

    // Prepare the cose-key
    let mut key = keys::CoseKey::new();
    key.kty(keys::SYMMETRIC);
    key.alg(algs::CHACHA20);
    key.k(hex::decode("849b57219dae48de646d07dbb533566e976686457c1491be3a76dcea6c427188").unwrap());
    key.key_ops(vec![keys::KEY_OPS_DECRYPT]);


    // Generate CoseEncrypt struct with the cose-encryt0 message to decode
    let mut dec0 = CoseEncrypt::new();
    dec0.bytes =
    hex::decode("d08352a2011818054c89f52f65a1c580933b5261a7a0582481c32c048134989007b3b5b932811ea410eeab15bd0de5d5ac5be03c84dce8c88871d6e9").unwrap();

    // Initial decoding of the message
    dec0.init_decoder().unwrap();

    // Add cose-key
    dec0.key(&key).unwrap();

    // Decrypt the cose-encrypt0 message
    let msg = dec0.decode(None, None).unwrap();
    assert_eq!(msg, expected_msg);
}

```
## cose-mac0

### Encode cose-mac0 message
```rust
use cose::mac::CoseMAC;
use cose::keys;
use cose::algs;

fn main() {
    let msg = b"This is the content.".to_vec();

    // Prepare the cose-key
    let mut key = keys::CoseKey::new();
    key.kty(keys::SYMMETRIC);
    key.alg(algs::AES_MAC_256_128);
    key.k(hex::decode("849b57219dae48de646d07dbb533566e976686457c1491be3a76dcea6c427188").unwrap());
    key.key_ops(vec![keys::KEY_OPS_MAC]);

    // Prepare the cose-mac0 message
    let mut mac0 = CoseMAC::new();
    mac0.header.alg(algs::AES_MAC_256_128, true, false);

    // Add the payload
    mac0.payload(msg);
     
    // Add cose-key
    mac0.key(&key).unwrap();

    // Generate MAC tag without AAD
    mac0.gen_tag(None).unwrap();
    // Encode the cose-mac0 message with the payload included
    mac0.encode(true).unwrap();

}
```

### Decode cose-mac0 message
```rust
use cose::mac::CoseMAC;
use cose::keys;
use cose::algs;

fn main() {
    // Prepare the cose-key
    let mut key = keys::CoseKey::new();
    key.kty(keys::SYMMETRIC);
    key.alg(algs::AES_MAC_256_128);
    key.k(hex::decode("849b57219dae48de646d07dbb533566e976686457c1491be3a76dcea6c427188").unwrap());
    key.key_ops(vec![keys::KEY_OPS_MAC_VERIFY]);

    // Generate CoseMAC struct with the cose-mac0 message to decode
    let mut verify = CoseMAC::new();
    verify.bytes =
    hex::decode("d18444a101181aa054546869732069732074686520636f6e74656e742e50403152cc208c1d501e1dc2a789ae49e4").unwrap();

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
