//! CBOR Object Signing and Encryption, COSE ([RFC 8152](https://tools.ietf.org/html/rfc8152)), implementation for Rust.
//!
//! This library offers a set of methods and structures to help encoding/decoding a COSE message,
//! including the respective cryptographic operations with the given parameters.
//!
//! The cryptographic functions used in this library are from the
//! [rust-openssl](https://crates.io/crates/openssl) and [rand](https://crates.io/crates/rand) crates and
//! the CBOR encoding/decoding methods are from the
//! [cbor-codec](https://twittner.gitlab.io/cbor-codec/cbor/) crate.
//!
//! # Examples
//!
//! The following examples, show how to encode and decode COSE messages in different types without
//! the recipients bucket. Multiple recipients examples are also present in the
//! modules [sign](sign/index.html), [encrypt](encrypt/index.html) and [mac](encrypt/mac.html).
//!
//! ## cose-sign1
//!
//! ```
//! use cose::sign;
//! use cose::keys;
//! use cose::algs;
//!
//! fn main() {
//!     let msg = b"signed message".to_vec();
//!
//!     // Prepare cose-sign1 headers
//!     let mut sign1 = sign::CoseSign::new();
//!     sign1.header.alg(algs::EDDSA, true, false);
//!     sign1.header.kid(b"kid1".to_vec(), true, false);
//!
//!     // Add the payload
//!     sign1.payload(msg);
//!
//!     // Prepare the cose-key
//!     let mut key = keys::CoseKey::new();
//!     key.kty(keys::EC2);
//!     key.alg(algs::EDDSA);
//!     key.crv(keys::ED25519);
//!     key.x(vec![215, 90, 152, 1, 130, 177, 10, 183, 213, 75, 254, 211, 201, 100, 7, 58, 14, 225, 114, 243, 218, 166, 35, 37, 175, 2, 26, 104, 247, 7, 81, 26]);
//!     key.d(vec![157, 97, 177, 157, 239, 253, 90, 96, 186, 132, 74, 244, 146, 236, 44, 196, 68, 73, 197, 105, 123, 50, 105, 25, 112, 59, 172, 3, 28, 174, 127, 96]);
//!     key.key_ops(vec![keys::KEY_OPS_SIGN, keys::KEY_OPS_VERIFY]);
//!
//!     // Add key to the cose-sign1 structure
//!     sign1.key(&key).unwrap();
//!
//!     // Generate the signature without AAD
//!     sign1.gen_signature(None).unwrap();
//!     // Encode the cose-sign1 message with the payload included in the message
//!     sign1.encode(true).unwrap();
//!
//!     // Prepare verifier
//!     let mut verify = sign::CoseSign::new();
//!     // Add the cose-sign1 message generated
//!     verify.bytes = sign1.bytes;
//!     // Initial decoding of the message
//!     verify.init_decoder(None).unwrap();
//!
//!     // Add cose-key
//!     verify.key(&key).unwrap();
//!     // Verify cose-sign1 signature
//!     verify.decode(None, None).unwrap();
//! }
//! ```
//!
//! ## cose-encrypt0
//! ```
//! use cose::encrypt;
//! use cose::keys;
//! use cose::algs;
//!
//! fn main() {
//!     let msg = b"encrypted message".to_vec();
//!     let k = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F";
//!     let iv = b"\x00\x01\x02\x03\x04\x05\x06\x07\x00\x01\x02\x03";
//!
//!     // Prepare cose-encrypt0 headers
//!     let mut enc0 = encrypt::CoseEncrypt::new();
//!     enc0.header.alg(algs::CHACHA20, true, false);
//!     enc0.header.kid(b"kid2".to_vec(), true, false);
//!     enc0.header.iv(iv.to_vec(), true, false);
//!
//!     // Add the payload
//!     enc0.payload(msg);
//!
//!     // Prepare the cose-key
//!     let mut key = keys::CoseKey::new();
//!     key.kty(keys::SYMMETRIC);
//!     key.alg(algs::CHACHA20);
//!     key.k(k.to_vec());
//!     key.key_ops(vec![keys::KEY_OPS_ENCRYPT, keys::KEY_OPS_DECRYPT]);
//!
//!     // Add cose-key
//!     enc0.key(&key).unwrap();
//!
//!     // Generate the ciphertext with no AAD.
//!     enc0.gen_ciphertext(None).unwrap();
//!     // Encode the cose-encrypt0 message with the ciphertext included in the message
//!     enc0.encode(true).unwrap();
//!
//!     // Prepare decrypter
//!     let mut dec0 = encrypt::CoseEncrypt::new();
//!     // Add the cose-encrypt0 message generated
//!     dec0.bytes = enc0.bytes;
//!     // Initial decoding of the message
//!     dec0.init_decoder().unwrap();
//!
//!     // Add cose-key
//!     dec0.key(&key).unwrap();
//!
//!     // Decrypt the cose-encrypt0 message
//!     let resp = dec0.decode(None, None).unwrap();
//!     assert_eq!(resp, b"encrypted message".to_vec());
//! }
//!
//! ```
//!
//! ## cose-mac0
//!
//! ```
//! use cose::mac;
//! use cose::keys;
//! use cose::algs;
//!
//! fn main() {
//!     let msg = b"tagged message".to_vec();
//!
//!     // Prepare the cose-mac0 headers
//!     let mut mac0 = mac::CoseMAC::new();
//!     mac0.header.alg(algs::AES_MAC_256_128, true, false);
//!     mac0.header.kid(b"kid2".to_vec(), true, false);
//!
//!     // Add the payload
//!     mac0.payload(msg);
//!      
//!     // Prepare the cose-key
//!     let mut key = keys::CoseKey::new();
//!     key.kty(keys::SYMMETRIC);
//!     key.alg(algs::AES_MAC_256_128);
//!     key.k(b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F".to_vec());
//!     key.key_ops(vec![keys::KEY_OPS_MAC, keys::KEY_OPS_MAC_VERIFY]);
//!     
//!     // Add cose-key
//!     mac0.key(&key).unwrap();
//!
//!     // Generate MAC tag without AAD
//!     mac0.gen_tag(None).unwrap();
//!     // Encode the cose-mac0 message with the payload included
//!     mac0.encode(true).unwrap();
//!
//!     // Prepare the verifier
//!     let mut verify = mac::CoseMAC::new();
//!     // Add the cose-mac0 message generated
//!     verify.bytes = mac0.bytes;
//!     // Initial decoding of the message
//!     verify.init_decoder().unwrap();
//!
//!     // Add cose-key
//!     verify.key(&key).unwrap();
//!     // Verify the MAC tag of the cose-mac0 message
//!     verify.decode(None, None).unwrap();
//! }
//! ```

pub mod headers;
pub mod keys;

pub mod algs;
pub mod encrypt;
pub mod mac;
pub mod recipients;
pub mod sign;

pub(in crate) mod common;
pub mod errors;
pub mod utils;

pub(in crate) mod enc_struct;
pub(in crate) mod kdf_struct;
pub(in crate) mod mac_struct;
pub(in crate) mod sig_struct;
