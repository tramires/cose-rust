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
//! The following examples, demonstrate how to encode and decode COSE messages in different types without
//! the recipients/signers bucket. Examples with the recipients/signers bucket can be found in the modules
//! [message](message/index.html) and [agent](agent/index.html).
//!
//! ## cose-sign1
//!
//! ### Encode cose-sign1 message
//! ```
//! use cose::message::CoseMessage;
//! use cose::keys;
//! use cose::algs;
//! use hex;
//!
//! fn main() {
//!     let msg = b"This is the content.".to_vec();
//!     let kid = vec![49, 49];
//!
//!     let mut signer = CoseMessage::new_sign();
//!
//!     // Prepare cose-key
//!     let mut key = keys::CoseKey::new();
//!     key.set_kty(keys::EC2);
//!     key.set_alg(algs::ES256);
//!     key.set_crv(keys::P_256);
//!     key.set_d(hex::decode("57c92077664146e876760c9520d054aa93c3afb04e306705db6090308507b4d3").unwrap());
//!
//!     // Prepare cose-sign1 parameters
//!     signer.header.set_alg(algs::ES256, true, false);
//!     signer.header.set_kid(kid, true, false);
//!     signer.payload = msg;
//!     signer.key(&key).unwrap();
//!
//!     // Generate the signature
//!     signer.secure_content(None).unwrap();
//!
//!     // Encode the message with the payload included
//!     signer.encode(true).unwrap();
//! }
//! ```
//!
//! ### Decode cose-sign1 message
//! ```
//! use cose::message::CoseMessage;
//! use cose::keys;
//! use cose::algs;
//! use hex;
//!
//! fn main() {
//!
//!     // Prepare cose-key
//!     let mut key = keys::CoseKey::new();
//!     key.set_kty(keys::EC2);
//!     key.set_alg(algs::ES256);
//!     key.set_crv(keys::P_256);
//!     key.set_x(hex::decode("bac5b11cad8f99f9c72b05cf4b9e26d244dc189f745228255a219a86d6a09eff").unwrap());
//!     key.set_y(hex::decode("20138bf82dc1b6d562be0fa54ab7804a3a64b6d72ccfed6b6fb6ed28bbfc117e").unwrap());
//!     
//!     // Prepare CoseSign with the cose-sign1 bytes
//!     let mut verify = CoseMessage::new_sign();
//!     verify.bytes =
//!     hex::decode("d28447a2012604423131a054546869732069732074686520636f6e74656e742e58405e84ce5812b0966e6919ff1ac15c030666bae902c0705d1e0a5fbac828437c63b0bb87a95a456835f4d115850adefcf0fd0a5c26027140c10d3e20a890c5eaa7").unwrap();
//!
//!     // Init decoding
//!     verify.init_decoder(None).unwrap();
//!
//!     // Add key
//!     verify.key(&key).unwrap();
//!
//!     // Verify the cose-sign1 signature
//!     verify.decode(None, None).unwrap();
//! }
//! ```
//!
//! ## cose-encrypt0
//!
//! ### Encode cose-encrypt0 message
//! ```
//! use cose::message::CoseMessage;
//! use cose::keys;
//! use cose::algs;
//! use hex;
//!
//! fn main() {
//!     let msg = b"This is the content.".to_vec();
//!     let kid = b"secret".to_vec();
//!
//!     let mut enc = CoseMessage::new_encrypt();
//!
//!     // Prepare the cose-key
//!     let mut key = keys::CoseKey::new();
//!     key.set_kty(keys::SYMMETRIC);
//!     key.set_alg(algs::CHACHA20);
//!     key.set_k(hex::decode("849b57219dae48de646d07dbb533566e976686457c1491be3a76dcea6c427188").unwrap());
//!
//!     // Prepare cose-encrypt0 parameters
//!     enc.header.set_alg(algs::CHACHA20, true, false);
//!     enc.header.set_iv(hex::decode("89f52f65a1c580933b5261a7").unwrap(), true, false);
//!     enc.payload = msg;
//!     enc.key(&key).unwrap();
//!
//!     // Generate the ciphertext with no AAD.
//!     enc.secure_content(None).unwrap();
//!
//!     // Encode the cose-encrypt0 message with the ciphertext included
//!     enc.encode(true).unwrap();
//! }
//!
//! ```
//!
//! ### Decode cose-encrypt0 message
//! ```
//! use cose::message::CoseMessage;
//! use cose::keys;
//! use cose::algs;
//! use hex;
//!
//! fn main() {
//!     let expected_msg = b"This is the content.".to_vec();
//!
//!     // Prepare the cose-key
//!     let mut key = keys::CoseKey::new();
//!     key.set_kty(keys::SYMMETRIC);
//!     key.set_alg(algs::CHACHA20);
//!     key.set_k(hex::decode("849b57219dae48de646d07dbb533566e976686457c1491be3a76dcea6c427188").unwrap());
//!
//!
//!     // Generate CoseEncrypt struct with the cose-encryt0 bytes
//!     let mut dec = CoseMessage::new_encrypt();
//!     dec.bytes =
//!     hex::decode("d08352a2011818054c89f52f65a1c580933b5261a7a0582481c32c048134989007b3b5b932811ea410eeab15bd0de5d5ac5be03c84dce8c88871d6e9").unwrap();
//!
//!     // Init decoding
//!     dec.init_decoder(None).unwrap();
//!
//!     // Add cose-key
//!     dec.key(&key).unwrap();
//!
//!     // Decrypt the cose-encrypt0 message
//!     let msg = dec.decode(None, None).unwrap();
//!     assert_eq!(msg, expected_msg);
//! }
//!
//! ```
//! ## cose-mac0
//!
//! ### Encode cose-mac0 message
//! ```
//! use cose::message::CoseMessage;
//! use cose::keys;
//! use cose::algs;
//! use hex;
//!
//! fn main() {
//!     let msg = b"This is the content.".to_vec();
//!
//!     // Prepare the cose-key
//!     let mut key = keys::CoseKey::new();
//!     key.set_kty(keys::SYMMETRIC);
//!     key.set_alg(algs::AES_MAC_256_128);
//!     key.set_k(hex::decode("849b57219dae48de646d07dbb533566e976686457c1491be3a76dcea6c427188").unwrap());
//!
//!     // Prepare the cose-mac0 parameters
//!     let mut mac = CoseMessage::new_mac();
//!     mac.header.set_alg(algs::AES_MAC_256_128, true, false);
//!     mac.payload = msg;
//!     mac.key(&key).unwrap();
//!
//!     // Generate MAC tag without AAD
//!     mac.secure_content(None).unwrap();
//!
//!     // Encode the cose-mac0 message with the payload included
//!     mac.encode(true).unwrap();
//!
//! }
//! ```
//!
//! ### Decode cose-mac0 message
//! ```
//! use cose::message::CoseMessage;
//! use cose::keys;
//! use cose::algs;
//! use hex;
//!
//! fn main() {
//!     // Prepare the cose-key
//!     let mut key = keys::CoseKey::new();
//!     key.set_kty(keys::SYMMETRIC);
//!     key.set_alg(algs::AES_MAC_256_128);
//!     key.set_k(hex::decode("849b57219dae48de646d07dbb533566e976686457c1491be3a76dcea6c427188").unwrap());
//!
//!     // Generate CoseMAC struct with the cose-mac0 bytes
//!     let mut verify = CoseMessage::new_mac();
//!     verify.bytes =
//!     hex::decode("d18444a101181aa054546869732069732074686520636f6e74656e742e50403152cc208c1d501e1dc2a789ae49e4").unwrap();
//!
//!     // Init decoding
//!     verify.init_decoder(None).unwrap();
//!
//!     // Add cose-key
//!     verify.key(&key).unwrap();
//!
//!     // Verify the cose-mac0 message
//!     verify.decode(None, None).unwrap();
//! }
//! ```

// Macro for getters
macro_rules! getters {
    (deref: $($(#[$doc:meta])* $name:ident -> $ret:ty),* $(,)?) => {
        $($(#[$doc])* #[must_use] pub fn $name(&self) -> $ret { self.$name.as_deref() })*
    };
    (copy: $($(#[$doc:meta])* $name:ident -> $ret:ty),* $(,)?) => {
        $($(#[$doc])* #[must_use] pub fn $name(&self) -> $ret { self.$name })*
    };
    (by_ref: $($(#[$doc:meta])* $name:ident -> $ret:ty),* $(,)?) => {
        $($(#[$doc])* #[must_use] pub fn $name(&self) -> $ret { &self.$name })*
    };
}

pub mod headers;
pub mod keys;

pub mod agent;
pub mod algs;
pub mod message;

pub mod errors;

pub(crate) mod common;
pub(crate) mod cose_struct;
