//! Module to encode/decode COSE messages.
//!
//! # Examples
//!
//! ## cose-sign1
//!
//! cose-sign1 message with ECDSA w/ SHA-256  algorithm
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
//!     let kid = b"11".to_vec();
//!
//!     // cose-key to encode the message
//!     let mut key = keys::CoseKey::new();
//!     key.kty(keys::EC2);
//!     key.alg(algs::ES256);
//!     key.crv(keys::P_256);
//!     key.x(hex::decode("bac5b11cad8f99f9c72b05cf4b9e26d244dc189f745228255a219a86d6a09eff").unwrap());
//!     key.y(hex::decode("20138bf82dc1b6d562be0fa54ab7804a3a64b6d72ccfed6b6fb6ed28bbfc117e").unwrap());
//!     key.d(hex::decode("57c92077664146e876760c9520d054aa93c3afb04e306705db6090308507b4d3").unwrap());
//!     key.key_ops(vec![keys::KEY_OPS_SIGN, keys::KEY_OPS_VERIFY]);
//!
//!     // Prepare cose_sign1 message
//!     let mut sign1 = CoseMessage::new_sign();
//!     sign1.header.alg(algs::ES256, true, false);
//!     sign1.header.kid(kid, true, false);
//!     sign1.payload(msg);
//!     sign1.key(&key).unwrap();
//!
//!     // Generate the Signature
//!     sign1.secure_content(None).unwrap();
//!
//!     // Encode the message with the payload
//!     sign1.encode(true).unwrap();
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
//!     // COSE_KEY to decode the message
//!     let mut key = keys::CoseKey::new();
//!     key.kty(keys::EC2);
//!     key.alg(algs::ES256);
//!     key.crv(keys::P_256);
//!     key.x(hex::decode("bac5b11cad8f99f9c72b05cf4b9e26d244dc189f745228255a219a86d6a09eff").unwrap());
//!     key.y(hex::decode("20138bf82dc1b6d562be0fa54ab7804a3a64b6d72ccfed6b6fb6ed28bbfc117e").unwrap());
//!     key.d(hex::decode("57c92077664146e876760c9520d054aa93c3afb04e306705db6090308507b4d3").unwrap());
//!     key.key_ops(vec![keys::KEY_OPS_SIGN, keys::KEY_OPS_VERIFY]);
//!
//!     // Generate CoseSign struct with the cose-sign1 message to decode
//!     let mut verify = CoseMessage::new_sign();
//!     verify.bytes =
//!     hex::decode("d28447a2012604423131a054546869732069732074686520636f6e74656e742e5840dc93ddf7d5aff58131589087eaa65eeffa0baf2e72201ee91c0ca876ec42fdfb2a67dbc6ea1a95d2257cec645cf789808c0a392af045e2bc1bdb6746d80f221b").unwrap();
//!
//!     // Initial decoding
//!     verify.init_decoder(None).unwrap();
//!
//!     // Add key and verify the signature
//!     verify.key(&key).unwrap();
//!     verify.decode(None, None).unwrap();
//! }
//! ```
//!
//! ## cose-sign
//!
//! Encode and decode cose-sign message with 2 signers, both using ECDSA w/ SHA-256
//!
//! ### Encode cose-sign message
//! ```
//! use cose::message::CoseMessage;
//! use cose::keys;
//! use cose::algs;
//! use cose::agent::CoseAgent;
//! use hex;
//!
//! fn main() {
//!     let msg = b"This is the content.".to_vec();
//!     let s1_kid = b"11".to_vec();
//!     let s2_kid = b"22".to_vec();
//!
//!     // Prepare signer 1 key
//!     let mut s1_key = keys::CoseKey::new();
//!     s1_key.kty(keys::EC2);
//!     s1_key.alg(algs::ES256);
//!     s1_key.crv(keys::P_256);
//!     s1_key.d(hex::decode("57c92077664146e876760c9520d054aa93c3afb04e306705db6090308507b4d3").unwrap());
//!     s1_key.key_ops(vec![keys::KEY_OPS_SIGN]);
//!
//!     // Prepare signer 2 key
//!     let mut s2_key = keys::CoseKey::new();
//!     s2_key.kty(keys::OKP);
//!     s2_key.alg(algs::EDDSA);
//!     s2_key.crv(keys::ED25519);
//!     s2_key.d(hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60").unwrap());
//!     s2_key.key_ops(vec![keys::KEY_OPS_SIGN]);
//!
//!     // Prepare cose-sign message
//!     let mut sign = CoseMessage::new_sign();
//!     sign.payload(msg);
//!
//!     // Add signer 1
//!     let mut signer1 = CoseAgent::new();
//!     signer1.header.alg(algs::ES256, true, false);
//!     signer1.header.kid(s1_kid.clone(), false, false);
//!     signer1.key(&s1_key).unwrap();
//!     sign.add_agent(&mut signer1).unwrap();
//!
//!     // Add signer 2
//!     let mut signer2 = CoseAgent::new();
//!     signer2.header.alg(algs::EDDSA, true, false);
//!     signer2.header.kid(s2_kid.clone(), false, false);
//!     signer2.key(&s2_key).unwrap();
//!     sign.add_agent(&mut signer2).unwrap();
//!
//!     // Generate signature without AAD
//!     sign.secure_content(None).unwrap();
//!
//!     // Encode the cose-sign message
//!     sign.encode(true).unwrap();
//!
//! }
//! ```
//!
//! ### Decode cose-sign message
//! ```
//! use cose::message::CoseMessage;
//! use cose::keys;
//! use cose::algs;
//! use cose::agent::CoseAgent;
//! use hex;
//!
//! fn main() {
//!     let s1_kid = b"11".to_vec();
//!     let s2_kid = b"22".to_vec();
//!
//!     // Prepare signer 1 key
//!     let mut s1_key = keys::CoseKey::new();
//!     s1_key.kty(keys::EC2);
//!     s1_key.alg(algs::ES256);
//!     s1_key.crv(keys::P_256);
//!     s1_key.kid(b"1".to_vec());
//!     s1_key.x(hex::decode("bac5b11cad8f99f9c72b05cf4b9e26d244dc189f745228255a219a86d6a09eff").unwrap());
//!     s1_key.y(hex::decode("20138bf82dc1b6d562be0fa54ab7804a3a64b6d72ccfed6b6fb6ed28bbfc117e").unwrap());
//!     s1_key.key_ops(vec![keys::KEY_OPS_VERIFY]);
//!
//!     // Prepare signer 2 key
//!     let mut s2_key = keys::CoseKey::new();
//!     s2_key.kty(keys::OKP);
//!     s2_key.alg(algs::EDDSA);
//!     s2_key.crv(keys::ED25519);
//!     s2_key.x(hex::decode("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a").unwrap());
//!     s2_key.key_ops(vec![keys::KEY_OPS_VERIFY]);
//!
//!     // Generate CoseSign with the cose-sign message to decode
//!     let mut verify = CoseMessage::new_sign();
//!     verify.bytes =
//!     hex::decode("d8628440a054546869732069732074686520636f6e74656e742e828343a10126a1044231315840a45d63392d72cfef8bd08ec6a17e40364f8b3094558f1f8078c497718de536dceadfb4a637804b31e21572ba3714e03b0b5510e243b0240c252da3a827ba4e998343a10127a104423232584081d92439ecaf31f11f611054346d50b5fbd4e5cfe00c1c237cf673fa3948678b378eacd5eecf6f680980f818a8ecc57a8b4c733ec2fd8d03ae3ba04a02ea4a06").unwrap();
//!     verify.init_decoder(None).unwrap();
//!
//!     // Get signer 1 and verify
//!     let mut index1 = verify.get_agent(&s1_kid).unwrap()[0];
//!     verify.agents[index1].key(&s1_key).unwrap();
//!     verify.decode(None, Some(index1)).unwrap();
//!
//!     // Get signer 2 and verify
//!     let mut index2 = verify.get_agent(&s2_kid).unwrap()[0];
//!     verify.agents[index2].key(&s2_key).unwrap();
//!     verify.decode(None, Some(index2)).unwrap();
//! }
//! ```
//! //! ## cose-encrypt0
//!
//! cose-encrypt0 message with ChaCha20/Poly1305 algorithm
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
//!     // Prepare the cose-key
//!     let mut key = keys::CoseKey::new();
//!     key.kty(keys::SYMMETRIC);
//!     key.alg(algs::CHACHA20);
//!     key.k(hex::decode("849b57219dae48de646d07dbb533566e976686457c1491be3a76dcea6c427188").unwrap());
//!     key.key_ops(vec![keys::KEY_OPS_ENCRYPT, keys::KEY_OPS_DECRYPT]);
//!
//!     // Prepare cose-encrypt0 message
//!     let mut enc0 = CoseMessage::new_encrypt();
//!     enc0.header.alg(algs::CHACHA20, true, false);
//!     enc0.header.iv(hex::decode("89f52f65a1c580933b5261a7").unwrap(), true, false);
//!     enc0.payload(msg);
//!     enc0.key(&key).unwrap();
//!
//!     // Generate the ciphertext with no AAD.
//!     enc0.secure_content(None).unwrap();
//!     // Encode the cose-encrypt0 message with the ciphertext included
//!     enc0.encode(true).unwrap();
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
//!     key.kty(keys::SYMMETRIC);
//!     key.alg(algs::CHACHA20);
//!     key.k(hex::decode("849b57219dae48de646d07dbb533566e976686457c1491be3a76dcea6c427188").unwrap());
//!     key.key_ops(vec![keys::KEY_OPS_ENCRYPT, keys::KEY_OPS_DECRYPT]);
//!
//!
//!     // Generate CoseEncrypt struct with the cose-encrypt0 message to decode
//!     let mut dec0 = CoseMessage::new_encrypt();
//!     dec0.bytes =
//!     hex::decode("d08352a2011818054c89f52f65a1c580933b5261a7a0582481c32c048134989007b3b5b932811ea410eeab15bd0de5d5ac5be03c84dce8c88871d6e9").unwrap();
//!
//!     // Initial decoding of the message
//!     dec0.init_decoder(None).unwrap();
//!
//!     // Add cose-key
//!     dec0.key(&key).unwrap();
//!
//!     // Decrypt the cose-encrypt0 message
//!     let msg = dec0.decode(None, None).unwrap();
//!     assert_eq!(msg, expected_msg);
//! }
//!
//! ```
//!
//! ## cose-encrypt
//!
//! Encode and decode cose-encrypt message with AES-GCM algorithm with 2 recipients, one using [A128KW](../algs/constant.A128KW.html) as the key agreement and the other using the [ECDH-ES +
//! A128KW](../algs/constant.ECDH_ES_A128KW.html) key agreement.
//!
//! ### Encode cose-encrypt message
//! ```
//! use cose::message::CoseMessage;
//! use cose::keys;
//! use cose::headers;
//! use cose::algs;
//! use cose::agent::CoseAgent;
//! use hex;
//!
//! fn main() {
//!     let msg = b"This is the content.".to_vec();
//!     let r1_kid = b"11".to_vec();
//!     let r2_kid = b"22".to_vec();
//!
//!     // Prepare recipient 1 cose-key
//!     let mut r1_key = keys::CoseKey::new();
//!     r1_key.kty(keys::SYMMETRIC);
//!     r1_key.alg(algs::A128KW);
//!     r1_key.k(hex::decode("849b57219dae48de646d07dbb533566e976686457c1491be3a76dcea6c427188").unwrap());
//!     r1_key.key_ops(vec![keys::KEY_OPS_WRAP, keys::KEY_OPS_UNWRAP]);
//!
//!     // Prepare recipient 2 cose-key
//!     let mut r2_key = keys::CoseKey::new();
//!     r2_key.kty(keys::EC2);
//!     r2_key.crv(keys::P_256);
//!     r2_key.x(hex::decode("98F50A4FF6C05861C8860D13A638EA56C3F5AD7590BBFBF054E1C7B4D91D6280").unwrap());
//!
//!     // Prepare recipient 2 sender ephermeral ECDH key
//!     let mut r2_eph_key = keys::CoseKey::new();
//!     r2_eph_key.kty(keys::EC2);
//!     r2_eph_key.crv(keys::P_256);
//!     r2_eph_key.x(hex::decode("bac5b11cad8f99f9c72b05cf4b9e26d244dc189f745228255a219a86d6a09eff").unwrap());
//!     r2_eph_key.d(hex::decode("57c92077664146e876760c9520d054aa93c3afb04e306705db6090308507b4d3").unwrap());
//!
//!     // Prepare cose-encrypt message
//!     let mut enc = CoseMessage::new_encrypt();
//!     enc.header.alg(algs::A256GCM, true, false);
//!     enc.header.iv(hex::decode("89f52f65a1c580933b5261a7").unwrap(), true, false);
//!     enc.payload(msg);
//!
//!     // Add recipient 1 (A128KW)
//!     let mut recipient1 = CoseAgent::new();
//!     recipient1.header.alg(algs::A128KW, true, false);
//!     recipient1.header.kid(r1_kid.clone(), false, false);
//!     recipient1.key(&r1_key).unwrap();
//!     enc.add_agent(&mut recipient1).unwrap();
//!
//!     // Add recipient 2 (ECDH_ES_A128KW)
//!     let mut recipient2 = CoseAgent::new();
//!     recipient2.header.alg(algs::ECDH_ES_A128KW, true, false);
//!     recipient2.header.kid(r2_kid.clone(), false, false);
//!     recipient2.key(&r2_key).unwrap();
//!     recipient2.header.ephemeral_key(r2_eph_key, true, false);
//!     enc.add_agent(&mut recipient2).unwrap();
//!
//!     // Generate ciphertext without AAD
//!     enc.secure_content(None).unwrap();
//!
//!     // Encode the cose-encrypt message
//!     enc.encode(true).unwrap();
//! }
//! ```
//!
//! ### Decode cose-encrypt message
//! ```
//! use cose::message::CoseMessage;
//! use cose::keys;
//! use cose::headers;
//! use cose::algs;
//! use cose::agent::CoseAgent;
//! use hex;
//!
//! fn main() {
//!     let msg = b"This is the content.".to_vec();
//!     let r1_kid = b"11".to_vec();
//!     let r2_kid = b"22".to_vec();
//!
//!     // Prepare recipient 1 key
//!     let mut r1_key = keys::CoseKey::new();
//!     r1_key.kty(keys::SYMMETRIC);
//!     r1_key.alg(algs::A128KW);
//!     r1_key.k(hex::decode("849b57219dae48de646d07dbb533566e976686457c1491be3a76dcea6c427188").unwrap());
//!     r1_key.key_ops(vec![keys::KEY_OPS_WRAP, keys::KEY_OPS_UNWRAP]);
//!
//!     // Prepare recipient 2 key
//!     let mut r2_key = keys::CoseKey::new();
//!     r2_key.kty(keys::EC2);
//!     r2_key.crv(keys::P_256);
//!     r2_key.x(hex::decode("98F50A4FF6C05861C8860D13A638EA56C3F5AD7590BBFBF054E1C7B4D91D6280").unwrap());
//!     r2_key.y(hex::decode("F01400B089867804B8E9FC96C3932161F1934F4223069170D924B7E03BF822BB").unwrap());
//!     r2_key.d(hex::decode("02D1F7E6F26C43D4868D87CEB2353161740AACF1F7163647984B522A848DF1C3").unwrap());
//!
//!     // Generate CoseEncrypt struct with the cose-encrypt message to decode
//!     let mut dec = CoseMessage::new_encrypt();
//!     dec.bytes =
//!     hex::decode("d8608451a20103054c89f52f65a1c580933b5261a7a058243e102aa2950238585d10e72c9d485352814e3ce00ac7482fb08538225622248e4daa3d06828343a10122a104423131582800e14bb6ac7246738dc6cd8232340fb37623c7a2667e474a0c56cc6f742f2d3f15969b5c58351fea835832a201381c20a5010203262001215820bac5b11cad8f99f9c72b05cf4b9e26d244dc189f745228255a219a86d6a09eff048107a1044232325828f9b936b424c591bd5491916e98e4d6d71a4ea6fdf6a2c193718825787fac8d4c1df2c4f8473243c9").unwrap();
//!     dec.init_decoder(None).unwrap();
//!
//!     // Get recipient 1 and decode message
//!     let mut r1_i = dec.get_agent(&r1_kid).unwrap()[0];
//!     dec.agents[r1_i].key(&r1_key).unwrap();
//!     let resp = dec.decode(None, Some(r1_i)).unwrap();
//!     assert_eq!(resp, msg);
//!
//!     // Get recipient 2 and decode message
//!     let mut r2_i = dec.get_agent(&r2_kid).unwrap()[0];
//!     dec.agents[r2_i].key(&r2_key).unwrap();
//!     let resp2 = dec.decode(None, Some(r2_i)).unwrap();
//!     assert_eq!(resp2, msg);
//! }
//! ```
//! //! ## cose-mac0
//!
//! Encode and decode cose-mac0 message with AES-MAC algorithm
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
//!     key.kty(keys::SYMMETRIC);
//!     key.alg(algs::AES_MAC_256_128);
//!     key.k(hex::decode("849b57219dae48de646d07dbb533566e976686457c1491be3a76dcea6c427188").unwrap());
//!     key.key_ops(vec![keys::KEY_OPS_MAC, keys::KEY_OPS_MAC_VERIFY]);
//!
//!     // Prepare the cose-mac0 message
//!     let mut mac0 = CoseMessage::new_mac();
//!     mac0.header.alg(algs::AES_MAC_256_128, true, false);
//!
//!     // Add the payload
//!     mac0.payload(msg);
//!
//!     // Add cose-key
//!     mac0.key(&key).unwrap();
//!
//!     // Generate MAC tag without AAD
//!     mac0.secure_content(None).unwrap();
//!     // Encode the cose-mac0 message with the payload included
//!     mac0.encode(true).unwrap();
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
//!     key.kty(keys::SYMMETRIC);
//!     key.alg(algs::AES_MAC_256_128);
//!     key.k(hex::decode("849b57219dae48de646d07dbb533566e976686457c1491be3a76dcea6c427188").unwrap());
//!     key.key_ops(vec![keys::KEY_OPS_MAC, keys::KEY_OPS_MAC_VERIFY]);
//!
//!     // Generate CoseMAC struct with the cose-mac0 message to decode
//!     let mut verify = CoseMessage::new_mac();
//!     verify.bytes =
//!     hex::decode("d18444a101181aa054546869732069732074686520636f6e74656e742e50403152cc208c1d501e1dc2a789ae49e4").unwrap();
//!
//!     // Initial decoding of the message
//!     verify.init_decoder(None).unwrap();
//!
//!     // Add cose-key
//!     verify.key(&key).unwrap();
//!     // Verify the MAC tag of the cose-mac0 message
//!     verify.decode(None, None).unwrap();
//! }
//! ```
//!
//! ## MAC
//!
//! Encode and decode cose-mac message with AES-MAC algorithm with 2 recipients, one using [A128KW](../algs/constant.A128KW.html) as the key agreement and the other using the [ECDH-ES +
//! A128KW](../algs/constant.ECDH_ES_A128KW.html) key agreement.
//!
//! ### Encode cose-mac message
//!
//! ```
//! use cose::message::CoseMessage;
//! use cose::keys;
//! use cose::algs;
//! use cose::agent::CoseAgent;
//! use hex;
//!
//! fn main() {
//!     let msg = b"This is the content.".to_vec();
//!     let r1_kid = b"11".to_vec();
//!     let r2_kid = b"22".to_vec();
//!
//!     // Prepare recipient 1 cose-key
//!     let mut r1_key = keys::CoseKey::new();
//!     r1_key.kty(keys::SYMMETRIC);
//!     r1_key.alg(algs::A128KW);
//!     r1_key.k(hex::decode("849b57219dae48de646d07dbb533566e976686457c1491be3a76dcea6c427188").unwrap());
//!     r1_key.key_ops(vec![keys::KEY_OPS_WRAP, keys::KEY_OPS_UNWRAP]);
//!
//!     // Prepare recipient 2 cose-key
//!     let mut r2_key = keys::CoseKey::new();
//!     r2_key.kty(keys::EC2);
//!     r2_key.crv(keys::P_256);
//!     r2_key.x(hex::decode("98F50A4FF6C05861C8860D13A638EA56C3F5AD7590BBFBF054E1C7B4D91D6280").unwrap());
//!
//!     // Prepare recipient 2 sender ephemeral key
//!     let mut r2_eph_key = keys::CoseKey::new();
//!     r2_eph_key.kty(keys::EC2);
//!     r2_eph_key.crv(keys::P_256);
//!     r2_eph_key.x(hex::decode("bac5b11cad8f99f9c72b05cf4b9e26d244dc189f745228255a219a86d6a09eff").unwrap());
//!     r2_eph_key.d(hex::decode("57c92077664146e876760c9520d054aa93c3afb04e306705db6090308507b4d3").unwrap());
//!
//!     // Prepare CoseMAC message
//!     let mut mac = CoseMessage::new_mac();
//!     mac.header.alg(algs::AES_MAC_256_128, true, false);
//!     mac.payload(msg);
//!
//!     // Add recipient 1 (A128KW)
//!     let mut recipient1 = CoseAgent::new();
//!     recipient1.header.alg(algs::A128KW, true, false);
//!     recipient1.header.kid(r1_kid.clone(), false, false);
//!     recipient1.key(&r1_key).unwrap();
//!     mac.add_agent(&mut recipient1).unwrap();
//!
//!     // Add recipient 2 (ECDH_ES_A128KW)
//!     let mut recipient2 = CoseAgent::new();
//!     recipient2.header.alg(algs::ECDH_ES_A128KW, true, false);
//!     recipient2.header.kid(r2_kid.clone(), false, false);
//!     recipient2.header.salt(vec![0; 32], false, false);
//!     recipient2.key(&r2_key).unwrap();
//!     recipient2.header.ephemeral_key(r2_eph_key.clone(), true, false);
//!     mac.add_agent(&mut recipient2).unwrap();
//!
//!     // Generate tag without AAD
//!     mac.secure_content(None).unwrap();
//!
//!     // Encode the cose-mac message
//!     mac.encode(true).unwrap();
//!
//! }
//! ```
//!
//! ### Decode cose-mac message
//!
//! ```
//! use cose::message::CoseMessage;
//! use cose::keys;
//! use cose::algs;
//! use cose::agent::CoseAgent;
//! use hex;
//!
//! fn main() {
//!     let r1_kid = b"11".to_vec();
//!     let r2_kid = b"22".to_vec();
//!
//!     // Prepare recipient 1 cose-key
//!     let mut r1_key = keys::CoseKey::new();
//!     r1_key.kty(keys::SYMMETRIC);
//!     r1_key.alg(algs::A128KW);
//!     r1_key.k(hex::decode("849b57219dae48de646d07dbb533566e976686457c1491be3a76dcea6c427188").unwrap());
//!     r1_key.key_ops(vec![keys::KEY_OPS_WRAP, keys::KEY_OPS_UNWRAP]);
//!
//!     // Prepare recipient 2 cose-key
//!     let mut r2_key = keys::CoseKey::new();
//!     r2_key.kty(keys::EC2);
//!     r2_key.crv(keys::P_256);
//!     r2_key.d(hex::decode("02D1F7E6F26C43D4868D87CEB2353161740AACF1F7163647984B522A848DF1C3").unwrap());
//!
//!     // Generate CoseMAC struct with the cose-mac message to decode
//!     let mut verifier = CoseMessage::new_mac();
//!     verifier.bytes =
//!     hex::decode("d8618544a101181aa054546869732069732074686520636f6e74656e742e5064f33e4802d33bceec3fba4333ec5bf3828343a10122a10442313158281d77d288a153ab460c7c5c05e417b91becd26e9b73d2a0733c3b801db4885e51a635a2759801801b835832a201381c20a5010203262001215820bac5b11cad8f99f9c72b05cf4b9e26d244dc189f745228255a219a86d6a09eff048107a20442323233582000000000000000000000000000000000000000000000000000000000000000005828e53a16090a9caf558a6a2d2709cf195ee28ea55ae92c8e0ddddac26fbee3eb76e494ecd7cfbf49c8").unwrap();
//!     verifier.init_decoder(None).unwrap();
//!
//!     // Get recipient 1 and decode message
//!     let mut index1 = verifier.get_agent(&r1_kid).unwrap()[0];
//!     verifier.agents[index1].key(&r1_key).unwrap();
//!     verifier.decode(None, Some(index1)).unwrap();
//!
//!     // Get recipient 2 and decode message
//!     let mut index2 = verifier.get_agent(&r2_kid).unwrap()[0];
//!     verifier.agents[index2].key(&r2_key).unwrap();
//!     verifier.decode(None, Some(index2)).unwrap();
//! }
//! ```

use crate::agent::CoseAgent;
use crate::algs;
use crate::common;
use crate::cose_struct;
use crate::errors::{CoseError, CoseResult, CoseResultWithRet};
use crate::headers::{CoseHeader, COUNTER_SIG};
use crate::keys;
use cbor::{decoder::DecodeError, types::Tag, types::Type, Config, Decoder, Encoder};
use std::io::Cursor;

const SIG: usize = 0;
const MAC: usize = 1;
const ENC: usize = 2;

const CONTEXTS: [&str; 3] = [
    cose_struct::SIGNATURE,
    cose_struct::MAC_RECIPIENT,
    cose_struct::ENCRYPT_RECIPIENT,
];
const KO: [[i32; 2]; 3] = [
    [keys::KEY_OPS_SIGN, keys::KEY_OPS_VERIFY],
    [keys::KEY_OPS_MAC, keys::KEY_OPS_MAC_VERIFY],
    [keys::KEY_OPS_ENCRYPT, keys::KEY_OPS_DECRYPT],
];

// COSE tags
pub const ENC0_TAG: u64 = 16;
pub const MAC0_TAG: u64 = 17;
pub const SIG1_TAG: u64 = 18;
pub const ENC_TAG: u64 = 96;
pub const MAC_TAG: u64 = 97;
pub const SIG_TAG: u64 = 98;

// COSE types in string
pub const ENC0_TYPE: &str = "cose-encrypt0";
pub const MAC0_TYPE: &str = "cose-mac0";
pub const SIG1_TYPE: &str = "cose-sign1";
pub const ENC_TYPE: &str = "cose-encrypt";
pub const MAC_TYPE: &str = "cose-mac";
pub const SIG_TYPE: &str = "cose-sign";

const SIZES: [[usize; 2]; 3] = [[4, 4], [4, 5], [3, 4]];
const TAGS: [[Tag; 2]; 3] = [
    [Tag::Unassigned(SIG1_TAG), Tag::Unassigned(SIG_TAG)],
    [Tag::Unassigned(MAC0_TAG), Tag::Unassigned(MAC_TAG)],
    [Tag::Unassigned(ENC0_TAG), Tag::Unassigned(ENC_TAG)],
];

/// Structure to encode/decode cose-sign and cose-sign1 messages
pub struct CoseMessage {
    /// The header parameters of the message.
    pub header: CoseHeader,
    /// The payload of the message.
    pub payload: Vec<u8>,
    secured: Vec<u8>,
    /// The COSE encoded message.
    pub bytes: Vec<u8>,
    ph_bstr: Vec<u8>,
    pub_key: Vec<u8>,
    priv_key: Vec<u8>,
    key_encode: bool,
    key_decode: bool,
    crv: Option<i32>,
    base_iv: Option<Vec<u8>>,
    /// The signers/recipients of the message, empty if cose-sign1, cose-encrypt0 and cose-mac0 message type.
    pub agents: Vec<CoseAgent>,
    context: usize,
}

impl CoseMessage {
    /// Creates a new empty COSE signature (cose-sign1 and cose-sign) message structure.
    pub fn new_sign() -> CoseMessage {
        CoseMessage {
            bytes: Vec::new(),
            header: CoseHeader::new(),
            payload: Vec::new(),
            secured: Vec::new(),
            ph_bstr: Vec::new(),
            pub_key: Vec::new(),
            priv_key: Vec::new(),
            key_encode: false,
            key_decode: false,
            crv: None,
            base_iv: None,
            agents: Vec::new(),
            context: SIG,
        }
    }

    /// Creates a new empty COSE encrypt (cose-encrypt0 and cose-encrypt) message structure.
    pub fn new_encrypt() -> CoseMessage {
        CoseMessage {
            bytes: Vec::new(),
            header: CoseHeader::new(),
            payload: Vec::new(),
            secured: Vec::new(),
            ph_bstr: Vec::new(),
            pub_key: Vec::new(),
            priv_key: Vec::new(),
            key_encode: false,
            key_decode: false,
            crv: None,
            base_iv: None,
            agents: Vec::new(),
            context: ENC,
        }
    }

    /// Creates a new empty COSE MAC (cose-mac0 and cose-mac) message structure.
    pub fn new_mac() -> CoseMessage {
        CoseMessage {
            bytes: Vec::new(),
            header: CoseHeader::new(),
            payload: Vec::new(),
            secured: Vec::new(),
            ph_bstr: Vec::new(),
            pub_key: Vec::new(),
            priv_key: Vec::new(),
            key_encode: false,
            key_decode: false,
            crv: None,
            base_iv: None,
            agents: Vec::new(),
            context: MAC,
        }
    }

    /// Add an [header](../headers/struct.CoseHeader.html) to the message.
    pub fn add_header(&mut self, header: CoseHeader) {
        self.header = header;
    }

    /// Add the payload to the message.
    pub fn payload(&mut self, payload: Vec<u8>) {
        self.payload = payload;
    }

    /// Adds a signer/recipient ([agent](../agent/struct.CoseAgent.html)) to the message.
    ///
    /// Used for cose-sign, cose-mac and cose-encrypt messages.
    pub fn add_agent(&mut self, agent: &mut CoseAgent) -> CoseResult {
        if self.context == SIG {
            agent.context = cose_struct::SIGNATURE.to_string();
            if !algs::SIGNING_ALGS.contains(&agent.header.alg.ok_or(CoseError::MissingAlg())?) {
                return Err(CoseError::InvalidAlg());
            }
            if agent.key_ops.len() > 0 && !agent.key_ops.contains(&keys::KEY_OPS_SIGN) {
                return Err(CoseError::KeyOpNotSupported());
            }
            self.agents.push(agent.clone());
            Ok(())
        } else if self.context == MAC {
            agent.context = cose_struct::MAC_RECIPIENT.to_string();
            self.agents.push(agent.clone());
            Ok(())
        } else {
            agent.context = cose_struct::ENCRYPT_RECIPIENT.to_string();
            if !algs::KEY_DISTRIBUTION_ALGS
                .contains(&agent.header.alg.ok_or(CoseError::MissingAlg())?)
            {
                return Err(CoseError::InvalidAlg());
            }
            self.agents.push(agent.clone());
            Ok(())
        }
    }

    /// Returns a signer/recipient ([agent](../agent/struct.CoseAgent.html)) of the message with a given Key ID.
    pub fn get_agent(&self, kid: &Vec<u8>) -> CoseResultWithRet<Vec<usize>> {
        let mut keys: Vec<usize> = Vec::new();
        for i in 0..self.agents.len() {
            if self.agents[i]
                .header
                .kid
                .as_ref()
                .ok_or(CoseError::MissingKID())?
                == kid
            {
                keys.push(i);
            }
        }
        Ok(keys)
    }

    /// Adds a [cose-key](../keys/struct.CoseKey.html) to the message.
    ///
    /// This option is only available for the cose-sign1, cose-encrypt0 and cose-mac0 message types, since when using
    /// this message types, the keys are respective to each signer/recipient.
    pub fn key(&mut self, cose_key: &keys::CoseKey) -> CoseResult {
        if self.agents.len() > 0 {
            return Err(CoseError::InvalidMethodForContext());
        }
        cose_key.verify_kty()?;
        if cose_key.alg.ok_or(CoseError::MissingAlg())?
            != self.header.alg.ok_or(CoseError::MissingAlg())?
        {
            return Err(CoseError::AlgsDontMatch());
        }
        if self.context == SIG {
            self.crv = cose_key.crv;
            if cose_key.key_ops.len() == 0 || cose_key.key_ops.contains(&keys::KEY_OPS_SIGN) {
                let priv_key = match cose_key.get_s_key() {
                    Ok(v) => v,
                    Err(_) => Vec::new(),
                };
                if priv_key.len() > 0 {
                    self.key_encode = true;
                    self.priv_key = priv_key;
                }
            }
            if cose_key.key_ops.len() == 0 || cose_key.key_ops.contains(&keys::KEY_OPS_VERIFY) {
                let pub_key = match cose_key.get_pub_key() {
                    Ok(v) => v,
                    Err(_) => Vec::new(),
                };
                if pub_key.len() > 0 {
                    self.key_decode = true;
                    self.pub_key = pub_key;
                }
            }
        } else {
            if self.context == ENC {
                self.base_iv = cose_key.base_iv.clone();
            }
            let key = cose_key.get_s_key()?;
            if key.len() > 0 {
                if (self.context == ENC
                    && (cose_key.key_ops.len() == 0
                        || cose_key.key_ops.contains(&keys::KEY_OPS_ENCRYPT)))
                    || (self.context == MAC
                        && (cose_key.key_ops.len() == 0
                            || cose_key.key_ops.contains(&keys::KEY_OPS_MAC)))
                {
                    self.key_encode = true;
                }
                if (self.context == ENC
                    && (cose_key.key_ops.len() == 0
                        || cose_key.key_ops.contains(&keys::KEY_OPS_DECRYPT)))
                    || (self.context == MAC
                        && (cose_key.key_ops.len() == 0
                            || cose_key.key_ops.contains(&keys::KEY_OPS_MAC_VERIFY)))
                {
                    self.key_decode = true;
                }
                self.priv_key = key;
            }
        }
        if !self.key_encode && !self.key_decode {
            return Err(CoseError::KeyOpNotSupported());
        }
        Ok(())
    }

    /// Adds a counter signature to the message.
    ///
    /// The counter signature structure is the same type as the
    /// [signers/recipients](../agent/struct.CoseAgent.html) structure and it should be used the
    /// function [new_counter_sig](../agent/struct.CoseAgent.html#method.new_counter_sig) to initiate the structure.
    pub fn counter_sig(
        &self,
        external_aad: Option<Vec<u8>>,
        counter: &mut CoseAgent,
    ) -> CoseResult {
        let to_sig;
        if self.context != ENC {
            to_sig = &self.payload;
        } else {
            to_sig = &self.secured;
        }
        if to_sig.len() == 0 {
            if self.context == ENC {
                Err(CoseError::MissingCiphertext())
            } else {
                Err(CoseError::MissingPayload())
            }
        } else {
            let aead = match external_aad {
                None => Vec::new(),
                Some(v) => v,
            };
            counter.sign(to_sig, &aead, &self.ph_bstr)?;
            Ok(())
        }
    }

    /// Function to get the content to sign by the counter signature.
    ///
    /// This function is meant to be called if the counter signature process needs to be external
    /// to this crate, like a timestamp authority.
    pub fn get_to_sign(
        &self,
        external_aad: Option<Vec<u8>>,
        counter: &mut CoseAgent,
    ) -> CoseResultWithRet<Vec<u8>> {
        let to_sig;
        if self.context != ENC {
            to_sig = &self.payload;
        } else {
            to_sig = &self.secured;
        }
        if to_sig.len() == 0 {
            if self.context == ENC {
                Err(CoseError::MissingCiphertext())
            } else {
                Err(CoseError::MissingPayload())
            }
        } else {
            let aead = match external_aad {
                None => Vec::new(),
                Some(v) => v,
            };
            counter.get_sign_content(to_sig, &aead, &self.ph_bstr)
        }
    }

    /// Function to get the content to verify with the counter signature.
    ///
    /// This function is meant to be called if the counter signature process needs to be external
    /// to this crate, like a timestamp authority.
    pub fn get_to_verify(
        &mut self,
        external_aad: Option<Vec<u8>>,
        counter: &usize,
    ) -> CoseResultWithRet<Vec<u8>> {
        let to_sig;
        if self.context != ENC {
            to_sig = &self.payload;
        } else {
            to_sig = &self.secured;
        }
        if to_sig.len() == 0 {
            if self.context == ENC {
                Err(CoseError::MissingCiphertext())
            } else {
                Err(CoseError::MissingPayload())
            }
        } else {
            let aead = match external_aad {
                None => Vec::new(),
                Some(v) => v,
            };
            self.header.counters[*counter].get_sign_content(to_sig, &aead, &self.ph_bstr)
        }
    }

    /// Function that verifies a given counter signature on the COSE message.
    pub fn counters_verify(&mut self, external_aad: Option<Vec<u8>>, counter: usize) -> CoseResult {
        let to_sig;
        if self.context != ENC {
            to_sig = &self.payload;
        } else {
            to_sig = &self.secured;
        }
        if to_sig.len() == 0 {
            if self.context == ENC {
                Err(CoseError::MissingCiphertext())
            } else {
                Err(CoseError::MissingPayload())
            }
        } else {
            let aead = match external_aad {
                None => Vec::new(),
                Some(v) => v,
            };
            if self.header.counters[counter].verify(to_sig, &aead, &self.ph_bstr)? {
                Ok(())
            } else {
                Err(CoseError::InvalidCounterSignature())
            }
        }
    }

    /// Function that adds a counter signature which was signed externally with the use of
    /// [get_to_sign](#method.get_to_sign)
    pub fn add_counter_sig(&mut self, counter: CoseAgent) -> CoseResult {
        if !algs::SIGNING_ALGS.contains(&counter.header.alg.ok_or(CoseError::MissingAlg())?) {
            return Err(CoseError::InvalidAlg());
        }
        if counter.context != cose_struct::COUNTER_SIGNATURE {
            return Err(CoseError::InvalidContext());
        }
        if self.header.unprotected.contains(&COUNTER_SIG) {
            self.header.counters.push(counter);
            Ok(())
        } else {
            self.header.counters.push(counter);
            self.header.remove_label(COUNTER_SIG);
            self.header.unprotected.push(COUNTER_SIG);
            Ok(())
        }
    }

    /// Function to secure the content, sign, encrypt or mac depending on the COSE message type.
    ///
    /// `external_aad` parameter is used when it is desired to have an additional authentication
    /// data to reinforce security of the signature.
    pub fn secure_content(&mut self, external_aad: Option<Vec<u8>>) -> CoseResult {
        if self.payload.len() <= 0 {
            return Err(CoseError::MissingPayload());
        }
        self.ph_bstr = self.header.get_protected_bstr(true)?;
        let aead = match external_aad {
            None => Vec::new(),
            Some(v) => v,
        };
        if self.agents.len() <= 0 {
            if !self.key_encode {
                return Err(CoseError::KeyOpNotSupported());
            }
            let alg = self.header.alg.ok_or(CoseError::MissingAlg())?;
            if self.context == SIG {
                if !algs::SIGNING_ALGS.contains(&alg) {
                    Err(CoseError::InvalidAlg())
                } else {
                    self.secured = cose_struct::gen_sig(
                        &self.priv_key,
                        &alg,
                        &self.crv,
                        &aead,
                        cose_struct::SIGNATURE1,
                        &self.ph_bstr,
                        &Vec::new(),
                        &self.payload,
                    )?;
                    Ok(())
                }
            } else if self.context == ENC {
                if !algs::ENCRYPT_ALGS.contains(&alg) {
                    Err(CoseError::InvalidAlg())
                } else {
                    let iv = match self.base_iv.clone() {
                        Some(v) => algs::gen_iv(
                            self.header
                                .partial_iv
                                .as_ref()
                                .ok_or(CoseError::MissingPartialIV())?,
                            &v,
                            &alg,
                        )?,
                        None => self.header.iv.clone().ok_or(CoseError::MissingIV())?,
                    };
                    self.secured = cose_struct::gen_cipher(
                        &self.priv_key,
                        &alg,
                        &iv,
                        &aead,
                        cose_struct::ENCRYPT0,
                        &self.ph_bstr,
                        &self.payload,
                    )?;
                    Ok(())
                }
            } else {
                if !algs::MAC_ALGS.contains(&alg) {
                    Err(CoseError::InvalidAlg())
                } else {
                    self.secured = cose_struct::gen_mac(
                        &self.priv_key,
                        &alg,
                        &aead,
                        cose_struct::MAC0,
                        &self.ph_bstr,
                        &self.payload,
                    )?;
                    Ok(())
                }
            }
        } else {
            if self.context == SIG {
                for i in 0..self.agents.len() {
                    if !algs::SIGNING_ALGS
                        .contains(&self.agents[i].header.alg.ok_or(CoseError::MissingAlg())?)
                    {
                        return Err(CoseError::InvalidAlg());
                    } else if self.agents[i].key_ops.len() > 0
                        && !self.agents[i].key_ops.contains(&keys::KEY_OPS_SIGN)
                    {
                        return Err(CoseError::KeyOpNotSupported());
                    } else {
                        self.agents[i].sign(&self.payload, &aead, &self.ph_bstr)?;
                        self.agents[i].enc = true;
                    }
                }
                Ok(())
            } else {
                let alg = self.header.alg.ok_or(CoseError::MissingAlg())?;
                let mut cek;
                if algs::DIRECT == self.agents[0].header.alg.ok_or(CoseError::MissingAlg())? {
                    if self.agents.len() > 1 {
                        return Err(CoseError::AlgOnlySupportsOneRecipient());
                    }
                    if self.agents[0].key_ops.len() > 0
                        && !self.agents[0].key_ops.contains(&KO[self.context][0])
                    {
                        return Err(CoseError::KeyOpNotSupported());
                    } else {
                        if self.context == ENC {
                            self.secured = self.agents[0].enc(
                                &self.payload,
                                &aead,
                                &self.ph_bstr,
                                &alg,
                                self.header.iv.as_ref().ok_or(CoseError::MissingIV())?,
                            )?;
                            self.agents[0].enc = true;
                            return Ok(());
                        } else {
                            self.secured = cose_struct::gen_mac(
                                &self.agents[0].s_key,
                                &alg,
                                &aead,
                                cose_struct::MAC,
                                &self.ph_bstr,
                                &self.payload,
                            )?;
                            self.agents[0].enc = true;
                            return Ok(());
                        }
                    }
                } else if algs::ECDH_H.contains(
                    self.agents[0]
                        .header
                        .alg
                        .as_ref()
                        .ok_or(CoseError::MissingAlg())?,
                ) {
                    if self.agents.len() > 1 {
                        return Err(CoseError::AlgOnlySupportsOneRecipient());
                    }
                    let size = algs::get_cek_size(&alg)?;
                    cek = self.agents[0].derive_key(&Vec::new(), size, true, &alg)?;
                    self.agents[0].enc = true;
                } else {
                    cek = algs::gen_random_key(&alg)?;
                    for i in 0..self.agents.len() {
                        if algs::DIRECT == self.agents[i].header.alg.unwrap()
                            || algs::ECDH_H.contains(self.agents[i].header.alg.as_ref().unwrap())
                        {
                            return Err(CoseError::AlgOnlySupportsOneRecipient());
                        }
                        cek = self.agents[i].derive_key(&cek, cek.len(), true, &alg)?;
                        self.agents[i].enc = true;
                    }
                }
                if self.context == ENC {
                    let iv = match self.agents[0].base_iv.clone() {
                        Some(v) => algs::gen_iv(
                            self.header
                                .partial_iv
                                .as_ref()
                                .ok_or(CoseError::MissingPartialIV())?,
                            &v,
                            &alg,
                        )?,
                        None => self.header.iv.clone().ok_or(CoseError::MissingIV())?,
                    };
                    self.secured = cose_struct::gen_cipher(
                        &cek,
                        &alg,
                        &iv,
                        &aead,
                        cose_struct::ENCRYPT,
                        &self.ph_bstr,
                        &self.payload,
                    )?;
                    Ok(())
                } else {
                    self.secured = cose_struct::gen_mac(
                        &cek,
                        &alg,
                        &aead,
                        cose_struct::MAC,
                        &self.ph_bstr,
                        &self.payload,
                    )?;
                    Ok(())
                }
            }
        }
    }

    /// Function to encode the COSE message after the content is secured by [gen_signature](#method.gen_signature).
    ///
    /// The `data` parameter is used to specified if the payload/ciphertext shall be present or not in
    /// the message.
    pub fn encode(&mut self, data: bool) -> CoseResult {
        if self.agents.len() <= 0 {
            if self.secured.len() <= 0 {
                if self.context == SIG {
                    Err(CoseError::MissingSignature())
                } else if self.context == MAC {
                    Err(CoseError::MissingTag())
                } else {
                    Err(CoseError::MissingCiphertext())
                }
            } else {
                let mut e = Encoder::new(Vec::new());
                e.tag(TAGS[self.context][0])?;
                e.array(SIZES[self.context][0])?;
                e.bytes(self.ph_bstr.as_slice())?;
                self.header.encode_unprotected(&mut e)?;
                if data {
                    if self.context == ENC {
                        e.bytes(self.secured.as_slice())?;
                    } else {
                        e.bytes(self.payload.as_slice())?;
                    }
                } else {
                    e.null()?;
                }
                if self.context != ENC {
                    e.bytes(self.secured.as_slice())?;
                }
                self.bytes = e.into_writer().to_vec();
                self.header.labels_found = Vec::new();
                Ok(())
            }
        } else {
            let mut e = Encoder::new(Vec::new());
            e.tag(TAGS[self.context][1])?;
            e.array(SIZES[self.context][1])?;
            e.bytes(self.ph_bstr.as_slice())?;
            self.header.encode_unprotected(&mut e)?;
            if data {
                if self.context == ENC {
                    e.bytes(self.secured.as_slice())?;
                } else {
                    e.bytes(self.payload.as_slice())?;
                }
            } else {
                e.null()?;
            }
            if self.context == MAC {
                e.bytes(self.secured.as_slice())?;
            }
            let a_len = self.agents.len();
            e.array(a_len)?;
            for i in 0..a_len {
                self.agents[i].encode(&mut e)?;
            }
            self.bytes = e.into_writer().to_vec();
            self.header.labels_found = Vec::new();
            Ok(())
        }
    }

    /// Function to decode the initial parts of the COSE message, in order to access the required
    /// parameters to fully decode the message with [decode](#method.decode)
    ///
    /// This function requires that the attribute bytes is set in the structure with the COSE
    /// encoded message beforehand.
    ///
    /// if the payload/ciphertext is not included in the COSE message, it needs to be provided in
    /// the `data` parameter.
    pub fn init_decoder(&mut self, data: Option<Vec<u8>>) -> CoseResult {
        let input = Cursor::new(self.bytes.clone());
        let mut d = Decoder::new(Config::default(), input);
        let mut tag: Option<Tag> = None;

        match d.tag() {
            Ok(v) => {
                if !TAGS[self.context].contains(&v) {
                    return Err(CoseError::InvalidTag());
                } else {
                    tag = Some(v);
                    d.array()?;
                }
            }
            Err(ref err) => match err {
                DecodeError::UnexpectedType { datatype, info } => {
                    if *datatype != Type::Array && *info != SIZES[self.context][0] as u8 {
                        return Err(CoseError::InvalidCoseStructure());
                    }
                }
                _ => {
                    return Err(CoseError::InvalidCoseStructure());
                }
            },
        };
        self.ph_bstr = common::ph_bstr(d.bytes())?;
        if self.ph_bstr.len() > 0 {
            self.header.decode_protected_bstr(&self.ph_bstr)?;
        }
        self.header.decode_unprotected(&mut d, false)?;
        self.header.labels_found = Vec::new();
        match data {
            None => {
                if self.context == ENC {
                    self.secured = d.bytes()?.to_vec();
                } else {
                    self.payload = d.bytes()?.to_vec();
                }
            }
            Some(v) => {
                d.skip()?;
                if self.context == ENC {
                    self.secured = v;
                } else {
                    self.payload = v;
                }
            }
        };

        if (self.context == ENC && self.secured.len() <= 0)
            || (self.context != ENC && self.payload.len() <= 0)
        {
            if self.context == ENC {
                return Err(CoseError::MissingCiphertext());
            } else {
                return Err(CoseError::MissingPayload());
            }
        }

        if self.context != SIG {
            if self.header.alg.ok_or(CoseError::MissingAlg())? == algs::DIRECT
                && self.ph_bstr.len() > 0
            {
                return Err(CoseError::InvalidCoseStructure());
            } else if algs::A_KW.contains(self.header.alg.as_ref().ok_or(CoseError::MissingAlg())?)
                && self.ph_bstr.len() > 0
            {
                return Err(CoseError::InvalidCoseStructure());
            }
        }

        if self.context == MAC {
            self.secured = d.bytes()?.to_vec();
            if self.secured.len() <= 0 {
                return Err(CoseError::MissingPayload());
            }
        }

        match d.kernel().typeinfo() {
            Ok(type_info) => {
                if type_info.0 == Type::Array
                    && (tag == None || tag.unwrap() == TAGS[self.context][1])
                {
                    let r_len = type_info.1;
                    let mut agent: CoseAgent;
                    for _ in 0..r_len {
                        agent = CoseAgent::new();
                        agent.context = CONTEXTS[self.context].to_string();
                        d.array()?;
                        agent.ph_bstr = common::ph_bstr(d.bytes())?;
                        agent.decode(&mut d)?;
                        agent.enc = true;
                        self.agents.push(agent);
                    }
                } else if type_info.0 == Type::Bytes
                    && (tag == None || tag.unwrap() == TAGS[self.context][0])
                {
                    if self.context == SIG {
                        self.secured = d.kernel().raw_data(type_info.1, 0x500000)?;
                    }
                    if self.secured.len() <= 0 {
                        if self.context == SIG {
                            return Err(CoseError::MissingSignature());
                        } else if self.context == MAC {
                            return Err(CoseError::MissingTag());
                        } else {
                            return Err(CoseError::MissingCiphertext());
                        }
                    }
                }
            }
            Err(_) => {}
        }
        Ok(())
    }

    /// Function to verify/decrypt the secured content of the COSE message.
    ///
    /// `external_add` is used in case of an AAD is included.
    ///
    /// `agent` parameter must be `None` if the type of the message is cose-sign1, cose-encrypt0 or
    /// cose-mac0 and in case of being a cose-sign, cose-mac or cose-encrypt message type, the index of the
    /// signer/recipient of the message must be given with the respective key already added to the same
    /// signer/recipient.
    pub fn decode(
        &mut self,
        external_aad: Option<Vec<u8>>,
        agent: Option<usize>,
    ) -> CoseResultWithRet<Vec<u8>> {
        let aead = match external_aad {
            None => Vec::new(),
            Some(v) => v,
        };
        if self.agents.len() <= 0 {
            if !self.key_decode {
                return Err(CoseError::KeyOpNotSupported());
            } else {
                if self.context == SIG {
                    if !cose_struct::verify_sig(
                        &self.pub_key,
                        &self.header.alg.ok_or(CoseError::MissingAlg())?,
                        &self.crv,
                        &aead,
                        cose_struct::SIGNATURE1,
                        &self.ph_bstr,
                        &Vec::new(),
                        &self.payload,
                        &self.secured,
                    )? {
                        Err(CoseError::InvalidSignature())
                    } else {
                        Ok(self.payload.clone())
                    }
                } else if self.context == MAC {
                    if !cose_struct::verify_mac(
                        &self.priv_key,
                        &self.header.alg.ok_or(CoseError::MissingAlg())?,
                        &aead,
                        cose_struct::MAC0,
                        &self.ph_bstr,
                        &self.secured,
                        &self.payload,
                    )? {
                        return Err(CoseError::InvalidMAC());
                    } else {
                        Ok(self.payload.clone())
                    }
                } else {
                    let iv = match self.base_iv.clone() {
                        Some(v) => algs::gen_iv(
                            self.header
                                .partial_iv
                                .as_ref()
                                .ok_or(CoseError::MissingPartialIV())?,
                            &v,
                            &self.header.alg.ok_or(CoseError::MissingAlg())?,
                        )?,
                        None => self.header.iv.clone().ok_or(CoseError::MissingIV())?,
                    };
                    Ok(cose_struct::dec_cipher(
                        &self.priv_key,
                        &self.header.alg.ok_or(CoseError::MissingAlg())?,
                        &iv,
                        &aead,
                        cose_struct::ENCRYPT0,
                        &self.ph_bstr,
                        &self.secured,
                    )?)
                }
            }
        } else if agent != None {
            let index = agent.ok_or(CoseError::MissingSigner())?;
            if self.context == SIG {
                if self.agents[index].pub_key.len() == 0
                    || self.agents[index].key_ops.len() > 0
                        && !self.agents[index].key_ops.contains(&keys::KEY_OPS_VERIFY)
                {
                    Err(CoseError::KeyOpNotSupported())
                } else {
                    if !self.agents[index].verify(&self.payload, &aead, &self.ph_bstr)? {
                        Err(CoseError::InvalidSignature())
                    } else {
                        Ok(self.payload.clone())
                    }
                }
            } else {
                let alg = self.header.alg.ok_or(CoseError::MissingAlg())?;
                let cek;
                if algs::DIRECT
                    == self.agents[index]
                        .header
                        .alg
                        .ok_or(CoseError::MissingAlg())?
                {
                    if self.agents[index].key_ops.len() > 0
                        && !self.agents[index].key_ops.contains(&KO[self.context][1])
                    {
                        return Err(CoseError::KeyOpNotSupported());
                    } else {
                        if self.agents[index].s_key.len() > 0 {
                            cek = self.agents[index].s_key.clone();
                        } else {
                            return Err(CoseError::KeyOpNotSupported());
                        }
                    }
                } else {
                    let size = algs::get_cek_size(&alg)?;
                    let payload = self.agents[index].payload.clone();
                    cek = self.agents[index].derive_key(&payload, size, false, &alg)?;
                }
                if self.context == ENC {
                    let iv = match self.agents[index].base_iv.clone() {
                        Some(v) => algs::gen_iv(
                            self.header
                                .partial_iv
                                .as_ref()
                                .ok_or(CoseError::MissingPartialIV())?,
                            &v,
                            &alg,
                        )?,
                        None => self.header.iv.clone().ok_or(CoseError::MissingIV())?,
                    };
                    Ok(cose_struct::dec_cipher(
                        &cek,
                        &alg,
                        &iv,
                        &aead,
                        cose_struct::ENCRYPT,
                        &self.ph_bstr,
                        &self.secured,
                    )?)
                } else {
                    if !cose_struct::verify_mac(
                        &cek,
                        &alg,
                        &aead,
                        cose_struct::MAC,
                        &self.ph_bstr,
                        &self.secured,
                        &self.payload,
                    )? {
                        Err(CoseError::InvalidMAC())
                    } else {
                        Ok(self.payload.clone())
                    }
                }
            }
        } else {
            return Err(CoseError::MissingSigner());
        }
    }
}
