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
//!     let kid = b"11".to_vec();
//!
//!     // cose-key to encode the message
//!     let mut key = keys::CoseKey::new();
//!     key.kty(keys::EC2);
//!     key.alg(algs::ES512);
//!     key.crv(keys::P_256);
//!     key.x(hex::decode("bac5b11cad8f99f9c72b05cf4b9e26d244dc189f745228255a219a86d6a09eff").unwrap());
//!     key.y(hex::decode("20138bf82dc1b6d562be0fa54ab7804a3a64b6d72ccfed6b6fb6ed28bbfc117e").unwrap());
//!     key.d(hex::decode("57c92077664146e876760c9520d054aa93c3afb04e306705db6090308507b4d3").unwrap());
//!     key.key_ops(vec![keys::KEY_OPS_SIGN]);
//!
//!     // Prepare cose-sign1 message
//!     let mut sign1 = CoseMessage::new_sign();
//!     sign1.header.alg(algs::ES512, true, false);
//!     sign1.header.kid(kid, true, false);
//!     sign1.payload(msg);
//!     sign1.key(&key).unwrap();
//!
//!     // Generate the signature
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
//!     // cose-key to decode the message
//!     let mut key = keys::CoseKey::new();
//!     key.kty(keys::EC2);
//!     key.alg(algs::ES256);
//!     key.crv(keys::P_256);
//!     key.x(hex::decode("bac5b11cad8f99f9c72b05cf4b9e26d244dc189f745228255a219a86d6a09eff").unwrap());
//!     key.y(hex::decode("20138bf82dc1b6d562be0fa54ab7804a3a64b6d72ccfed6b6fb6ed28bbfc117e").unwrap());
//!     key.key_ops(vec![keys::KEY_OPS_VERIFY]);
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
//!     // Prepare the cose-key
//!     let mut key = keys::CoseKey::new();
//!     key.kty(keys::SYMMETRIC);
//!     key.alg(algs::CHACHA20);
//!     key.k(hex::decode("849b57219dae48de646d07dbb533566e976686457c1491be3a76dcea6c427188").unwrap());
//!     key.key_ops(vec![keys::KEY_OPS_ENCRYPT]);
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
//!     key.key_ops(vec![keys::KEY_OPS_DECRYPT]);
//!
//!
//!     // Generate CoseEncrypt struct with the cose-encryt0 message to decode
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
//!     key.kty(keys::SYMMETRIC);
//!     key.alg(algs::AES_MAC_256_128);
//!     key.k(hex::decode("849b57219dae48de646d07dbb533566e976686457c1491be3a76dcea6c427188").unwrap());
//!     key.key_ops(vec![keys::KEY_OPS_MAC]);
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
//!     key.key_ops(vec![keys::KEY_OPS_MAC_VERIFY]);
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

pub mod headers;
pub mod keys;

pub mod agent;
pub mod algs;
pub mod message;

pub mod errors;
pub mod utils;

pub(crate) mod common;
pub(crate) mod cose_struct;

#[cfg(test)]
mod test_vecs {
    use crate::algs;
    use crate::keys;
    use crate::message::CoseMessage;
    const ELEVEN: [u8; 118] = [
        167, 1, 2, 32, 1, 2, 66, 49, 49, 33, 88, 32, 186, 197, 177, 28, 173, 143, 153, 249, 199,
        43, 5, 207, 75, 158, 38, 210, 68, 220, 24, 159, 116, 82, 40, 37, 90, 33, 154, 134, 214,
        160, 158, 255, 34, 88, 32, 32, 19, 139, 248, 45, 193, 182, 213, 98, 190, 15, 165, 74, 183,
        128, 74, 58, 100, 182, 215, 44, 207, 237, 107, 111, 182, 237, 40, 187, 252, 17, 126, 35,
        88, 32, 87, 201, 32, 119, 102, 65, 70, 232, 118, 118, 12, 149, 32, 208, 84, 170, 147, 195,
        175, 176, 78, 48, 103, 5, 219, 96, 144, 48, 133, 7, 180, 211, 4, 130, 2, 1,
    ];
    const BILBO: [u8; 249] = [
        167, 1, 2, 32, 3, 2, 88, 30, 98, 105, 108, 98, 111, 46, 98, 97, 103, 103, 105, 110, 115,
        64, 104, 111, 98, 98, 105, 116, 111, 110, 46, 101, 120, 97, 109, 112, 108, 101, 33, 88, 66,
        0, 114, 153, 44, 179, 172, 8, 236, 243, 229, 198, 61, 237, 236, 13, 81, 168, 193, 247, 158,
        242, 248, 47, 148, 243, 199, 55, 191, 93, 231, 152, 102, 113, 234, 198, 37, 254, 130, 87,
        187, 208, 57, 70, 68, 202, 170, 58, 175, 143, 39, 164, 88, 95, 187, 202, 208, 242, 69, 118,
        32, 8, 94, 92, 143, 66, 173, 34, 88, 66, 1, 220, 166, 148, 123, 206, 136, 188, 87, 144, 72,
        90, 201, 116, 39, 52, 43, 195, 95, 136, 125, 134, 214, 90, 8, 147, 119, 226, 71, 230, 11,
        170, 85, 228, 232, 80, 30, 42, 218, 87, 36, 172, 81, 214, 144, 144, 8, 3, 62, 188, 16, 172,
        153, 155, 157, 127, 92, 194, 81, 159, 63, 225, 234, 29, 148, 117, 35, 88, 66, 0, 8, 81, 56,
        221, 171, 245, 202, 151, 95, 88, 96, 249, 26, 8, 233, 29, 109, 95, 154, 118, 173, 64, 24,
        118, 106, 71, 102, 128, 181, 92, 211, 57, 232, 171, 108, 114, 181, 250, 205, 178, 162, 165,
        10, 194, 91, 208, 134, 100, 125, 211, 226, 230, 233, 158, 132, 202, 44, 54, 9, 253, 241,
        119, 254, 178, 109, 4, 130, 2, 1,
    ];
    const MERIADOC: [u8; 154] = [
        167, 1, 2, 32, 1, 2, 88, 36, 109, 101, 114, 105, 97, 100, 111, 99, 46, 98, 114, 97, 110,
        100, 121, 98, 117, 99, 107, 64, 98, 117, 99, 107, 108, 97, 110, 100, 46, 101, 120, 97, 109,
        112, 108, 101, 33, 88, 32, 101, 237, 165, 161, 37, 119, 194, 186, 232, 41, 67, 127, 227,
        56, 112, 26, 16, 170, 163, 117, 225, 187, 91, 93, 225, 8, 222, 67, 156, 8, 85, 29, 34, 88,
        32, 30, 82, 237, 117, 112, 17, 99, 247, 249, 228, 13, 223, 159, 52, 27, 61, 201, 186, 134,
        10, 247, 224, 202, 124, 167, 233, 238, 205, 0, 132, 209, 156, 35, 88, 32, 175, 249, 7, 201,
        159, 154, 211, 170, 230, 196, 205, 242, 17, 34, 188, 226, 189, 104, 181, 40, 62, 105, 7,
        21, 74, 217, 17, 132, 15, 162, 8, 207, 4, 131, 7, 1, 2,
    ];

    const PEREGRIN: [u8; 150] = [
        167, 1, 2, 32, 1, 2, 88, 33, 112, 101, 114, 101, 103, 114, 105, 110, 46, 116, 111, 111,
        107, 64, 116, 117, 99, 107, 98, 111, 114, 111, 117, 103, 104, 46, 101, 120, 97, 109, 112,
        108, 101, 33, 88, 32, 152, 245, 10, 79, 246, 192, 88, 97, 200, 134, 13, 19, 166, 56, 234,
        86, 195, 245, 173, 117, 144, 187, 251, 240, 84, 225, 199, 180, 217, 29, 98, 128, 34, 88,
        32, 240, 20, 0, 176, 137, 134, 120, 4, 184, 233, 252, 150, 195, 147, 33, 97, 241, 147, 79,
        66, 35, 6, 145, 112, 217, 36, 183, 224, 59, 248, 34, 187, 35, 88, 32, 2, 209, 247, 230,
        242, 108, 67, 212, 134, 141, 135, 206, 178, 53, 49, 97, 116, 10, 172, 241, 247, 22, 54, 71,
        152, 75, 82, 42, 132, 141, 241, 195, 4, 130, 2, 1,
    ];
    const OUR_SECRET: [u8; 55] = [
        165, 1, 4, 2, 74, 111, 117, 114, 45, 115, 101, 99, 114, 101, 116, 32, 88, 32, 132, 155, 87,
        33, 157, 174, 72, 222, 100, 109, 7, 219, 181, 51, 86, 110, 151, 102, 134, 69, 124, 20, 145,
        190, 58, 118, 220, 234, 108, 66, 113, 136, 3, 15, 4, 129, 10,
    ];
    const UID: [u8; 81] = [
        164, 1, 4, 2, 88, 36, 48, 49, 56, 99, 48, 97, 101, 53, 45, 52, 100, 57, 98, 45, 52, 55, 49,
        98, 45, 98, 102, 100, 54, 45, 101, 101, 102, 51, 49, 52, 98, 99, 55, 48, 51, 55, 32, 88,
        32, 132, 155, 87, 33, 157, 174, 72, 222, 100, 109, 7, 219, 181, 51, 86, 110, 151, 102, 134,
        69, 124, 20, 145, 190, 58, 118, 220, 234, 108, 66, 113, 136, 4, 130, 2, 1,
    ];
    #[test]
    fn c11() {
        let kid = &b"11".to_vec();
        let mut verify = CoseMessage::new_sign();
        verify.bytes = [
            216, 98, 132, 64, 160, 84, 84, 104, 105, 115, 32, 105, 115, 32, 116, 104, 101, 32, 99,
            111, 110, 116, 101, 110, 116, 46, 129, 131, 67, 161, 1, 38, 161, 4, 66, 49, 49, 88, 64,
            226, 174, 175, 212, 13, 105, 209, 157, 254, 110, 82, 7, 124, 93, 127, 244, 228, 8, 40,
            44, 190, 251, 93, 6, 203, 244, 20, 175, 46, 25, 217, 130, 172, 69, 172, 152, 184, 84,
            76, 144, 139, 69, 7, 222, 30, 144, 183, 23, 195, 211, 72, 22, 254, 146, 106, 43, 152,
            245, 58, 253, 47, 160, 243, 10,
        ]
        .to_vec();
        verify.init_decoder(None).unwrap();
        let v1 = verify.get_agent(kid).unwrap()[0];
        let mut key = keys::CoseKey::new();
        key.bytes = ELEVEN.to_vec();
        key.decode().unwrap();
        key.alg(algs::ES256);
        verify.agents[v1].key(&key).unwrap();
    }

    #[test]
    fn c12() {
        let kid1 = &b"11".to_vec();
        let kid2 = &b"bilbo.baggins@hobbiton.example".to_vec();
        let mut verify = CoseMessage::new_sign();
        verify.bytes = [
            216, 98, 132, 64, 160, 84, 84, 104, 105, 115, 32, 105, 115, 32, 116, 104, 101, 32, 99,
            111, 110, 116, 101, 110, 116, 46, 130, 131, 67, 161, 1, 38, 161, 4, 66, 49, 49, 88, 64,
            226, 174, 175, 212, 13, 105, 209, 157, 254, 110, 82, 7, 124, 93, 127, 244, 228, 8, 40,
            44, 190, 251, 93, 6, 203, 244, 20, 175, 46, 25, 217, 130, 172, 69, 172, 152, 184, 84,
            76, 144, 139, 69, 7, 222, 30, 144, 183, 23, 195, 211, 72, 22, 254, 146, 106, 43, 152,
            245, 58, 253, 47, 160, 243, 10, 131, 68, 161, 1, 56, 35, 161, 4, 88, 30, 98, 105, 108,
            98, 111, 46, 98, 97, 103, 103, 105, 110, 115, 64, 104, 111, 98, 98, 105, 116, 111, 110,
            46, 101, 120, 97, 109, 112, 108, 101, 88, 132, 0, 162, 210, 138, 124, 43, 219, 21, 135,
            135, 116, 32, 246, 90, 223, 125, 11, 154, 6, 99, 93, 209, 222, 100, 187, 98, 151, 76,
            134, 63, 11, 22, 13, 210, 22, 55, 52, 3, 78, 106, 192, 3, 176, 30, 135, 5, 82, 76, 92,
            76, 164, 121, 169, 82, 240, 36, 126, 232, 203, 11, 79, 183, 57, 123, 160, 141, 0, 158,
            12, 139, 244, 130, 39, 12, 197, 119, 26, 161, 67, 150, 110, 90, 70, 154, 9, 246, 19,
            72, 128, 48, 197, 176, 126, 198, 215, 34, 227, 131, 90, 219, 91, 45, 140, 68, 233, 95,
            251, 19, 135, 125, 210, 88, 40, 102, 136, 53, 53, 222, 59, 176, 61, 1, 117, 63, 131,
            171, 135, 187, 79, 122, 2, 151,
        ]
        .to_vec();

        verify.init_decoder(None).unwrap();
        let c1 = verify.get_agent(kid1).unwrap()[0];
        let mut key = keys::CoseKey::new();
        key.bytes = ELEVEN.to_vec();
        key.decode().unwrap();
        key.alg(algs::ES256);
        verify.agents[c1].key(&key).unwrap();
        verify.decode(None, Some(c1)).unwrap();
        let c2 = verify.get_agent(kid2).unwrap()[0];
        key = keys::CoseKey::new();
        key.bytes = BILBO.to_vec();
        key.decode().unwrap();
        key.alg(algs::ES512);
        verify.agents[c2].key(&key).unwrap();
        verify.decode(None, Some(c2)).unwrap();
    }

    #[test]
    fn c13() {
        let kid = &b"11".to_vec();
        let mut verify = CoseMessage::new_sign();
        verify.bytes = [
            216, 98, 132, 64, 161, 7, 131, 67, 161, 1, 38, 161, 4, 66, 49, 49, 88, 64, 90, 192, 94,
            40, 157, 93, 14, 27, 10, 127, 4, 138, 93, 43, 100, 56, 19, 222, 213, 11, 201, 228, 146,
            32, 244, 247, 39, 143, 133, 241, 157, 74, 119, 214, 85, 201, 211, 181, 30, 128, 90,
            116, 176, 153, 225, 224, 133, 170, 205, 151, 252, 41, 215, 47, 136, 126, 136, 2, 187,
            102, 80, 204, 235, 44, 84, 84, 104, 105, 115, 32, 105, 115, 32, 116, 104, 101, 32, 99,
            111, 110, 116, 101, 110, 116, 46, 129, 131, 67, 161, 1, 38, 161, 4, 66, 49, 49, 88, 64,
            226, 174, 175, 212, 13, 105, 209, 157, 254, 110, 82, 7, 124, 93, 127, 244, 228, 8, 40,
            44, 190, 251, 93, 6, 203, 244, 20, 175, 46, 25, 217, 130, 172, 69, 172, 152, 184, 84,
            76, 144, 139, 69, 7, 222, 30, 144, 183, 23, 195, 211, 72, 22, 254, 146, 106, 43, 152,
            245, 58, 253, 47, 160, 243, 10,
        ]
        .to_vec();

        verify.init_decoder(None).unwrap();
        let v1 = verify.get_agent(kid).unwrap()[0];
        let mut key = keys::CoseKey::new();
        key.bytes = ELEVEN.to_vec();
        key.decode().unwrap();
        key.alg(algs::ES256);
        verify.agents[v1].key(&key).unwrap();

        verify.decode(None, Some(v1)).unwrap();

        let counter = verify.header.get_counter(&b"11".to_vec()).unwrap()[0];
        verify.header.counters[counter].key(&key).unwrap();
        verify.counters_verify(None, counter).unwrap();
    }
    #[test]
    fn c21() {
        let mut verify = CoseMessage::new_sign();
        verify.bytes = [
            210, 132, 67, 161, 1, 38, 161, 4, 66, 49, 49, 84, 84, 104, 105, 115, 32, 105, 115, 32,
            116, 104, 101, 32, 99, 111, 110, 116, 101, 110, 116, 46, 88, 64, 142, 179, 62, 76, 163,
            29, 28, 70, 90, 176, 90, 172, 52, 204, 107, 35, 213, 143, 239, 92, 8, 49, 6, 196, 210,
            90, 145, 174, 240, 176, 17, 126, 42, 249, 162, 145, 170, 50, 225, 74, 184, 52, 220, 86,
            237, 42, 34, 52, 68, 84, 126, 1, 241, 29, 59, 9, 22, 229, 164, 195, 69, 202, 203, 54,
        ]
        .to_vec();

        verify.init_decoder(None).unwrap();
        let mut key = keys::CoseKey::new();
        key.bytes = ELEVEN.to_vec();
        key.decode().unwrap();
        key.alg(algs::ES256);
        verify.key(&key).unwrap();
        verify.decode(None, None).unwrap();
    }
    #[test]
    fn c31() {
        let kid = &b"meriadoc.brandybuck@buckland.example".to_vec();
        let msg = b"This is the content.".to_vec();
        let mut dec = CoseMessage::new_encrypt();
        dec.bytes = [
            216, 96, 132, 67, 161, 1, 1, 161, 5, 76, 201, 207, 77, 242, 254, 108, 99, 43, 247, 136,
            100, 19, 88, 36, 122, 219, 226, 112, 156, 168, 24, 251, 65, 95, 30, 93, 246, 111, 78,
            26, 81, 5, 59, 166, 214, 90, 26, 12, 82, 163, 87, 218, 122, 100, 75, 128, 112, 161, 81,
            176, 129, 131, 68, 161, 1, 56, 24, 162, 32, 164, 1, 2, 32, 1, 33, 88, 32, 152, 245, 10,
            79, 246, 192, 88, 97, 200, 134, 13, 19, 166, 56, 234, 86, 195, 245, 173, 117, 144, 187,
            251, 240, 84, 225, 199, 180, 217, 29, 98, 128, 34, 245, 4, 88, 36, 109, 101, 114, 105,
            97, 100, 111, 99, 46, 98, 114, 97, 110, 100, 121, 98, 117, 99, 107, 64, 98, 117, 99,
            107, 108, 97, 110, 100, 46, 101, 120, 97, 109, 112, 108, 101, 64,
        ]
        .to_vec();
        dec.init_decoder(None).unwrap();
        let r = dec.get_agent(kid).unwrap()[0];
        let mut key = keys::CoseKey::new();
        key.bytes = MERIADOC.to_vec();
        key.decode().unwrap();
        dec.agents[r].key(&key).unwrap();
        assert_eq!(dec.decode(None, Some(r)).unwrap(), msg);
    }

    #[test]
    fn c33() {
        let kid = &b"meriadoc.brandybuck@buckland.example".to_vec();
        let msg = b"This is the content.".to_vec();
        let mut dec = CoseMessage::new_encrypt();
        dec.bytes = [
            216, 96, 132, 67, 161, 1, 1, 162, 5, 76, 201, 207, 77, 242, 254, 108, 99, 43, 247, 136,
            100, 19, 7, 131, 68, 161, 1, 56, 35, 161, 4, 88, 30, 98, 105, 108, 98, 111, 46, 98, 97,
            103, 103, 105, 110, 115, 64, 104, 111, 98, 98, 105, 116, 111, 110, 46, 101, 120, 97,
            109, 112, 108, 101, 88, 132, 0, 146, 150, 99, 200, 120, 155, 178, 129, 119, 174, 40,
            70, 126, 102, 55, 125, 161, 35, 2, 215, 249, 89, 77, 41, 153, 175, 165, 223, 165, 49,
            41, 79, 136, 150, 242, 182, 205, 241, 116, 0, 20, 244, 199, 241, 163, 88, 227, 166,
            207, 87, 244, 237, 111, 176, 47, 207, 143, 122, 169, 137, 245, 223, 208, 127, 7, 0,
            163, 167, 216, 243, 198, 4, 186, 112, 250, 148, 17, 189, 16, 194, 89, 27, 72, 62, 29,
            44, 49, 222, 0, 49, 131, 228, 52, 216, 251, 161, 143, 23, 164, 199, 227, 223, 160, 3,
            172, 28, 243, 211, 13, 68, 210, 83, 60, 73, 137, 211, 172, 56, 195, 139, 113, 72, 28,
            195, 67, 12, 157, 101, 231, 221, 255, 88, 36, 122, 219, 226, 112, 156, 168, 24, 251,
            65, 95, 30, 93, 246, 111, 78, 26, 81, 5, 59, 166, 214, 90, 26, 12, 82, 163, 87, 218,
            122, 100, 75, 128, 112, 161, 81, 176, 129, 131, 68, 161, 1, 56, 24, 162, 32, 164, 1, 2,
            32, 1, 33, 88, 32, 152, 245, 10, 79, 246, 192, 88, 97, 200, 134, 13, 19, 166, 56, 234,
            86, 195, 245, 173, 117, 144, 187, 251, 240, 84, 225, 199, 180, 217, 29, 98, 128, 34,
            245, 4, 88, 36, 109, 101, 114, 105, 97, 100, 111, 99, 46, 98, 114, 97, 110, 100, 121,
            98, 117, 99, 107, 64, 98, 117, 99, 107, 108, 97, 110, 100, 46, 101, 120, 97, 109, 112,
            108, 101, 64,
        ]
        .to_vec();
        dec.init_decoder(None).unwrap();
        let r = dec.get_agent(kid).unwrap()[0];
        let mut key = keys::CoseKey::new();
        key.bytes = MERIADOC.to_vec();
        key.decode().unwrap();
        key.alg(algs::ECDH_ES_HKDF_256);
        dec.agents[r].key(&key).unwrap();
        assert_eq!(dec.decode(None, Some(r)).unwrap(), msg);
        let c = dec
            .header
            .get_counter(&b"bilbo.baggins@hobbiton.example".to_vec())
            .unwrap()[0];
        key = keys::CoseKey::new();
        key.bytes = BILBO.to_vec();
        key.decode().unwrap();
        key.alg(algs::ES512);
        dec.header.counters[c].key(&key).unwrap();
        dec.counters_verify(None, c).unwrap();
    }
    #[test]
    fn c34() {
        let kid = &b"meriadoc.brandybuck@buckland.example".to_vec();
        let msg = b"This is the content.".to_vec();
        let aad = vec![0, 17, 187, 204, 34, 221, 68, 238, 85, 255, 102, 0, 119];
        let mut dec = CoseMessage::new_encrypt();
        dec.bytes = [
            216, 96, 132, 67, 161, 1, 1, 161, 5, 76, 2, 209, 247, 230, 242, 108, 67, 212, 134, 141,
            135, 206, 88, 36, 100, 248, 77, 145, 59, 166, 10, 118, 7, 10, 154, 72, 242, 110, 151,
            232, 99, 226, 133, 41, 216, 245, 51, 94, 95, 1, 101, 238, 233, 118, 180, 165, 246, 198,
            240, 157, 129, 131, 68, 161, 1, 56, 31, 163, 34, 88, 33, 112, 101, 114, 101, 103, 114,
            105, 110, 46, 116, 111, 111, 107, 64, 116, 117, 99, 107, 98, 111, 114, 111, 117, 103,
            104, 46, 101, 120, 97, 109, 112, 108, 101, 4, 88, 36, 109, 101, 114, 105, 97, 100, 111,
            99, 46, 98, 114, 97, 110, 100, 121, 98, 117, 99, 107, 64, 98, 117, 99, 107, 108, 97,
            110, 100, 46, 101, 120, 97, 109, 112, 108, 101, 53, 66, 1, 1, 88, 24, 65, 224, 215,
            111, 87, 157, 189, 13, 147, 106, 102, 45, 84, 216, 88, 32, 55, 222, 46, 54, 111, 222,
            28, 98,
        ]
        .to_vec();
        dec.init_decoder(None).unwrap();
        let r = dec.get_agent(kid).unwrap()[0];
        let mut key = keys::CoseKey::new();
        key.bytes = MERIADOC.to_vec();
        key.decode().unwrap();
        key.key_ops(vec![keys::KEY_OPS_DERIVE]);
        dec.agents[r].key(&key).unwrap();
        key = keys::CoseKey::new();
        key.bytes = PEREGRIN.to_vec();
        key.decode().unwrap();
        key.alg(algs::ES256);
        key.key_ops(vec![keys::KEY_OPS_DERIVE]);
        dec.agents[r].header.ecdh_key(key);
        assert_eq!(dec.decode(Some(aad), Some(r)).unwrap(), msg);
    }
    #[test]
    fn c51() {
        let mut verify = CoseMessage::new_mac();
        verify.bytes = [
            216, 97, 133, 67, 161, 1, 15, 160, 84, 84, 104, 105, 115, 32, 105, 115, 32, 116, 104,
            101, 32, 99, 111, 110, 116, 101, 110, 116, 46, 72, 158, 18, 38, 186, 31, 129, 184, 72,
            129, 131, 64, 162, 1, 37, 4, 74, 111, 117, 114, 45, 115, 101, 99, 114, 101, 116, 64,
        ]
        .to_vec();
        verify.init_decoder(None).unwrap();
        let r = verify.get_agent(&b"our-secret".to_vec()).unwrap()[0];
        let mut key = keys::CoseKey::new();
        key.bytes = OUR_SECRET.to_vec();
        key.decode().unwrap();
        key.alg(algs::AES_MAC_256_64);
        verify.agents[r].key(&key).unwrap();
        verify.decode(None, Some(r)).unwrap();
    }
    #[test]
    fn c52() {
        let kid = &b"meriadoc.brandybuck@buckland.example".to_vec();
        let mut verify = CoseMessage::new_mac();
        verify.bytes = [
            216, 97, 133, 67, 161, 1, 5, 160, 84, 84, 104, 105, 115, 32, 105, 115, 32, 116, 104,
            101, 32, 99, 111, 110, 116, 101, 110, 116, 46, 88, 32, 129, 160, 52, 72, 172, 211, 211,
            5, 55, 110, 170, 17, 251, 63, 228, 22, 169, 85, 190, 44, 190, 126, 201, 111, 1, 44,
            153, 75, 195, 241, 106, 65, 129, 131, 68, 161, 1, 56, 26, 163, 34, 88, 33, 112, 101,
            114, 101, 103, 114, 105, 110, 46, 116, 111, 111, 107, 64, 116, 117, 99, 107, 98, 111,
            114, 111, 117, 103, 104, 46, 101, 120, 97, 109, 112, 108, 101, 4, 88, 36, 109, 101,
            114, 105, 97, 100, 111, 99, 46, 98, 114, 97, 110, 100, 121, 98, 117, 99, 107, 64, 98,
            117, 99, 107, 108, 97, 110, 100, 46, 101, 120, 97, 109, 112, 108, 101, 53, 88, 64, 77,
            133, 83, 231, 231, 79, 60, 106, 58, 157, 211, 239, 40, 106, 129, 149, 203, 248, 162,
            61, 25, 85, 140, 207, 236, 125, 52, 184, 36, 244, 45, 146, 189, 6, 189, 44, 127, 2,
            113, 240, 33, 78, 20, 31, 183, 121, 174, 40, 86, 171, 245, 133, 165, 131, 104, 176, 23,
            231, 242, 169, 229, 206, 77, 181, 64,
        ]
        .to_vec();
        verify.init_decoder(None).unwrap();
        let r = verify.get_agent(kid).unwrap()[0];
        let mut key = keys::CoseKey::new();
        key.bytes = MERIADOC.to_vec();
        key.decode().unwrap();
        verify.agents[r].key(&key).unwrap();
        key = keys::CoseKey::new();
        key.bytes = PEREGRIN.to_vec();
        key.decode().unwrap();
        verify.agents[r].header.ecdh_key(key);

        verify.decode(None, Some(r)).unwrap();
    }
    #[test]
    fn c53() {
        let kid = &b"018c0ae5-4d9b-471b-bfd6-eef314bc7037".to_vec();
        let mut verify = CoseMessage::new_mac();
        verify.bytes = [
            216, 97, 133, 67, 161, 1, 14, 160, 84, 84, 104, 105, 115, 32, 105, 115, 32, 116, 104,
            101, 32, 99, 111, 110, 116, 101, 110, 116, 46, 72, 54, 245, 175, 175, 11, 171, 93, 67,
            129, 131, 64, 162, 1, 36, 4, 88, 36, 48, 49, 56, 99, 48, 97, 101, 53, 45, 52, 100, 57,
            98, 45, 52, 55, 49, 98, 45, 98, 102, 100, 54, 45, 101, 101, 102, 51, 49, 52, 98, 99,
            55, 48, 51, 55, 88, 24, 113, 26, 176, 220, 47, 196, 88, 93, 206, 39, 239, 250, 103,
            129, 200, 9, 62, 186, 144, 111, 34, 123, 110, 176,
        ]
        .to_vec();
        verify.init_decoder(None).unwrap();
        let r = verify.get_agent(kid).unwrap()[0];
        let mut key = keys::CoseKey::new();
        key.bytes = UID.to_vec();
        key.decode().unwrap();
        key.alg(algs::AES_MAC_128_64);
        key.key_ops(vec![keys::KEY_OPS_MAC_VERIFY]);
        verify.agents[r].key(&key).unwrap();

        verify.decode(None, Some(r)).unwrap();
    }
    #[test]
    fn c54() {
        let kid1 = &b"bilbo.baggins@hobbiton.example".to_vec();
        let kid2 = &b"018c0ae5-4d9b-471b-bfd6-eef314bc7037".to_vec();
        let mut verify = CoseMessage::new_mac();
        verify.bytes = [
            216, 97, 133, 67, 161, 1, 5, 160, 84, 84, 104, 105, 115, 32, 105, 115, 32, 116, 104,
            101, 32, 99, 111, 110, 116, 101, 110, 116, 46, 88, 32, 191, 72, 35, 94, 128, 155, 92,
            66, 233, 149, 242, 183, 213, 250, 19, 98, 14, 126, 216, 52, 227, 55, 246, 170, 67, 223,
            22, 30, 73, 233, 50, 62, 130, 131, 68, 161, 1, 56, 28, 162, 32, 164, 1, 2, 32, 3, 33,
            88, 66, 0, 67, 177, 38, 105, 172, 172, 63, 210, 120, 152, 255, 186, 11, 205, 46, 108,
            54, 109, 83, 188, 77, 183, 31, 144, 154, 117, 147, 4, 172, 251, 94, 24, 205, 199, 186,
            11, 19, 255, 140, 118, 54, 39, 26, 105, 36, 177, 172, 99, 192, 38, 136, 7, 91, 85, 239,
            45, 97, 53, 116, 231, 220, 36, 47, 121, 195, 34, 245, 4, 88, 30, 98, 105, 108, 98, 111,
            46, 98, 97, 103, 103, 105, 110, 115, 64, 104, 111, 98, 98, 105, 116, 111, 110, 46, 101,
            120, 97, 109, 112, 108, 101, 88, 40, 51, 155, 196, 247, 153, 132, 205, 198, 179, 230,
            206, 95, 49, 90, 76, 125, 43, 10, 196, 102, 252, 234, 105, 232, 192, 125, 251, 202, 91,
            177, 246, 97, 188, 95, 142, 13, 249, 227, 239, 245, 131, 64, 162, 1, 36, 4, 88, 36, 48,
            49, 56, 99, 48, 97, 101, 53, 45, 52, 100, 57, 98, 45, 52, 55, 49, 98, 45, 98, 102, 100,
            54, 45, 101, 101, 102, 51, 49, 52, 98, 99, 55, 48, 51, 55, 88, 40, 11, 44, 124, 252,
            224, 78, 152, 39, 99, 66, 214, 71, 106, 119, 35, 192, 144, 223, 221, 21, 249, 165, 24,
            231, 115, 101, 73, 233, 152, 55, 6, 149, 230, 214, 168, 59, 74, 229, 7, 187,
        ]
        .to_vec();
        verify.init_decoder(None).unwrap();
        let mut r = verify.get_agent(kid1).unwrap()[0];
        let mut key = keys::CoseKey::new();
        key.bytes = BILBO.to_vec();
        key.decode().unwrap();
        key.key_ops(vec![keys::KEY_OPS_DERIVE]);
        verify.agents[r].key(&key).unwrap();
        verify.decode(None, Some(r)).unwrap();

        r = verify.get_agent(kid2).unwrap()[0];
        let mut key = keys::CoseKey::new();
        key.bytes = UID.to_vec();
        key.decode().unwrap();
        key.alg(algs::AES_MAC_128_64);
        key.key_ops(vec![keys::KEY_OPS_MAC_VERIFY]);
        verify.agents[r].key(&key).unwrap();
        verify.decode(None, Some(r)).unwrap();
    }
    #[test]
    fn c61() {
        let mut verify = CoseMessage::new_mac();
        verify.bytes = [
            209, 132, 67, 161, 1, 15, 160, 84, 84, 104, 105, 115, 32, 105, 115, 32, 116, 104, 101,
            32, 99, 111, 110, 116, 101, 110, 116, 46, 72, 114, 96, 67, 116, 80, 39, 33, 79,
        ]
        .to_vec();
        verify.init_decoder(None).unwrap();
        let mut key = keys::CoseKey::new();
        key.bytes = OUR_SECRET.to_vec();
        key.decode().unwrap();
        key.alg(algs::AES_MAC_256_64);
        verify.key(&key).unwrap();
        verify.decode(None, None).unwrap();
    }
    #[test]
    fn rsa() {
        use hex;
        let kid = &b"meriadoc.brandybuck@rsa.example".to_vec();
        let mut verify = CoseMessage::new_sign();
        verify.bytes = hex::decode("D8628443A10300A054546869732069732074686520636F6E74656E742E818344A1013824A104581F6D65726961646F632E6272616E64796275636B407273612E6578616D706C655901003AD4027074989995F25E167F99C9B4096FDC5C242D438D30382AE7B30F83C88D5B5EBECB64D2256D58D3CCE5C47D343BFA532B117C2D04DF3FB20679A99CF3555A7DAE6098BD123B0F3441A1E50E897CBAA1B17CE171EBAB20AE2E10F16D6EE918D37AF102175979BE65EBCEDEB47519346EA3ED6D13B5741BC63742AE31342B10B46FE93F39B55FDD6E32128FD8B476FED88F671F304D0943D2C7A33BCE48DF08E1F890CF5ACDA3EF46DA21981C3A687CFFF85EEB276A98612F38D6EE63644859D66A9AD49939EA290F7A9FDFED9AF1246930F522CB8C6909567DCBE2729716CB18A31E6F231DB3D69A7A432AA3D6FA1DEF9C9659616BEB626F158378E0FBDD").unwrap().to_vec();

        verify.init_decoder(None).unwrap();
        let v1 = verify.get_agent(kid).unwrap()[0];
        let mut key = keys::CoseKey::new();
        key.alg(algs::PS256);
        key.kty(keys::RSA);
        key.n(hex::decode("BC7E29D0DF7E20CC9DC8D509E0F68895922AF0EF452190D402C61B554334A7BF91C9A570240F994FAE1B69035BCFAD4F7E249EB26087C2665E7C958C967B1517413DC3F97A431691A5999B257CC6CD356BAD168D929B8BAE9020750E74CF60F6FD35D6BB3FC93FC28900478694F508B33E7C00E24F90EDF37457FC3E8EFCFD2F42306301A8205AB740515331D5C18F0C64D4A43BE52FC440400F6BFC558A6E32884C2AF56F29E5C52780CEA7285F5C057FC0DFDA232D0ADA681B01495D9D0E32196633588E289E59035FF664F056189F2F10FE05827B796C326E3E748FFA7C589ED273C9C43436CDDB4A6A22523EF8BCB2221615B799966F1ABA5BC84B7A27CF").unwrap());
        key.e(hex::decode("010001").unwrap());
        key.key_ops(vec![keys::KEY_OPS_VERIFY]);
        verify.agents[v1].key(&key).unwrap();

        verify.decode(None, Some(v1)).unwrap();
    }
    #[test]
    fn x5bag() {
        use hex;
        let mut verify = CoseMessage::new_sign();
        verify.bytes = hex::decode("D8628443A10300A054546869732069732074686520636F6E74656E742E818343A10126A2046E416C696365204C6F76656C6163651820825901AD308201A930820150A00302010202144E3019548429A2893D04B8EDBA143B8F7D17B276300A06082A8648CE3D040302302C312A30280603550403132153616D706C6520434F534520436572746966696361746520417574686F726974793020170D3230313230323137323732355A180F32303533313031303137323732355A3019311730150603550403130E416C696365204C6F76656C6163653059301306072A8648CE3D020106082A8648CE3D03010703420004863AA7BC0326716AA59DB5BF66CC660D0591D51E4891BC2E6A9BAFF5077D927CAD4EED482A7985BE019E9B1936C16E00190E8BCC48EE12D35FF89F0FC7A099CAA361305F300C0603551D130101FF04023000300F0603551D0F0101FF04050303078000301D0603551D0E041604141151555B01FF3F6DDDF9E5712AD3FF72A2D94D62301F0603551D230418301680141E6FC4D0C0DA004A8427CBBD3FE05A99EA2D2D11300A06082A8648CE3D0403020347003044022038FF9207872BA4D685700774783D35BE5B45AF59265A8567AE952D7182D5CBA00220163A18388EFE6310517385458AB4D3BBF7A0C23D9C87DA1CF378884FBBCDC86C5901A23082019E30820145A003020102021414A4957FD506AA2AAFC669A880032E8C95B87624300A06082A8648CE3D040302302C312A30280603550403132153616D706C6520434F534520436572746966696361746520417574686F726974793020170D3230313230323137323333325A180F32303533313031303137323333325A302C312A30280603550403132153616D706C6520434F534520436572746966696361746520417574686F726974793059301306072A8648CE3D020106082A8648CE3D030107034200047B447C98F731337AFBE3BAC96E793AF12865F3BD56B647A1729764191AE111F3161B4D56FA42F26E1B18DD87F9DB42F4C9168E420E2CE5E2D149648EE0EE5FB4A3433041300F0603551D130101FF040530030101FF300F0603551D0F0101FF04050303070600301D0603551D0E041604141E6FC4D0C0DA004A8427CBBD3FE05A99EA2D2D11300A06082A8648CE3D0403020347003044022006F99B3ACE00007BFB717784DDD230013D8CDCA0BABE20EE00039BEA0898A6D402200FFAF9DE61C1B6BD28BF5DDB1A191E63B22EAD4A69468D5222C487D53C33C2045840D27029503ED8CF40C7B73BBCB88C062467C0A50F0897D1559855F4FCF1788874BA8E3843D23B59566BC825102D573817437D91D0D765FA2165EFA390B50A03FF").unwrap().to_vec();

        verify.init_decoder(None).unwrap();
        let v1 = verify.get_agent(&b"Alice Lovelace".to_vec()).unwrap()[0];
        let mut key = keys::CoseKey::new();
        key.alg(algs::ES256);
        key.kty(keys::EC2);
        key.crv(keys::P_256);
        key.x(
            hex::decode("863aa7bc0326716aa59db5bf66cc660d0591d51e4891bc2e6a9baff5077d927c")
                .unwrap(),
        );
        key.y(
            hex::decode("ad4eed482a7985be019e9b1936c16e00190e8bcc48ee12d35ff89f0fc7a099ca")
                .unwrap(),
        );
        key.key_ops(vec![keys::KEY_OPS_VERIFY]);
        verify.agents[v1].key(&key).unwrap();

        verify.decode(None, Some(v1)).unwrap();
    }
    #[test]
    fn x5chain() {
        use hex;
        let mut verify = CoseMessage::new_sign();
        verify.bytes = hex::decode("D8628443A10300A054546869732069732074686520636F6E74656E742E818343A10126A11821825901AD308201A930820150A00302010202144E3019548429A2893D04B8EDBA143B8F7D17B276300A06082A8648CE3D040302302C312A30280603550403132153616D706C6520434F534520436572746966696361746520417574686F726974793020170D3230313230323137323732355A180F32303533313031303137323732355A3019311730150603550403130E416C696365204C6F76656C6163653059301306072A8648CE3D020106082A8648CE3D03010703420004863AA7BC0326716AA59DB5BF66CC660D0591D51E4891BC2E6A9BAFF5077D927CAD4EED482A7985BE019E9B1936C16E00190E8BCC48EE12D35FF89F0FC7A099CAA361305F300C0603551D130101FF04023000300F0603551D0F0101FF04050303078000301D0603551D0E041604141151555B01FF3F6DDDF9E5712AD3FF72A2D94D62301F0603551D230418301680141E6FC4D0C0DA004A8427CBBD3FE05A99EA2D2D11300A06082A8648CE3D0403020347003044022038FF9207872BA4D685700774783D35BE5B45AF59265A8567AE952D7182D5CBA00220163A18388EFE6310517385458AB4D3BBF7A0C23D9C87DA1CF378884FBBCDC86C5901A23082019E30820145A003020102021414A4957FD506AA2AAFC669A880032E8C95B87624300A06082A8648CE3D040302302C312A30280603550403132153616D706C6520434F534520436572746966696361746520417574686F726974793020170D3230313230323137323333325A180F32303533313031303137323333325A302C312A30280603550403132153616D706C6520434F534520436572746966696361746520417574686F726974793059301306072A8648CE3D020106082A8648CE3D030107034200047B447C98F731337AFBE3BAC96E793AF12865F3BD56B647A1729764191AE111F3161B4D56FA42F26E1B18DD87F9DB42F4C9168E420E2CE5E2D149648EE0EE5FB4A3433041300F0603551D130101FF040530030101FF300F0603551D0F0101FF04050303070600301D0603551D0E041604141E6FC4D0C0DA004A8427CBBD3FE05A99EA2D2D11300A06082A8648CE3D0403020347003044022006F99B3ACE00007BFB717784DDD230013D8CDCA0BABE20EE00039BEA0898A6D402200FFAF9DE61C1B6BD28BF5DDB1A191E63B22EAD4A69468D5222C487D53C33C2045840CFFD4CDA8DD573279CD6878F30DC44E1295D045BCB13D93D0C42A2F6F3B58C0757F39116ACD90B84EB0DA8818D2BBEB6B919905AF14BAF804599B772FD4A4ECD").unwrap().to_vec();

        verify.init_decoder(None).unwrap();
        let v1 = 0;
        let mut key = keys::CoseKey::new();
        key.alg(algs::ES256);
        key.kty(keys::EC2);
        key.crv(keys::P_256);
        key.x(
            hex::decode("863aa7bc0326716aa59db5bf66cc660d0591d51e4891bc2e6a9baff5077d927c")
                .unwrap(),
        );
        key.y(
            hex::decode("ad4eed482a7985be019e9b1936c16e00190e8bcc48ee12d35ff89f0fc7a099ca")
                .unwrap(),
        );
        key.key_ops(vec![keys::KEY_OPS_VERIFY]);
        verify.agents[v1].key(&key).unwrap();

        verify.decode(None, Some(v1)).unwrap();
    }
    #[test]
    fn x5chain_fail() {
        use crate::errors::CoseError;
        use hex;
        let mut verify = CoseMessage::new_sign();
        verify.bytes = hex::decode("D8628443A10300A054546869732069732074686520636F6E74656E742E818343A10126A11821825901A23082019E30820145A003020102021414A4957FD506AA2AAFC669A880032E8C95B87624300A06082A8648CE3D040302302C312A30280603550403132153616D706C6520434F534520436572746966696361746520417574686F726974793020170D3230313230323137323333325A180F32303533313031303137323333325A302C312A30280603550403132153616D706C6520434F534520436572746966696361746520417574686F726974793059301306072A8648CE3D020106082A8648CE3D030107034200047B447C98F731337AFBE3BAC96E793AF12865F3BD56B647A1729764191AE111F3161B4D56FA42F26E1B18DD87F9DB42F4C9168E420E2CE5E2D149648EE0EE5FB4A3433041300F0603551D130101FF040530030101FF300F0603551D0F0101FF04050303070600301D0603551D0E041604141E6FC4D0C0DA004A8427CBBD3FE05A99EA2D2D11300A06082A8648CE3D0403020347003044022006F99B3ACE00007BFB717784DDD230013D8CDCA0BABE20EE00039BEA0898A6D402200FFAF9DE61C1B6BD28BF5DDB1A191E63B22EAD4A69468D5222C487D53C33C2045901AD308201A930820150A00302010202144E3019548429A2893D04B8EDBA143B8F7D17B276300A06082A8648CE3D040302302C312A30280603550403132153616D706C6520434F534520436572746966696361746520417574686F726974793020170D3230313230323137323732355A180F32303533313031303137323732355A3019311730150603550403130E416C696365204C6F76656C6163653059301306072A8648CE3D020106082A8648CE3D03010703420004863AA7BC0326716AA59DB5BF66CC660D0591D51E4891BC2E6A9BAFF5077D927CAD4EED482A7985BE019E9B1936C16E00190E8BCC48EE12D35FF89F0FC7A099CAA361305F300C0603551D130101FF04023000300F0603551D0F0101FF04050303078000301D0603551D0E041604141151555B01FF3F6DDDF9E5712AD3FF72A2D94D62301F0603551D230418301680141E6FC4D0C0DA004A8427CBBD3FE05A99EA2D2D11300A06082A8648CE3D0403020347003044022038FF9207872BA4D685700774783D35BE5B45AF59265A8567AE952D7182D5CBA00220163A18388EFE6310517385458AB4D3BBF7A0C23D9C87DA1CF378884FBBCDC86C5840CFFD4CDA8DD573279CD6878F30DC44E1295D045BCB13D93D0C42A2F6F3B58C0757F39116ACD90B84EB0DA8818D2BBEB6B919905AF14BAF804599B772FD4A4ECD").unwrap().to_vec();

        match verify.init_decoder(None) {
            Ok(_) => {
                panic!("Key Chain validation failed")
            }
            Err(e) => match e {
                CoseError::InvalidKeyChain() => {}
                _ => panic!("Key Chain validation failed"),
            },
        };
    }
    #[test]
    fn x5t() {
        use hex;
        let mut verify = CoseMessage::new_sign();
        verify.bytes = hex::decode("D8628443A10300A054546869732069732074686520636F6E74656E742E818343A10126A11822822F582011FA0500D6763AE15A3238296E04C048A8FDD220A0DDA0234824B18FB66666005840E2868433DB5EB82E91F8BE52E8A67903A93332634470DE3DD90D52422B62DFE062248248AC388FAF77B277F91C4FB6EE776EDC52069C67F17D9E7FA57AC9BBA9").unwrap().to_vec();

        verify.init_decoder(None).unwrap();
        let v1 = 0;
        let mut key = keys::CoseKey::new();
        key.alg(algs::ES256);
        key.kty(keys::EC2);
        key.crv(keys::P_256);
        key.x(
            hex::decode("863aa7bc0326716aa59db5bf66cc660d0591d51e4891bc2e6a9baff5077d927c")
                .unwrap(),
        );
        key.y(
            hex::decode("ad4eed482a7985be019e9b1936c16e00190e8bcc48ee12d35ff89f0fc7a099ca")
                .unwrap(),
        );
        key.key_ops(vec![keys::KEY_OPS_VERIFY]);
        verify.agents[v1].key(&key).unwrap();

        verify.decode(None, Some(v1)).unwrap();
    }
    #[test]
    fn x5_sender() {
        use crate::agent::CoseAgent;
        use hex;

        let msg = b"This is the content.".to_vec();
        let r2_kid = b"22".to_vec();

        let mut r2_key = keys::CoseKey::new();
        r2_key.kty(keys::EC2);
        r2_key.crv(keys::P_256);
        r2_key.x(
            hex::decode("98F50A4FF6C05861C8860D13A638EA56C3F5AD7590BBFBF054E1C7B4D91D6280")
                .unwrap(),
        );
        r2_key.d(
            hex::decode("02D1F7E6F26C43D4868D87CEB2353161740AACF1F7163647984B522A848DF1C3")
                .unwrap(),
        );

        let x5_private = hex::decode("30770201010420d42044eb2cd2691e926da4871cf3529ddec6b034f824ba5e050d2c702f97c7a5a00a06082a8648ce3d030107a14403420004863aa7bc0326716aa59db5bf66cc660d0591d51e4891bc2e6a9baff5077d927cad4eed482a7985be019e9b1936c16e00190e8bcc48ee12d35ff89f0fc7a099ca").unwrap().to_vec();
        let x5chain = vec![
		     hex::decode("308201A930820150A00302010202144E3019548429A2893D04B8EDBA143B8F7D17B276300A06082A8648CE3D040302302C312A30280603550403132153616D706C6520434F534520436572746966696361746520417574686F726974793020170D3230313230323137323732355A180F32303533313031303137323732355A3019311730150603550403130E416C696365204C6F76656C6163653059301306072A8648CE3D020106082A8648CE3D03010703420004863AA7BC0326716AA59DB5BF66CC660D0591D51E4891BC2E6A9BAFF5077D927CAD4EED482A7985BE019E9B1936C16E00190E8BCC48EE12D35FF89F0FC7A099CAA361305F300C0603551D130101FF04023000300F0603551D0F0101FF04050303078000301D0603551D0E041604141151555B01FF3F6DDDF9E5712AD3FF72A2D94D62301F0603551D230418301680141E6FC4D0C0DA004A8427CBBD3FE05A99EA2D2D11300A06082A8648CE3D0403020347003044022038FF9207872BA4D685700774783D35BE5B45AF59265A8567AE952D7182D5CBA00220163A18388EFE6310517385458AB4D3BBF7A0C23D9C87DA1CF378884FBBCDC86C").unwrap().to_vec(),
		     hex::decode("3082019E30820145A003020102021414A4957FD506AA2AAFC669A880032E8C95B87624300A06082A8648CE3D040302302C312A30280603550403132153616D706C6520434F534520436572746966696361746520417574686F726974793020170D3230313230323137323333325A180F32303533313031303137323333325A302C312A30280603550403132153616D706C6520434F534520436572746966696361746520417574686F726974793059301306072A8648CE3D020106082A8648CE3D030107034200047B447C98F731337AFBE3BAC96E793AF12865F3BD56B647A1729764191AE111F3161B4D56FA42F26E1B18DD87F9DB42F4C9168E420E2CE5E2D149648EE0EE5FB4A3433041300F0603551D130101FF040530030101FF300F0603551D0F0101FF04050303070600301D0603551D0E041604141E6FC4D0C0DA004A8427CBBD3FE05A99EA2D2D11300A06082A8648CE3D0403020347003044022006F99B3ACE00007BFB717784DDD230013D8CDCA0BABE20EE00039BEA0898A6D402200FFAF9DE61C1B6BD28BF5DDB1A191E63B22EAD4A69468D5222C487D53C33C204").unwrap().to_vec(),
		  ];

        let mut enc = CoseMessage::new_encrypt();
        enc.header.alg(algs::A256GCM, true, false);
        enc.header.iv(
            hex::decode("89f52f65a1c580933b5261a7").unwrap(),
            true,
            false,
        );
        enc.payload(msg);

        let mut recipient2 = CoseAgent::new();
        recipient2.header.alg(algs::ECDH_ES_A128KW, true, false);
        recipient2.header.kid(r2_kid.clone(), false, false);
        recipient2.key(&r2_key).unwrap();
        recipient2.header.x5chain_sender(x5chain, true, false);
        recipient2.header.x5_private(x5_private);
        enc.add_agent(&mut recipient2).unwrap();

        enc.secure_content(None).unwrap();

        enc.encode(true).unwrap();

        r2_key.key_ops(vec![keys::KEY_OPS_DERIVE]);

        let mut dec = CoseMessage::new_encrypt();
        dec.bytes = enc.bytes;
        dec.init_decoder(None).unwrap();

        let r2_i = dec.get_agent(&r2_kid).unwrap()[0];
        dec.agents[r2_i].key(&r2_key).unwrap();
        let resp2 = dec.decode(None, Some(r2_i)).unwrap();
        assert_eq!(resp2, b"This is the content.".to_vec());
    }
}
