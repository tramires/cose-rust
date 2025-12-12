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
//!     key.kty(keys::EC2);
//!     key.alg(algs::ES256);
//!     key.crv(keys::P_256);
//!     key.d(hex::decode("57c92077664146e876760c9520d054aa93c3afb04e306705db6090308507b4d3").unwrap());
//!
//!     // Prepare cose-sign1 parameters
//!     signer.header.alg(algs::ES256, true, false);
//!     signer.header.kid(kid, true, false);
//!     signer.payload(msg);
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
//!     key.kty(keys::EC2);
//!     key.alg(algs::ES256);
//!     key.crv(keys::P_256);
//!     key.x(hex::decode("bac5b11cad8f99f9c72b05cf4b9e26d244dc189f745228255a219a86d6a09eff").unwrap());
//!     key.y(hex::decode("20138bf82dc1b6d562be0fa54ab7804a3a64b6d72ccfed6b6fb6ed28bbfc117e").unwrap());
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
//!     key.kty(keys::SYMMETRIC);
//!     key.alg(algs::CHACHA20);
//!     key.k(hex::decode("849b57219dae48de646d07dbb533566e976686457c1491be3a76dcea6c427188").unwrap());
//!
//!     // Prepare cose-encrypt0 parameters
//!     enc.header.alg(algs::CHACHA20, true, false);
//!     enc.header.iv(hex::decode("89f52f65a1c580933b5261a7").unwrap(), true, false);
//!     enc.payload(msg);
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
//!     key.kty(keys::SYMMETRIC);
//!     key.alg(algs::CHACHA20);
//!     key.k(hex::decode("849b57219dae48de646d07dbb533566e976686457c1491be3a76dcea6c427188").unwrap());
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
//!     key.kty(keys::SYMMETRIC);
//!     key.alg(algs::AES_MAC_256_128);
//!     key.k(hex::decode("849b57219dae48de646d07dbb533566e976686457c1491be3a76dcea6c427188").unwrap());
//!
//!     // Prepare the cose-mac0 parameters
//!     let mut mac = CoseMessage::new_mac();
//!     mac.header.alg(algs::AES_MAC_256_128, true, false);
//!     mac.payload(msg);
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
//!     key.kty(keys::SYMMETRIC);
//!     key.alg(algs::AES_MAC_256_128);
//!     key.k(hex::decode("849b57219dae48de646d07dbb533566e976686457c1491be3a76dcea6c427188").unwrap());
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
    use crate::agent::CoseAgent;
    use crate::algs;
    use crate::keys;
    use crate::message::CoseMessage;
    use std::fs;
    use std::path::Path;

    fn get_test_vec(id: &str) -> Vec<u8> {
        let path = format!("test_params/{}.bin", id);
        fs::read(Path::new(&path)).unwrap()
    }

    fn get_pub_key(kid: &Vec<u8>) -> keys::CoseKey {
        let key_set = include_bytes!("../test_params/pub_key_set.bin");
        let mut cose_ks = keys::CoseKeySet::new();
        cose_ks.bytes = key_set.to_vec();
        cose_ks.decode().unwrap();
        cose_ks.get_key(kid).unwrap()
    }

    fn get_priv_key(kid: &Vec<u8>) -> keys::CoseKey {
        let key_set = include_bytes!("../test_params/priv_key_set.bin");
        let mut cose_ks = keys::CoseKeySet::new();
        cose_ks.bytes = key_set.to_vec();
        cose_ks.decode().unwrap();
        cose_ks.get_key(kid).unwrap()
    }

    #[test]
    fn c11() {
        let kid = &b"11".to_vec();
        let mut verify = CoseMessage::new_sign();
        verify.bytes = get_test_vec("c11");
        verify.init_decoder(None).unwrap();
        let i = verify.get_agent(kid).unwrap()[0];
        let key = get_pub_key(&kid);
        verify.agents[i].key(&key).unwrap();
        verify.decode(None, Some(i)).unwrap();
    }

    #[test]
    fn prod_c11() {
        let kid = &b"11".to_vec();
        let payload = b"This is the content.".to_vec();
        let mut sign = CoseMessage::new_sign();
        sign.payload = payload;

        let key = get_priv_key(&kid);

        let mut agent = CoseAgent::new();
        agent.header.kid(kid.clone(), false, false);
        agent.header.alg(algs::ES256, true, false);

        agent.key(&key).unwrap();

        sign.add_agent(&mut agent).unwrap();
        sign.secure_content(None).unwrap();

        sign.encode(true).unwrap();
        assert_eq!(sign.bytes, get_test_vec("c11"));
    }

    #[test]
    fn c12() {
        let kid1 = &b"11".to_vec();
        let kid2 = &b"bilbo.baggins@hobbiton.example".to_vec();

        let mut verify = CoseMessage::new_sign();
        verify.bytes = get_test_vec("c12");
        verify.init_decoder(None).unwrap();

        let mut i = verify.get_agent(kid1).unwrap()[0];
        let mut key = get_pub_key(&kid1);
        verify.agents[i].key(&key).unwrap();
        verify.decode(None, Some(i)).unwrap();

        i = verify.get_agent(kid2).unwrap()[0];
        key = get_pub_key(&kid2);
        verify.agents[i].key(&key).unwrap();
        verify.decode(None, Some(i)).unwrap();
    }

    #[test]
    fn prod_c12() {
        let kid1 = &b"11".to_vec();
        let kid2 = &b"bilbo.baggins@hobbiton.example".to_vec();

        let payload = b"This is the content.".to_vec();
        let mut sign = CoseMessage::new_sign();
        sign.payload = payload;

        let mut key = get_priv_key(&kid1);
        let mut agent = CoseAgent::new();
        agent.header.kid(kid1.clone(), false, false);
        agent.header.alg(algs::ES256, true, false);
        agent.key(&key).unwrap();
        sign.add_agent(&mut agent).unwrap();

        key = get_priv_key(&kid2);
        agent = CoseAgent::new();
        agent.header.kid(kid2.clone(), false, false);
        agent.header.alg(algs::ES512, true, false);
        agent.key(&key).unwrap();
        sign.add_agent(&mut agent).unwrap();

        sign.secure_content(None).unwrap();

        // Remove probabilistic signature for ES512 agent ("SHOULD use a deterministic version of
        // ECDSA")
        sign.agents[1].payload = vec![];
        let mut t_vec = CoseMessage::new_sign();
        t_vec.bytes = get_test_vec("c12");
        t_vec.init_decoder(None).unwrap();
        t_vec.agents[1].payload = vec![];
        t_vec.encode(true).unwrap();

        sign.encode(true).unwrap();

        assert_eq!(sign.bytes, t_vec.bytes);
    }

    #[test]
    fn c13() {
        let kid = &b"11".to_vec();
        let mut verify = CoseMessage::new_sign();
        verify.bytes = get_test_vec("c13");
        verify.init_decoder(None).unwrap();

        let i = verify.get_agent(kid).unwrap()[0];
        let key = get_pub_key(&kid);
        verify.agents[i].key(&key).unwrap();
        verify.decode(None, Some(i)).unwrap();

        let counter = verify.header.get_counter(kid).unwrap()[0];
        verify.header.counters[counter].key(&key).unwrap();
        verify.counters_verify(None, counter).unwrap();
    }

    #[test]
    fn prod_c13() {
        let kid = &b"11".to_vec();
        let payload = b"This is the content.".to_vec();

        let mut sign = CoseMessage::new_sign();
        sign.payload = payload;

        let key = get_priv_key(&kid);
        let mut agent = CoseAgent::new();
        agent.header.kid(kid.clone(), false, false);
        agent.header.alg(algs::ES256, true, false);
        agent.key(&key).unwrap();

        sign.add_agent(&mut agent).unwrap();
        sign.secure_content(None).unwrap();

        agent = CoseAgent::new_counter_sig();
        agent.header.kid(kid.clone(), false, false);
        agent.header.alg(algs::ES256, true, false);
        agent.key(&key).unwrap();
        sign.counter_sig(None, &mut agent).unwrap();
        sign.add_counter_sig(agent).unwrap();

        sign.encode(true).unwrap();

        assert_eq!(sign.bytes, get_test_vec("c13"));
    }

    #[test]
    fn c21() {
        let mut verify = CoseMessage::new_sign();
        verify.bytes = get_test_vec("c21");
        verify.init_decoder(None).unwrap();

        let key = get_pub_key(&verify.header.kid.clone().unwrap());
        verify.key(&key).unwrap();

        verify.decode(None, None).unwrap();
    }

    #[test]
    fn prod_c21() {
        let kid = &b"11".to_vec();
        let payload = b"This is the content.".to_vec();

        let mut sign = CoseMessage::new_sign();
        sign.payload = payload;
        sign.header.kid(kid.clone(), false, false);
        sign.header.alg(algs::ES256, true, false);

        let key = get_priv_key(&kid);
        sign.key(&key).unwrap();

        sign.secure_content(None).unwrap();
        sign.encode(true).unwrap();

        assert_eq!(sign.bytes, get_test_vec("c21"));
    }

    #[test]
    fn c31() {
        let kid = &b"meriadoc.brandybuck@buckland.example".to_vec();
        let msg = b"This is the content.".to_vec();

        let mut dec = CoseMessage::new_encrypt();
        dec.bytes = get_test_vec("c31");
        dec.init_decoder(None).unwrap();

        let i = dec.get_agent(kid).unwrap()[0];
        let key = get_priv_key(kid);
        dec.agents[i].key(&key).unwrap();

        assert_eq!(dec.decode(None, Some(i)).unwrap(), msg);
    }

    #[test]
    fn prod_c31() {
        let kid = &b"meriadoc.brandybuck@buckland.example".to_vec();
        let eph_kid = &b"peregrin.took@tuckborough.example".to_vec();
        let payload = b"This is the content.".to_vec();

        let mut enc = CoseMessage::new_encrypt();
        enc.header.alg(algs::A128GCM, true, false);
        enc.header.iv(
            vec![201, 207, 77, 242, 254, 108, 99, 43, 247, 136, 100, 19],
            false,
            false,
        );
        enc.payload = payload;

        let mut key = get_priv_key(&kid);

        let mut agent = CoseAgent::new();
        agent.header.alg(algs::ECDH_ES_HKDF_256, true, false);
        agent.key(&key).unwrap();

        key = get_priv_key(eph_kid);

        agent.header.ephemeral_key(key, false, false);
        agent.header.kid(kid.clone(), false, false);

        enc.add_agent(&mut agent).unwrap();

        enc.secure_content(None).unwrap();

        enc.encode(true).unwrap();
        assert_eq!(enc.bytes, get_test_vec("c31"));
    }

    #[test]
    fn c32() {
        let kid = &b"our-secret".to_vec();
        let msg = b"This is the content.".to_vec();

        let mut dec = CoseMessage::new_encrypt();
        dec.bytes = get_test_vec("c32");
        dec.init_decoder(None).unwrap();

        let i = dec.get_agent(kid).unwrap()[0];
        let key = get_priv_key(kid);
        dec.agents[i].key(&key).unwrap();
        dec.agents[i]
            .header
            .party_identity(b"lighting-client".to_vec(), false, false, true, false);
        dec.agents[i].header.party_identity(
            b"lighting-server".to_vec(),
            false,
            false,
            false,
            false,
        );
        dec.agents[i]
            .header
            .pub_other(b"Encryption Example 02".to_vec());

        assert_eq!(dec.decode(None, Some(i)).unwrap(), msg);
    }

    #[test]
    fn prod_c32() {
        let kid = &b"our-secret".to_vec();
        let salt = b"aabbccddeeffgghh".to_vec();
        let payload = b"This is the content.".to_vec();

        let mut enc = CoseMessage::new_encrypt();
        enc.header.alg(algs::AES_CCM_16_64_128, true, false);
        enc.header.iv(
            vec![137, 245, 47, 101, 161, 197, 128, 147, 59, 82, 97, 167, 108],
            false,
            false,
        );
        enc.payload = payload;

        let key = get_priv_key(&kid);

        let mut agent = CoseAgent::new();
        agent.header.alg(algs::DIRECT_HKDF_SHA_256, true, false);
        agent.header.salt(salt, false, false);
        agent.header.kid(kid.clone(), false, false);
        agent
            .header
            .party_identity(b"lighting-client".to_vec(), false, false, true, false);
        agent
            .header
            .party_identity(b"lighting-server".to_vec(), false, false, false, false);
        agent.header.pub_other(b"Encryption Example 02".to_vec());
        agent.key(&key).unwrap();

        enc.add_agent(&mut agent).unwrap();

        enc.secure_content(None).unwrap();

        enc.encode(true).unwrap();
        assert_eq!(enc.bytes, get_test_vec("c32"));
    }

    #[test]
    fn c33() {
        let msg = b"This is the content.".to_vec();

        let mut dec = CoseMessage::new_encrypt();
        dec.bytes = get_test_vec("c33");
        dec.init_decoder(None).unwrap();

        let mut key = get_priv_key(&dec.agents[0].header.kid.clone().unwrap());
        dec.agents[0].key(&key).unwrap();

        key = get_priv_key(&dec.header.counters[0].header.kid.clone().unwrap());
        dec.header.counters[0].key(&key).unwrap();
        dec.counters_verify(None, 0).unwrap();

        assert_eq!(dec.decode(None, Some(0)).unwrap(), msg);
    }

    #[test]
    fn prod_c33() {
        let kid = &b"meriadoc.brandybuck@buckland.example".to_vec();
        let c_kid = &b"bilbo.baggins@hobbiton.example".to_vec();
        let eph_kid = &b"peregrin.took@tuckborough.example".to_vec();
        let payload = b"This is the content.".to_vec();

        let mut enc = CoseMessage::new_encrypt();
        enc.header.alg(algs::A128GCM, true, false);
        enc.header.iv(
            vec![201, 207, 77, 242, 254, 108, 99, 43, 247, 136, 100, 19],
            false,
            false,
        );
        enc.payload = payload;

        let mut key = get_pub_key(kid);

        let mut agent = CoseAgent::new();
        agent.header.alg(algs::ECDH_ES_HKDF_256, true, false);
        agent.key(&key).unwrap();

        key = get_priv_key(eph_kid);
        agent.header.ephemeral_key(key, false, false);
        agent.header.kid(kid.clone(), false, false);

        enc.add_agent(&mut agent).unwrap();

        enc.secure_content(None).unwrap();

        key = get_priv_key(c_kid);
        agent = CoseAgent::new_counter_sig();
        agent.header.kid(c_kid.clone(), false, false);
        agent.header.alg(algs::ES512, true, false);
        agent.key(&key).unwrap();
        enc.counter_sig(None, &mut agent).unwrap();
        enc.add_counter_sig(agent).unwrap();

        // Remove probabilistic signature for ES512 agent ("SHOULD use a deterministic version of
        // ECDSA")
        let mut test_vec = CoseMessage::new_encrypt();
        test_vec.bytes = get_test_vec("c33");
        test_vec.init_decoder(None).unwrap();
        test_vec.header.counters[0].payload = vec![];
        test_vec.encode(true).unwrap();
        enc.header.counters[0].payload = vec![];

        enc.encode(true).unwrap();

        assert_eq!(enc.bytes, test_vec.bytes);
    }

    #[test]
    fn c34() {
        let kid = &b"meriadoc.brandybuck@buckland.example".to_vec();
        let static_kid = &b"peregrin.took@tuckborough.example".to_vec();
        let msg = b"This is the content.".to_vec();
        let aad = vec![0, 17, 187, 204, 34, 221, 68, 238, 85, 255, 102, 0, 119];

        let mut dec = CoseMessage::new_encrypt();
        dec.bytes = get_test_vec("c34");
        dec.init_decoder(None).unwrap();

        let i = dec.get_agent(&kid.clone()).unwrap()[0];
        let mut key = get_priv_key(kid);
        dec.agents[i].key(&key).unwrap();

        key = get_pub_key(static_kid);
        dec.agents[i].header.ecdh_key(key);

        assert_eq!(dec.decode(Some(aad), Some(i)).unwrap(), msg);
    }

    #[test]
    fn prod_c34() {
        let kid = &b"meriadoc.brandybuck@buckland.example".to_vec();
        let static_kid = &b"peregrin.took@tuckborough.example".to_vec();
        let payload = b"This is the content.".to_vec();
        let aad = vec![0, 17, 187, 204, 34, 221, 68, 238, 85, 255, 102, 0, 119];

        let mut enc = CoseMessage::new_encrypt();
        enc.header.alg(algs::A128GCM, true, false);
        enc.header.iv(
            vec![2, 209, 247, 230, 242, 108, 67, 212, 134, 141, 135, 206],
            false,
            false,
        );
        enc.payload = payload;

        let mut key = get_priv_key(&kid);

        let mut agent = CoseAgent::new();
        agent.header.alg(algs::ECDH_SS_A128KW, true, false);
        agent.key(&key).unwrap();

        key = get_priv_key(static_kid);

        agent
            .header
            .static_key_id(static_kid.clone(), key, false, false);
        agent.header.kid(kid.clone(), false, false);
        agent.header.party_nonce(vec![1, 1], false, false, true);

        enc.add_agent(&mut agent).unwrap();

        enc.secure_content(Some(aad)).unwrap();

        // Remove probabilistic ciphertext and CEK
        let mut test_vec = CoseMessage::new_encrypt();
        test_vec.bytes = get_test_vec("c34");
        test_vec.init_decoder(None).unwrap();
        test_vec.agents[0].payload = vec![];
        test_vec.secured = vec![];
        test_vec.encode(true).unwrap();
        enc.agents[0].payload = vec![];
        enc.secured = vec![];

        enc.encode(true).unwrap();

        assert_eq!(enc.bytes, test_vec.bytes);
    }

    #[test]
    fn c41() {
        let kid = &b"our-secret2".to_vec();
        let msg = b"This is the content.".to_vec();

        let mut dec = CoseMessage::new_encrypt();
        dec.bytes = get_test_vec("c41");
        dec.init_decoder(None).unwrap();
        let key = get_priv_key(kid);
        dec.key(&key).unwrap();

        assert_eq!(dec.decode(None, None).unwrap(), msg);
    }

    #[test]
    fn prod_c41() {
        let kid = &b"our-secret2".to_vec();
        let msg = b"This is the content.".to_vec();

        let mut enc = CoseMessage::new_encrypt();
        enc.header.alg(algs::AES_CCM_16_64_128, true, false);
        enc.header.iv(
            vec![137, 245, 47, 101, 161, 197, 128, 147, 59, 82, 97, 167, 140],
            false,
            false,
        );
        enc.payload = msg;

        let key = get_priv_key(kid);
        enc.key(&key).unwrap();
        enc.secure_content(None).unwrap();
        enc.encode(true).unwrap();

        assert_eq!(enc.bytes, get_test_vec("c41"));
    }

    #[test]
    fn c42() {
        let kid = &b"our-secret2".to_vec();
        let msg = b"This is the content.".to_vec();

        let mut dec = CoseMessage::new_encrypt();
        dec.bytes = get_test_vec("c42");
        dec.init_decoder(None).unwrap();
        let mut key = get_priv_key(kid);
        key.base_iv(vec![137, 245, 47, 101, 161, 197, 128, 147]);
        dec.key(&key).unwrap();

        assert_eq!(dec.decode(None, None).unwrap(), msg);
    }

    #[test]
    fn prod_c42() {
        let kid = &b"our-secret2".to_vec();
        let msg = b"This is the content.".to_vec();

        let mut enc = CoseMessage::new_encrypt();
        enc.header.alg(algs::AES_CCM_16_64_128, true, false);
        enc.header.partial_iv(vec![97, 167], false, false);
        enc.payload = msg;

        let mut key = get_priv_key(kid);
        key.base_iv(vec![137, 245, 47, 101, 161, 197, 128, 147]);
        enc.key(&key).unwrap();
        enc.secure_content(None).unwrap();
        enc.encode(true).unwrap();

        assert_eq!(enc.bytes, get_test_vec("c42"));
    }

    #[test]
    fn c51() {
        let kid = &b"our-secret".to_vec();
        let mut verify = CoseMessage::new_mac();
        verify.bytes = get_test_vec("c51");
        verify.init_decoder(None).unwrap();

        let i = verify.get_agent(kid).unwrap()[0];

        let key = get_priv_key(kid);
        verify.agents[i].key(&key).unwrap();
        verify.decode(None, Some(i)).unwrap();
    }

    #[test]
    fn prod_c51() {
        let kid = &b"our-secret".to_vec();
        let payload = b"This is the content.".to_vec();

        let mut enc = CoseMessage::new_mac();
        enc.header.alg(algs::AES_MAC_256_64, true, false);
        enc.payload = payload;

        let key = get_priv_key(&kid);

        let mut agent = CoseAgent::new();
        agent.header.alg(algs::DIRECT, false, false);
        agent.header.kid(kid.clone(), false, false);
        agent.key(&key).unwrap();

        enc.add_agent(&mut agent).unwrap();

        enc.secure_content(None).unwrap();

        enc.encode(true).unwrap();
        assert_eq!(enc.bytes, get_test_vec("c51"));
    }

    #[test]
    fn c52() {
        let kid = &b"meriadoc.brandybuck@buckland.example".to_vec();
        let static_kid = &b"peregrin.took@tuckborough.example".to_vec();

        let mut verify = CoseMessage::new_mac();
        verify.bytes = get_test_vec("c52");
        verify.init_decoder(None).unwrap();

        let i = verify.get_agent(kid).unwrap()[0];
        let mut key = get_priv_key(kid);
        verify.agents[i].key(&key).unwrap();

        key = get_priv_key(static_kid);
        verify.agents[i].header.ecdh_key(key);

        verify.decode(None, Some(i)).unwrap();
    }

    #[test]
    fn prod_c52() {
        let kid = &b"meriadoc.brandybuck@buckland.example".to_vec();
        let static_kid = &b"peregrin.took@tuckborough.example".to_vec();
        let payload = b"This is the content.".to_vec();

        let mut enc = CoseMessage::new_mac();
        enc.header.alg(algs::HMAC_256_256, true, false);
        enc.payload = payload;

        let mut key = get_priv_key(&kid);

        let mut agent = CoseAgent::new();
        agent.header.alg(algs::ECDH_SS_HKDF_256, true, false);
        agent.key(&key).unwrap();

        key = get_priv_key(&static_kid);
        agent
            .header
            .static_key_id(static_kid.clone(), key, false, false);
        agent.header.kid(kid.clone(), false, false);
        agent.header.party_nonce(
            vec![
                77, 133, 83, 231, 231, 79, 60, 106, 58, 157, 211, 239, 40, 106, 129, 149, 203, 248,
                162, 61, 25, 85, 140, 207, 236, 125, 52, 184, 36, 244, 45, 146, 189, 6, 189, 44,
                127, 2, 113, 240, 33, 78, 20, 31, 183, 121, 174, 40, 86, 171, 245, 133, 165, 131,
                104, 176, 23, 231, 242, 169, 229, 206, 77, 181,
            ],
            false,
            false,
            true,
        );

        enc.add_agent(&mut agent).unwrap();

        enc.secure_content(None).unwrap();

        enc.encode(true).unwrap();
        assert_eq!(enc.bytes, get_test_vec("c52"));
    }

    #[test]
    fn c53() {
        let kid = &b"018c0ae5-4d9b-471b-bfd6-eef314bc7037".to_vec();

        let mut verify = CoseMessage::new_mac();
        verify.bytes = get_test_vec("c53");
        verify.init_decoder(None).unwrap();

        let i = verify.get_agent(kid).unwrap()[0];
        let key = get_priv_key(&kid);

        verify.agents[i].key(&key).unwrap();

        verify.decode(None, Some(i)).unwrap();
    }

    #[test]
    fn prod_c53() {
        let kid = &b"018c0ae5-4d9b-471b-bfd6-eef314bc7037".to_vec();
        let payload = b"This is the content.".to_vec();

        let mut enc = CoseMessage::new_mac();
        enc.header.alg(algs::AES_MAC_128_64, true, false);
        enc.payload = payload;

        let key = get_priv_key(&kid);

        let mut agent = CoseAgent::new();
        agent.header.alg(algs::A256KW, false, false);
        agent.header.kid(kid.clone(), false, false);
        agent.key(&key).unwrap();

        enc.add_agent(&mut agent).unwrap();

        enc.secure_content(None).unwrap();

        // Remove probabilistic
        let mut test_vec = CoseMessage::new_mac();
        test_vec.bytes = get_test_vec("c53");
        test_vec.init_decoder(None).unwrap();
        test_vec.agents[0].payload = vec![];
        test_vec.secured = vec![];
        test_vec.encode(true).unwrap();
        enc.agents[0].payload = vec![];
        enc.secured = vec![];

        enc.encode(true).unwrap();
        assert_eq!(enc.bytes, test_vec.bytes);
    }

    #[test]
    fn c54() {
        let kid1 = &b"018c0ae5-4d9b-471b-bfd6-eef314bc7037".to_vec();
        let kid2 = &b"bilbo.baggins@hobbiton.example".to_vec();

        let mut verify = CoseMessage::new_mac();
        verify.bytes = get_test_vec("c54");
        verify.init_decoder(None).unwrap();

        let mut i = verify.get_agent(kid1).unwrap()[0];
        let mut key = get_priv_key(kid1);
        verify.agents[i].key(&key).unwrap();

        verify.decode(None, Some(i)).unwrap();

        i = verify.get_agent(kid2).unwrap()[0];
        key = get_priv_key(kid2);
        verify.agents[i].key(&key).unwrap();

        verify.decode(None, Some(i)).unwrap();
    }
    #[test]
    fn prod_c54() {
        let kid1 = &b"bilbo.baggins@hobbiton.example".to_vec();
        let kid2 = &b"018c0ae5-4d9b-471b-bfd6-eef314bc7037".to_vec();
        let payload = b"This is the content.".to_vec();

        let mut enc = CoseMessage::new_mac();
        enc.header.alg(algs::HMAC_256_256, true, false);
        enc.payload = payload;

        let key = get_priv_key(&kid1);

        let mut agent = CoseAgent::new();
        agent.header.alg(algs::ECDH_ES_A128KW, true, false);
        agent.key(&key).unwrap();

        let mut eph_key = keys::CoseKey::new();
        eph_key.kty(keys::EC2);
        eph_key.crv(keys::P_521);
        eph_key.d(hex::decode("000624B09A73EAD64AE07C0EBDA18126F02C80720DA239C8643198DBC1A10F967E5183D915678503CB78808F831AED26FF7D0F1E638AC58CD398E2AD00AC8A9B56E6").unwrap());
        eph_key.x(hex::decode("0043b12669acac3fd27898ffba0bcd2e6c366d53bc4db71f909a759304acfb5e18cdc7ba0b13ff8c7636271a6924b1ac63c02688075b55ef2d613574e7dc242f79c3").unwrap());
        eph_key.y_parity(true);

        agent.header.ephemeral_key(eph_key, false, false);
        agent.header.kid(kid1.clone(), false, false);

        enc.add_agent(&mut agent).unwrap();

        let key = get_priv_key(&kid2);

        let mut agent = CoseAgent::new();
        agent.header.alg(algs::A256KW, false, false);
        agent.header.kid(kid2.clone(), false, false);
        agent.key(&key).unwrap();

        enc.add_agent(&mut agent).unwrap();

        enc.secure_content(None).unwrap();

        // Remove probabilistic
        let mut test_vec = CoseMessage::new_mac();
        test_vec.bytes = get_test_vec("c54");
        test_vec.init_decoder(None).unwrap();
        test_vec.agents[0].payload = vec![];
        test_vec.agents[1].payload = vec![];
        test_vec.secured = vec![];
        test_vec.encode(true).unwrap();
        enc.agents[0].payload = vec![];
        enc.agents[1].payload = vec![];
        enc.secured = vec![];

        enc.encode(true).unwrap();
        assert_eq!(enc.bytes, test_vec.bytes);
    }

    #[test]
    fn c61() {
        let kid = &b"our-secret".to_vec();

        let mut verify = CoseMessage::new_mac();
        verify.bytes = get_test_vec("c61");
        verify.init_decoder(None).unwrap();

        let key = get_priv_key(kid);

        verify.key(&key).unwrap();
        verify.decode(None, None).unwrap();
    }

    #[test]
    fn prod_c61() {
        let kid = &b"our-secret".to_vec();
        let msg = b"This is the content.".to_vec();

        let mut enc = CoseMessage::new_mac();
        enc.header.alg(algs::AES_MAC_256_64, true, false);
        enc.payload = msg;

        let key = get_priv_key(kid);
        enc.key(&key).unwrap();
        enc.secure_content(None).unwrap();
        enc.encode(true).unwrap();

        assert_eq!(enc.bytes, get_test_vec("c61"));
    }
    #[test]
    fn rsa_pss_01() {
        let kid = &b"meriadoc.brandybuck@rsa.example".to_vec();
        let mut verify = CoseMessage::new_sign();
        verify.bytes = get_test_vec("rsa_pss_01");
        verify.init_decoder(None).unwrap();

        let i = verify.get_agent(kid).unwrap()[0];
        let key = get_pub_key(kid);
        verify.agents[i].key(&key).unwrap();

        verify.decode(None, Some(i)).unwrap();
    }
    #[test]
    fn prod_rsa_pss_01() {
        use crate::headers::ContentTypeTypes;
        let kid = &b"meriadoc.brandybuck@rsa.example".to_vec();
        let msg = b"This is the content.".to_vec();

        let mut sign = CoseMessage::new_sign();
        sign.header
            .content_type(ContentTypeTypes::Uint(0), true, false);
        sign.payload = msg;

        let key = get_priv_key(kid);
        let mut agent = CoseAgent::new();
        agent.header.alg(algs::PS256, true, false);
        agent.header.kid(kid.clone(), false, false);
        agent.key(&key).unwrap();

        sign.add_agent(&mut agent).unwrap();

        sign.secure_content(None).unwrap();

        // Remove probabilistic
        let mut test_vec = CoseMessage::new_sign();
        test_vec.bytes = get_test_vec("rsa_pss_01");
        test_vec.init_decoder(None).unwrap();
        test_vec.agents[0].payload = vec![];
        test_vec.encode(true).unwrap();
        sign.agents[0].payload = vec![];

        sign.encode(true).unwrap();

        assert_eq!(sign.bytes, test_vec.bytes);
    }

    #[test]
    fn rsa_oaep_01() {
        let kid = &b"meriadoc.brandybuck@rsa.example".to_vec();
        let mut verify = CoseMessage::new_encrypt();
        verify.bytes = get_test_vec("rsa_oaep_01");
        verify.init_decoder(None).unwrap();

        let i = verify.get_agent(kid).unwrap()[0];
        let key = get_priv_key(kid);
        verify.agents[i].key(&key).unwrap();

        verify.decode(None, Some(i)).unwrap();
    }

    #[test]
    fn prod_rsa_oaep_01() {
        let kid = &b"meriadoc.brandybuck@rsa.example".to_vec();
        let payload = b"This is the content.".to_vec();

        let mut enc = CoseMessage::new_encrypt();
        enc.header.alg(algs::A128GCM, true, false);
        enc.header.iv(
            vec![217, 122, 179, 165, 199, 45, 47, 13, 126, 95, 141, 94],
            false,
            false,
        );
        enc.payload = payload;

        let key = get_pub_key(&kid);

        let mut agent = CoseAgent::new();
        agent.header.alg(algs::RSA_OAEP_1, false, false);
        agent.header.kid(kid.clone(), false, false);
        agent.key(&key).unwrap();

        enc.add_agent(&mut agent).unwrap();

        enc.secure_content(None).unwrap();

        // Remove probabilistic
        let mut test_vec = CoseMessage::new_encrypt();
        test_vec.bytes = get_test_vec("rsa_oaep_01");
        test_vec.init_decoder(None).unwrap();
        test_vec.agents[0].payload = vec![];
        test_vec.secured = vec![];
        test_vec.encode(true).unwrap();
        enc.agents[0].payload = vec![];
        enc.secured = vec![];
        enc.encode(true).unwrap();

        assert_eq!(enc.bytes, test_vec.bytes);
    }

    #[test]
    fn x509_signed_02() {
        let kid = &b"Alice Lovelace".to_vec();
        let mut verify = CoseMessage::new_sign();
        verify.bytes = get_test_vec("x509_signed_02");

        verify.init_decoder(None).unwrap();
        let v1 = verify.get_agent(kid).unwrap()[0];
        let key = get_pub_key(&kid);
        verify.agents[v1].key(&key).unwrap();

        verify.decode(None, Some(v1)).unwrap();
    }
    #[test]
    fn prod_x509_signed_02() {
        use crate::agent::CoseAgent;
        use crate::headers::ContentTypeTypes;
        use hex;

        let msg = b"This is the content.".to_vec();
        let kid = &b"Alice Lovelace".to_vec();

        let key = get_priv_key(kid);

        let x5_private = hex::decode("30770201010420d42044eb2cd2691e926da4871cf3529ddec6b034f824ba5e050d2c702f97c7a5a00a06082a8648ce3d030107a14403420004863aa7bc0326716aa59db5bf66cc660d0591d51e4891bc2e6a9baff5077d927cad4eed482a7985be019e9b1936c16e00190e8bcc48ee12d35ff89f0fc7a099ca").unwrap().to_vec();
        let x5bag = vec![
		     hex::decode("308201A930820150A00302010202144E3019548429A2893D04B8EDBA143B8F7D17B276300A06082A8648CE3D040302302C312A30280603550403132153616D706C6520434F534520436572746966696361746520417574686F726974793020170D3230313230323137323732355A180F32303533313031303137323732355A3019311730150603550403130E416C696365204C6F76656C6163653059301306072A8648CE3D020106082A8648CE3D03010703420004863AA7BC0326716AA59DB5BF66CC660D0591D51E4891BC2E6A9BAFF5077D927CAD4EED482A7985BE019E9B1936C16E00190E8BCC48EE12D35FF89F0FC7A099CAA361305F300C0603551D130101FF04023000300F0603551D0F0101FF04050303078000301D0603551D0E041604141151555B01FF3F6DDDF9E5712AD3FF72A2D94D62301F0603551D230418301680141E6FC4D0C0DA004A8427CBBD3FE05A99EA2D2D11300A06082A8648CE3D0403020347003044022038FF9207872BA4D685700774783D35BE5B45AF59265A8567AE952D7182D5CBA00220163A18388EFE6310517385458AB4D3BBF7A0C23D9C87DA1CF378884FBBCDC86C").unwrap().to_vec(),
		     hex::decode("3082019E30820145A003020102021414A4957FD506AA2AAFC669A880032E8C95B87624300A06082A8648CE3D040302302C312A30280603550403132153616D706C6520434F534520436572746966696361746520417574686F726974793020170D3230313230323137323333325A180F32303533313031303137323333325A302C312A30280603550403132153616D706C6520434F534520436572746966696361746520417574686F726974793059301306072A8648CE3D020106082A8648CE3D030107034200047B447C98F731337AFBE3BAC96E793AF12865F3BD56B647A1729764191AE111F3161B4D56FA42F26E1B18DD87F9DB42F4C9168E420E2CE5E2D149648EE0EE5FB4A3433041300F0603551D130101FF040530030101FF300F0603551D0F0101FF04050303070600301D0603551D0E041604141E6FC4D0C0DA004A8427CBBD3FE05A99EA2D2D11300A06082A8648CE3D0403020347003044022006F99B3ACE00007BFB717784DDD230013D8CDCA0BABE20EE00039BEA0898A6D402200FFAF9DE61C1B6BD28BF5DDB1A191E63B22EAD4A69468D5222C487D53C33C204").unwrap().to_vec(),
		  ];

        let mut enc = CoseMessage::new_sign();
        enc.header
            .content_type(ContentTypeTypes::Uint(0), true, false);
        enc.payload(msg);

        let mut recipient2 = CoseAgent::new();
        recipient2.header.alg(algs::ES256, true, false);
        recipient2.key(&key).unwrap();
        recipient2.header.kid(kid.clone(), false, false);
        recipient2.header.x5bag(x5bag, false, false);
        recipient2.header.x5_private(x5_private);
        enc.add_agent(&mut recipient2).unwrap();

        enc.secure_content(None).unwrap();

        // Remove probabilistic ciphertext and CEK
        let mut test_vec = CoseMessage::new_sign();
        test_vec.bytes = get_test_vec("x509_signed_02");
        test_vec.init_decoder(None).unwrap();
        test_vec.agents[0].payload = vec![];
        test_vec.encode(true).unwrap();
        enc.agents[0].payload = vec![];
        enc.encode(true).unwrap();

        assert_eq!(enc.bytes, test_vec.bytes);
    }
    #[test]
    fn x509_signed_04() {
        let mut verify = CoseMessage::new_sign();
        verify.bytes = get_test_vec("x509_signed_04");

        verify.init_decoder(None).unwrap();
        let key = get_pub_key(&b"Alice Lovelace".to_vec());
        verify.agents[0].key(&key).unwrap();

        verify.decode(None, Some(0)).unwrap();
    }
    #[test]
    fn prod_x509_signed_04() {
        use crate::agent::CoseAgent;
        use crate::headers::ContentTypeTypes;
        use hex;

        let msg = b"This is the content.".to_vec();
        let kid = &b"Alice Lovelace".to_vec();

        let key = get_priv_key(kid);

        let x5_private = hex::decode("30770201010420d42044eb2cd2691e926da4871cf3529ddec6b034f824ba5e050d2c702f97c7a5a00a06082a8648ce3d030107a14403420004863aa7bc0326716aa59db5bf66cc660d0591d51e4891bc2e6a9baff5077d927cad4eed482a7985be019e9b1936c16e00190e8bcc48ee12d35ff89f0fc7a099ca").unwrap().to_vec();
        let x5chain = vec![
		     hex::decode("308201A930820150A00302010202144E3019548429A2893D04B8EDBA143B8F7D17B276300A06082A8648CE3D040302302C312A30280603550403132153616D706C6520434F534520436572746966696361746520417574686F726974793020170D3230313230323137323732355A180F32303533313031303137323732355A3019311730150603550403130E416C696365204C6F76656C6163653059301306072A8648CE3D020106082A8648CE3D03010703420004863AA7BC0326716AA59DB5BF66CC660D0591D51E4891BC2E6A9BAFF5077D927CAD4EED482A7985BE019E9B1936C16E00190E8BCC48EE12D35FF89F0FC7A099CAA361305F300C0603551D130101FF04023000300F0603551D0F0101FF04050303078000301D0603551D0E041604141151555B01FF3F6DDDF9E5712AD3FF72A2D94D62301F0603551D230418301680141E6FC4D0C0DA004A8427CBBD3FE05A99EA2D2D11300A06082A8648CE3D0403020347003044022038FF9207872BA4D685700774783D35BE5B45AF59265A8567AE952D7182D5CBA00220163A18388EFE6310517385458AB4D3BBF7A0C23D9C87DA1CF378884FBBCDC86C").unwrap().to_vec(),
		     hex::decode("3082019E30820145A003020102021414A4957FD506AA2AAFC669A880032E8C95B87624300A06082A8648CE3D040302302C312A30280603550403132153616D706C6520434F534520436572746966696361746520417574686F726974793020170D3230313230323137323333325A180F32303533313031303137323333325A302C312A30280603550403132153616D706C6520434F534520436572746966696361746520417574686F726974793059301306072A8648CE3D020106082A8648CE3D030107034200047B447C98F731337AFBE3BAC96E793AF12865F3BD56B647A1729764191AE111F3161B4D56FA42F26E1B18DD87F9DB42F4C9168E420E2CE5E2D149648EE0EE5FB4A3433041300F0603551D130101FF040530030101FF300F0603551D0F0101FF04050303070600301D0603551D0E041604141E6FC4D0C0DA004A8427CBBD3FE05A99EA2D2D11300A06082A8648CE3D0403020347003044022006F99B3ACE00007BFB717784DDD230013D8CDCA0BABE20EE00039BEA0898A6D402200FFAF9DE61C1B6BD28BF5DDB1A191E63B22EAD4A69468D5222C487D53C33C204").unwrap().to_vec(),
		  ];

        let mut enc = CoseMessage::new_sign();
        enc.header
            .content_type(ContentTypeTypes::Uint(0), true, false);
        enc.payload(msg);

        let mut recipient2 = CoseAgent::new();
        recipient2.header.alg(algs::ES256, true, false);
        recipient2.key(&key).unwrap();
        recipient2.header.x5chain(x5chain, false, false);
        recipient2.header.x5_private(x5_private);
        enc.add_agent(&mut recipient2).unwrap();

        enc.secure_content(None).unwrap();

        // Remove probabilistic ciphertext and CEK
        let mut test_vec = CoseMessage::new_sign();
        test_vec.bytes = get_test_vec("x509_signed_04");
        test_vec.init_decoder(None).unwrap();
        test_vec.agents[0].payload = vec![];
        test_vec.encode(true).unwrap();
        enc.agents[0].payload = vec![];
        enc.encode(true).unwrap();

        assert_eq!(enc.bytes, test_vec.bytes);
    }
    #[test]
    fn x509_signed_05() {
        let mut verify = CoseMessage::new_sign();
        verify.bytes = get_test_vec("x509_signed_05");

        verify.init_decoder(None).unwrap();
        let key = get_pub_key(&b"Alice Lovelace".to_vec());
        let v1 = 0;
        verify.agents[v1].key(&key).unwrap();

        verify.decode(None, Some(v1)).unwrap();
    }
    #[test]
    fn prod_x509_signed_05() {
        use crate::agent::CoseAgent;
        use crate::headers::ContentTypeTypes;
        use hex;

        let msg = b"This is the content.".to_vec();
        let kid = &b"Alice Lovelace".to_vec();

        let key = get_priv_key(kid);

        let x5_private =
            hex::decode("00d42044eb2cd2691e926da4871cf3529ddec6b034f824ba5e050d2c702f97c7a5")
                .unwrap()
                .to_vec();
        let x5t = hex::decode("11FA0500D6763AE15A3238296E04C048A8FDD220A0DDA0234824B18FB6666600")
            .unwrap()
            .to_vec();

        let mut enc = CoseMessage::new_sign();
        enc.header
            .content_type(ContentTypeTypes::Uint(0), true, false);
        enc.payload(msg);

        let mut recipient2 = CoseAgent::new();
        recipient2.header.alg(algs::ES256, true, false);
        recipient2.key(&key).unwrap();
        recipient2
            .header
            .x5t(x5t, algs::SHA_256, false, false)
            .unwrap();
        recipient2.header.x5_private(x5_private);
        enc.add_agent(&mut recipient2).unwrap();

        enc.secure_content(None).unwrap();

        // Remove probabilistic ciphertext and CEK
        let mut test_vec = CoseMessage::new_sign();
        test_vec.bytes = get_test_vec("x509_signed_05");
        test_vec.init_decoder(None).unwrap();
        test_vec.agents[0].payload = vec![];
        test_vec.encode(true).unwrap();
        enc.agents[0].payload = vec![];
        enc.encode(true).unwrap();

        assert_eq!(enc.bytes, test_vec.bytes);
    }
}
