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
//!     // Prepare cose-sign message
//!     let mut sign = CoseMessage::new_sign();
//!     sign.payload(msg);
//!
//!     // Add signer 1
//!     let mut signer1 = CoseAgent::new();
//!
//!     let mut s1_key = keys::CoseKey::new();
//!     s1_key.bytes = hex::decode("A601020258246D65726961646F632E6272616E64796275636B406275636B6C616E642E6578616D706C65200121582065EDA5A12577C2BAE829437FE338701A10AAA375E1BB5B5DE108DE439C08551D2258201E52ED75701163F7F9E40DDF9F341B3DC9BA860AF7E0CA7CA7E9EECD0084D19C235820AFF907C99F9AD3AAE6C4CDF21122BCE2BD68B5283E6907154AD911840FA208CF").unwrap();
//!     s1_key.decode().unwrap();
//!
//!     signer1.header.alg(algs::ES256, true, false);
//!     signer1.header.kid(s1_kid.clone(), false, false);
//!     signer1.key(&s1_key).unwrap();
//!     sign.add_agent(&mut signer1).unwrap();
//!
//!     // And add signer 2
//!     let mut signer2 = CoseAgent::new();
//!
//!     let mut s2_key = keys::CoseKey::new();
//!     s2_key.bytes = hex::decode("A60102024231312001215820BAC5B11CAD8F99F9C72B05CF4B9E26D244DC189F745228255A219A86D6A09EFF22582020138BF82DC1B6D562BE0FA54AB7804A3A64B6D72CCFED6B6FB6ED28BBFC117E23582057C92077664146E876760C9520D054AA93C3AFB04E306705DB6090308507B4D3").unwrap();
//!     s2_key.decode().unwrap();
//!
//!     signer2.header.alg(algs::ES256, true, false);
//!     signer2.header.kid(s2_key.kid.clone().unwrap(), true, false);
//!     signer2.key(&s2_key).unwrap();
//!     sign.add_agent(&mut signer2).unwrap();
//!
//!     // Generate signature and encode cose-sign message
//!     sign.secure_content(None).unwrap();
//!     sign.encode(true).unwrap();
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
//!
//!     // Prepare signer 1 key
//!     let mut s1_key = keys::CoseKey::new();
//!     s1_key.bytes = hex::decode("A601020258246D65726961646F632E6272616E64796275636B406275636B6C616E642E6578616D706C65200121582065EDA5A12577C2BAE829437FE338701A10AAA375E1BB5B5DE108DE439C08551D2258201E52ED75701163F7F9E40DDF9F341B3DC9BA860AF7E0CA7CA7E9EECD0084D19C235820AFF907C99F9AD3AAE6C4CDF21122BCE2BD68B5283E6907154AD911840FA208CF").unwrap();
//!     s1_key.decode().unwrap();
//!
//!     // Prepare signer 2 key
//!     let mut s2_key = keys::CoseKey::new();
//!     s2_key.bytes = hex::decode("A60102024231312001215820BAC5B11CAD8F99F9C72B05CF4B9E26D244DC189F745228255A219A86D6A09EFF22582020138BF82DC1B6D562BE0FA54AB7804A3A64B6D72CCFED6B6FB6ED28BBFC117E23582057C92077664146E876760C9520D054AA93C3AFB04E306705DB6090308507B4D3").unwrap();
//!     s2_key.decode().unwrap();
//!
//!     // Prepare CoseSign with the cose-sign bytes
//!     let mut verify = CoseMessage::new_sign();
//!     verify.bytes =
//!     hex::decode("d8628440a054546869732069732074686520636f6e74656e742e8283582aa201260458246d65726961646f632e6272616e64796275636b406275636b6c616e642e6578616d706c65a05840b0714b778d405c76414fdefbc6499459a76a9f3741326b5b961ac7b87bf1f705697e5789eddb3ed722ca76eb125654b2a8b9f2135d2869bf4b97ddd90f16c5ab8347a2012604423131a058401234cb1cf8ca3ef16e78233a9e46192a17f7c70dbac76c7721f5a4da759ae1c3ccda943ecc62d12668a261550cc4bf39046f484f99ab9526c7916c09d189c0c1").unwrap();
//!
//!     // Init decoding
//!     verify.init_decoder(None).unwrap();
//!
//!     // Get signer 1 and verify
//!     let mut i1 = verify.get_agent(&s1_key.kid.clone().unwrap()).unwrap()[0];
//!     verify.agents[i1].key(&s1_key).unwrap();
//!     verify.decode(None, Some(i1)).unwrap();
//!
//!     // Get signer 2 and verify
//!     let mut i2 = verify.get_agent(&s2_key.kid.clone().unwrap()).unwrap()[0];
//!     verify.agents[i2].key(&s2_key).unwrap();
//!     verify.decode(None, Some(i2)).unwrap();
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
//!     // Prepare recipient cose-key
//!     let mut key = keys::CoseKey::new();
//!     key.bytes = hex::decode("A30104024B6F75722D736563726574322050849B5786457C1491BE3A76DCEA6C4271").unwrap();
//!     key.decode().unwrap();
//!
//!     // Prepare cose-encrypt message
//!     let mut enc = CoseMessage::new_encrypt();
//!     enc.header.alg(algs::A128GCM, true, false);
//!     enc.header.iv(hex::decode("89f52f65a1c580933b5261a7").unwrap(), true, false);
//!     enc.payload(msg);
//!
//!     // Add recipient to cose-encrypt message
//!     let mut rec= CoseAgent::new();
//!     rec.header.alg(algs::DIRECT, false, false);
//!     rec.header.kid(key.kid.clone().unwrap(), false, false);
//!     rec.key(&key).unwrap();
//!     enc.add_agent(&mut rec).unwrap();
//!
//!     // Generate ciphertext and encode cose-encrypt message
//!     enc.secure_content(None).unwrap();
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
//!     // Prepare recipient cose-key
//!     let mut key = keys::CoseKey::new();
//!     key.bytes = hex::decode("A30104024B6F75722D736563726574322050849B5786457C1491BE3A76DCEA6C4271").unwrap();
//!     key.decode().unwrap();
//!
//!     // Prepare CoseEncrypt struct with the cose-encrypt bytes
//!     let mut dec = CoseMessage::new_encrypt();
//!     dec.bytes =
//!     hex::decode("d8608443a10101a1054c89f52f65a1c580933b5261a75824b148914af99b365b06a29477e0fbd05a57acf3f987392a3d49818c394fa4771bdb2c2fc5818340a20125044b6f75722d7365637265743240").unwrap();
//!     dec.init_decoder(None).unwrap();
//!
//!     // Get recipient and the decode message
//!     let mut i = dec.get_agent(&key.kid.clone().unwrap()).unwrap()[0];
//!     dec.agents[i].key(&key).unwrap();
//!     let resp = dec.decode(None, Some(i)).unwrap();
//!     assert_eq!(resp, msg);
//!
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
//!
//!     // Prepare sender key
//!     let mut key_ecdh_send = keys::CoseKey::new();
//!     key_ecdh_send.bytes = hex::decode("A6200121582065EDA5A12577C2BAE829437FE338701A10AAA375E1BB5B5DE108DE439C08551D2258201E52ED75701163F7F9E40DDF9F341B3DC9BA860AF7E0CA7CA7E9EECD0084D19C235820AFF907C99F9AD3AAE6C4CDF21122BCE2BD68B5283E6907154AD911840FA208CF01020258246D65726961646F632E6272616E64796275636B406275636B6C616E642E6578616D706C65").unwrap();
//!     key_ecdh_send.decode().unwrap();
//!
//!     // Prepare receiver key
//!     let mut key_ecdh_rec = keys::CoseKey::new();
//!     key_ecdh_rec.bytes = hex::decode("A52001215820BAC5B11CAD8F99F9C72B05CF4B9E26D244DC189F745228255A219A86D6A09EFF22582020138BF82DC1B6D562BE0FA54AB7804A3A64B6D72CCFED6B6FB6ED28BBFC117E010202423131").unwrap();
//!     key_ecdh_rec.decode().unwrap();
//!
//!     // Prepare cose-mac message
//!     let mut mac = CoseMessage::new_mac();
//!     mac.header.alg(algs::AES_MAC_256_128, true, false);
//!     mac.payload(msg);
//!
//!     // Add recipient 1 (ECDH ephemeral A128KW)
//!     let mut rec1 = CoseAgent::new();
//!     rec1.header.alg(algs::ECDH_ES_A128KW, true, false);
//!     rec1.header.kid(key_ecdh_rec.kid.clone().unwrap(), false, false);
//!     rec1.key(&key_ecdh_rec).unwrap();
//!     rec1.header.ephemeral_key(key_ecdh_send.clone(), true, false);
//!     mac.add_agent(&mut rec1).unwrap();
//!
//!     // Add recipient 2 (ECDH static key A128KW)
//!     let mut rec2 = CoseAgent::new();
//!     rec2.header.alg(algs::ECDH_SS_A128KW, true, false);
//!     rec2.header.kid(key_ecdh_rec.kid.clone().unwrap(), false, false);
//!     rec2.key(&key_ecdh_rec).unwrap();
//!     rec2.header.static_key(key_ecdh_send.clone(), true, false);
//!     mac.add_agent(&mut rec2).unwrap();
//!
//!     // Add recipient 3 (ECDH static key ID A128KW)
//!     let mut rec3 = CoseAgent::new();
//!     rec3.header.alg(algs::ECDH_SS_A128KW, true, false);
//!     rec3.header.kid(key_ecdh_rec.kid.clone().unwrap(), false, false);
//!     rec3.key(&key_ecdh_rec).unwrap();
//!     rec3.header.static_key_id(key_ecdh_send.kid.clone().unwrap(), key_ecdh_send, true, false);
//!     mac.add_agent(&mut rec3).unwrap();
//!
//!     // Generate tag and encode the cose-mac message
//!     mac.secure_content(None).unwrap();
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
//!
//!     // Prepare sender key
//!     let mut key_ecdh_send = keys::CoseKey::new();
//!     key_ecdh_send.bytes = hex::decode("A5200121582065EDA5A12577C2BAE829437FE338701A10AAA375E1BB5B5DE108DE439C08551D2258201E52ED75701163F7F9E40DDF9F341B3DC9BA860AF7E0CA7CA7E9EECD0084D19C01020258246D65726961646F632E6272616E64796275636B406275636B6C616E642E6578616D706C65").unwrap();
//!     key_ecdh_send.decode().unwrap();
//!
//!     // Prepare receiver key
//!     let mut key_ecdh_rec = keys::CoseKey::new();
//!     key_ecdh_rec.bytes = hex::decode("A62001215820BAC5B11CAD8F99F9C72B05CF4B9E26D244DC189F745228255A219A86D6A09EFF22582020138BF82DC1B6D562BE0FA54AB7804A3A64B6D72CCFED6B6FB6ED28BBFC117E23582057C92077664146E876760C9520D054AA93C3AFB04E306705DB6090308507B4D3010202423131").unwrap();
//!     key_ecdh_rec.decode().unwrap();
//!
//!     // Generate Cose-mac struct with the cose-mac bytes
//!     let mut verify = CoseMessage::new_mac();
//!     verify.bytes =
//!     hex::decode("d8618552a201181a054c89f52f65a1c580933b5261a7a054546869732069732074686520636f6e74656e742e502a0e524fed1d0742b59c1c15cd519ba983835850a201381c20a4200121582065eda5a12577c2bae829437fe338701a10aaa375e1bb5b5de108de439c08551d2258201e52ed75701163f7f9e40ddf9f341b3dc9ba860af7e0ca7ca7e9eecd0084d19c0102a10442313158286b10f4e2b8a95c7b23ebd253d79b5f658e895ffd5edcaea274cf416ef1c24820f6425ae5effc1f1f835877a201381f21a5200121582065eda5a12577c2bae829437fe338701a10aaa375e1bb5b5de108de439c08551d2258201e52ed75701163f7f9e40ddf9f341b3dc9ba860af7e0ca7ca7e9eecd0084d19c01020258246d65726961646f632e6272616e64796275636b406275636b6c616e642e6578616d706c65a1044231315828effd0914890f90b6b6cf99533fcb6726a42b92661bc7594ef78cc8083b328580372503cea33967c483582ba201381f2258246d65726961646f632e6272616e64796275636b406275636b6c616e642e6578616d706c65a104423131582890d7d1cadeb712aa7426e7a7b9ad6554c1e5c79ebfe974c96b64f275c3f3e9fe09aee3ea5b7bc4f1").unwrap();
//!     verify.init_decoder(None).unwrap();
//!
//!     // Get recipient 1 and decode message (Ephemeral Key)
//!     verify.agents[0].key(&key_ecdh_rec).unwrap();
//!     verify.decode(None, Some(0)).unwrap();
//!
//!     // Get recipient 2 and decode message (Static Key)
//!     verify.agents[1].key(&key_ecdh_rec).unwrap();
//!     verify.decode(None, Some(1)).unwrap();
//!
//!     // Get recipient 3 and decode message (Static Key ID)
//!     verify.agents[2].key(&key_ecdh_rec).unwrap();
//!     verify.agents[2].header.ecdh_key(key_ecdh_send);
//!     verify.decode(None, Some(2)).unwrap();
//! }
//! ```

use crate::agent::CoseAgent;
use crate::algs;
use crate::common;
use crate::cose_struct;
use crate::errors::{CoseError, CoseField, CoseResult, CoseResultWithRet};
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
    pub(super) secured: Vec<u8>,
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
        agent.context = CONTEXTS[self.context].to_string();
        if self.context == SIG {
            if !algs::SIGNING_ALGS
                .contains(&agent.header.alg.ok_or(CoseError::Missing(CoseField::Alg))?)
            {
                return Err(CoseError::Invalid(CoseField::Alg));
            }
            if !agent.key_ops.is_empty() && !agent.key_ops.contains(&keys::KEY_OPS_SIGN) {
                return Err(CoseError::Invalid(CoseField::KeyOp));
            }
        } else if (self.context == MAC || self.context == ENC)
            && !algs::KEY_DISTRIBUTION_ALGS
                .contains(&agent.header.alg.ok_or(CoseError::Missing(CoseField::Alg))?)
        {
            return Err(CoseError::Invalid(CoseField::Alg));
        }
        self.agents.push(agent.clone());
        Ok(())
    }

    /// Returns a signer/recipient ([agent](../agent/struct.CoseAgent.html)) of the message with a given Key ID.
    pub fn get_agent(&self, kid: &Vec<u8>) -> CoseResultWithRet<Vec<usize>> {
        let mut keys: Vec<usize> = Vec::new();
        for i in 0..self.agents.len() {
            if self.agents[i]
                .header
                .kid
                .as_ref()
                .ok_or(CoseError::Missing(CoseField::Kid))?
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
        if !self.agents.is_empty() {
            return Err(CoseError::InvalidMethodMultipleAgents());
        }
        cose_key.verify_kty()?;
        if cose_key.alg.is_some()
            && cose_key.alg.ok_or(CoseError::Missing(CoseField::Alg))?
                != self.header.alg.ok_or(CoseError::Missing(CoseField::Alg))?
        {
            return Err(CoseError::AlgMismatch());
        }
        if self.context == SIG {
            self.crv = cose_key.crv;
            if cose_key.key_ops.is_empty() || cose_key.key_ops.contains(&keys::KEY_OPS_SIGN) {
                let priv_key = match cose_key.get_s_key() {
                    Ok(v) => v,
                    Err(_) => Vec::new(),
                };
                if !priv_key.is_empty() {
                    self.key_encode = true;
                    self.priv_key = priv_key;
                }
            }
            if cose_key.key_ops.is_empty() || cose_key.key_ops.contains(&keys::KEY_OPS_VERIFY) {
                let pub_key = match cose_key.get_pub_key() {
                    Ok(v) => v,
                    Err(_) => Vec::new(),
                };
                if !pub_key.is_empty() {
                    self.key_decode = true;
                    self.pub_key = pub_key;
                }
            }
        } else {
            if self.context == ENC {
                self.base_iv = cose_key.base_iv.clone();
            }
            let key = cose_key.get_s_key()?;
            if !key.is_empty() {
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
                    && (cose_key.key_ops.is_empty()
                        || cose_key.key_ops.contains(&keys::KEY_OPS_DECRYPT)))
                    || (self.context == MAC
                        && (cose_key.key_ops.is_empty()
                            || cose_key.key_ops.contains(&keys::KEY_OPS_MAC_VERIFY)))
                {
                    self.key_decode = true;
                }
                self.priv_key = key;
            }
        }
        if !self.key_encode && !self.key_decode {
            return Err(CoseError::Invalid(CoseField::KeyOp));
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
        if to_sig.is_empty() {
            if self.context == ENC {
                Err(CoseError::Missing(CoseField::Ciphertext))
            } else {
                Err(CoseError::Missing(CoseField::Payload))
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
        if to_sig.is_empty() {
            if self.context == ENC {
                Err(CoseError::Missing(CoseField::Ciphertext))
            } else {
                Err(CoseError::Missing(CoseField::Payload))
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
        if to_sig.is_empty() {
            if self.context == ENC {
                Err(CoseError::Missing(CoseField::Ciphertext))
            } else {
                Err(CoseError::Missing(CoseField::Payload))
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
        if to_sig.is_empty() {
            if self.context == ENC {
                Err(CoseError::Missing(CoseField::Ciphertext))
            } else {
                Err(CoseError::Missing(CoseField::Payload))
            }
        } else {
            let aead = match external_aad {
                None => Vec::new(),
                Some(v) => v,
            };
            if self.header.counters[counter].verify(to_sig, &aead, &self.ph_bstr)? {
                Ok(())
            } else {
                Err(CoseError::Invalid(CoseField::CounterSignature))
            }
        }
    }

    /// Function that adds a counter signature which was signed externally with the use of
    /// [get_to_sign](#method.get_to_sign)
    pub fn add_counter_sig(&mut self, counter: CoseAgent) -> CoseResult {
        if !algs::SIGNING_ALGS.contains(
            &counter
                .header
                .alg
                .ok_or(CoseError::Missing(CoseField::Alg))?,
        ) {
            return Err(CoseError::Invalid(CoseField::Alg));
        }
        if counter.context != cose_struct::COUNTER_SIGNATURE {
            return Err(CoseError::InvalidContext(counter.context));
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
        if self.payload.is_empty() {
            return Err(CoseError::Missing(CoseField::Payload));
        }
        self.ph_bstr = self.header.get_protected_bstr(true)?;
        let aead = match external_aad {
            None => Vec::new(),
            Some(v) => v,
        };
        if self.agents.is_empty() {
            if !self.key_encode {
                return Err(CoseError::Invalid(CoseField::KeyOp));
            }
            let alg = self.header.alg.ok_or(CoseError::Missing(CoseField::Alg))?;
            if self.context == SIG {
                if !algs::SIGNING_ALGS.contains(&alg) {
                    Err(CoseError::Invalid(CoseField::Alg))
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
                    Err(CoseError::Invalid(CoseField::Alg))
                } else {
                    let iv = match self.base_iv.clone() {
                        Some(v) => algs::gen_iv(
                            self.header
                                .partial_iv
                                .as_ref()
                                .ok_or(CoseError::Missing(CoseField::PartialIv))?,
                            &v,
                            &alg,
                        )?,
                        None => self
                            .header
                            .iv
                            .clone()
                            .ok_or(CoseError::Missing(CoseField::Iv))?,
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
                    Err(CoseError::Invalid(CoseField::Alg))
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
                    if !algs::SIGNING_ALGS.contains(
                        &self.agents[i]
                            .header
                            .alg
                            .ok_or(CoseError::Missing(CoseField::Alg))?,
                    ) {
                        return Err(CoseError::Invalid(CoseField::Alg));
                    } else if !self.agents[i].key_ops.is_empty()
                        && !self.agents[i].key_ops.contains(&keys::KEY_OPS_SIGN)
                    {
                        return Err(CoseError::Invalid(CoseField::KeyOp));
                    } else {
                        self.agents[i].sign(&self.payload, &aead, &self.ph_bstr)?;
                        self.agents[i].enc = true;
                    }
                }
                Ok(())
            } else {
                let alg = self.header.alg.ok_or(CoseError::Missing(CoseField::Alg))?;
                let mut cek;
                if algs::DIRECT
                    == self.agents[0]
                        .header
                        .alg
                        .ok_or(CoseError::Missing(CoseField::Alg))?
                {
                    if self.agents.len() > 1 {
                        return Err(CoseError::DirectAlgMultipleRecipientsError());
                    }
                    if !self.agents[0].key_ops.is_empty()
                        && !self.agents[0].key_ops.contains(&KO[self.context][0])
                    {
                        return Err(CoseError::Invalid(CoseField::KeyOp));
                    } else {
                        if self.context == ENC {
                            self.secured = cose_struct::gen_cipher(
                                &self.agents[0].s_key,
                                &alg,
                                self.header
                                    .iv
                                    .as_ref()
                                    .ok_or(CoseError::Missing(CoseField::Iv))?,
                                &aead,
                                cose_struct::ENCRYPT,
                                &self.ph_bstr,
                                &self.payload,
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
                        .ok_or(CoseError::Missing(CoseField::Alg))?,
                ) {
                    if self.agents.len() > 1 {
                        return Err(CoseError::DirectAlgMultipleRecipientsError());
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
                            return Err(CoseError::DirectAlgMultipleRecipientsError());
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
                                .ok_or(CoseError::Missing(CoseField::PartialIv))?,
                            &v,
                            &alg,
                        )?,
                        None => self
                            .header
                            .iv
                            .clone()
                            .ok_or(CoseError::Missing(CoseField::Iv))?,
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
        if self.agents.is_empty() {
            if self.secured.is_empty() {
                if self.context == SIG {
                    Err(CoseError::Missing(CoseField::Signature))
                } else if self.context == MAC {
                    Err(CoseError::Missing(CoseField::Mac))
                } else {
                    Err(CoseError::Missing(CoseField::Ciphertext))
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
                    return Err(CoseError::Invalid(CoseField::Tag));
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
        if !self.ph_bstr.is_empty() {
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

        if (self.context == ENC && self.secured.is_empty())
            || (self.context != ENC && self.payload.is_empty())
        {
            if self.context == ENC {
                return Err(CoseError::Missing(CoseField::Ciphertext));
            } else {
                return Err(CoseError::Missing(CoseField::Payload));
            }
        }

        if self.context != SIG {
            if self.header.alg.ok_or(CoseError::Missing(CoseField::Alg))? == algs::DIRECT
                && !self.ph_bstr.is_empty()
            {
                return Err(CoseError::InvalidCoseStructure());
            } else if algs::A_KW.contains(
                self.header
                    .alg
                    .as_ref()
                    .ok_or(CoseError::Missing(CoseField::Alg))?,
            ) && !self.ph_bstr.is_empty()
            {
                return Err(CoseError::InvalidCoseStructure());
            }
        }

        if self.context == MAC {
            self.secured = d.bytes()?.to_vec();
            if self.secured.is_empty() {
                return Err(CoseError::Missing(CoseField::Payload));
            }
        }

        match d.kernel().typeinfo() {
            Ok(type_info) => {
                if type_info.0 == Type::Array
                    && (!tag.is_some() || tag.unwrap() == TAGS[self.context][1])
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
                    && (!tag.is_some() || tag.unwrap() == TAGS[self.context][0])
                {
                    if self.context == SIG {
                        self.secured = d.kernel().raw_data(type_info.1, 0x500000)?;
                    }
                    if self.secured.is_empty() {
                        if self.context == SIG {
                            return Err(CoseError::Missing(CoseField::Signature));
                        } else if self.context == MAC {
                            return Err(CoseError::Missing(CoseField::Mac));
                        } else {
                            return Err(CoseError::Missing(CoseField::Ciphertext));
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
        if self.agents.is_empty() {
            if !self.key_decode {
                return Err(CoseError::Invalid(CoseField::KeyOp));
            } else {
                if self.context == SIG {
                    if !cose_struct::verify_sig(
                        &self.pub_key,
                        &self.header.alg.ok_or(CoseError::Missing(CoseField::Alg))?,
                        &self.crv,
                        &aead,
                        cose_struct::SIGNATURE1,
                        &self.ph_bstr,
                        &Vec::new(),
                        &self.payload,
                        &self.secured,
                    )? {
                        Err(CoseError::Invalid(CoseField::Signature))
                    } else {
                        Ok(self.payload.clone())
                    }
                } else if self.context == MAC {
                    if !cose_struct::verify_mac(
                        &self.priv_key,
                        &self.header.alg.ok_or(CoseError::Missing(CoseField::Alg))?,
                        &aead,
                        cose_struct::MAC0,
                        &self.ph_bstr,
                        &self.secured,
                        &self.payload,
                    )? {
                        return Err(CoseError::Invalid(CoseField::Mac));
                    } else {
                        Ok(self.payload.clone())
                    }
                } else {
                    let iv = match self.base_iv.clone() {
                        Some(v) => algs::gen_iv(
                            self.header
                                .partial_iv
                                .as_ref()
                                .ok_or(CoseError::Missing(CoseField::PartialIv))?,
                            &v,
                            &self.header.alg.ok_or(CoseError::Missing(CoseField::Alg))?,
                        )?,
                        None => self
                            .header
                            .iv
                            .clone()
                            .ok_or(CoseError::Missing(CoseField::Iv))?,
                    };
                    Ok(cose_struct::dec_cipher(
                        &self.priv_key,
                        &self.header.alg.ok_or(CoseError::Missing(CoseField::Alg))?,
                        &iv,
                        &aead,
                        cose_struct::ENCRYPT0,
                        &self.ph_bstr,
                        &self.secured,
                    )?)
                }
            }
        } else if agent.is_some() {
            let index = agent.ok_or(CoseError::Missing(CoseField::Signer))?;
            if self.context == SIG {
                if self.agents[index].pub_key.is_empty()
                    || !self.agents[index].key_ops.is_empty()
                        && !self.agents[index].key_ops.contains(&keys::KEY_OPS_VERIFY)
                {
                    Err(CoseError::Invalid(CoseField::KeyOp))
                } else {
                    if !self.agents[index].verify(&self.payload, &aead, &self.ph_bstr)? {
                        Err(CoseError::Invalid(CoseField::Signature))
                    } else {
                        Ok(self.payload.clone())
                    }
                }
            } else {
                let alg = self.header.alg.ok_or(CoseError::Missing(CoseField::Alg))?;
                let cek;
                if algs::DIRECT
                    == self.agents[index]
                        .header
                        .alg
                        .ok_or(CoseError::Missing(CoseField::Alg))?
                {
                    if !self.agents[index].key_ops.is_empty()
                        && !self.agents[index].key_ops.contains(&KO[self.context][1])
                    {
                        return Err(CoseError::Invalid(CoseField::KeyOp));
                    } else {
                        if !self.agents[index].s_key.is_empty() {
                            cek = self.agents[index].s_key.clone();
                        } else {
                            return Err(CoseError::Invalid(CoseField::KeyOp));
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
                                .ok_or(CoseError::Missing(CoseField::PartialIv))?,
                            &v,
                            &alg,
                        )?,
                        None => self
                            .header
                            .iv
                            .clone()
                            .ok_or(CoseError::Missing(CoseField::Iv))?,
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
                        Err(CoseError::Invalid(CoseField::Mac))
                    } else {
                        Ok(self.payload.clone())
                    }
                }
            }
        } else {
            return Err(CoseError::Missing(CoseField::Signer));
        }
    }
}
