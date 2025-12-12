//! Module to build recipients/signers for the various types of COSE messages.
//!
//! This structure is also used to build counter signatures that can be present in any type of COSE
//! message.
//!
//! # Example
//!
//! This example shows a cose-sign1 message with 2 counter signatures present in it, one of them is
//! counter signed externally to the crate.
//!
//! ## Encoding the message
//!
//! ```
//! use cose::message::CoseMessage;
//! use cose::agent::CoseAgent;
//! use cose::keys;
//! use cose::algs;
//! use openssl::bn::BigNum;
//! use openssl::bn::BigNumContext;
//! use openssl::ec::EcPoint;
//! use openssl::ec::{EcGroup, EcKey};
//! use openssl::hash::MessageDigest;
//! use openssl::pkey::PKey;
//! use openssl::sign::{Signer, Verifier};
//! use openssl::nid::Nid;
//! use hex;
//!
//! fn main() {
//!     let msg = b"This is the content.".to_vec();
//!
//!     // Prepare cose-key
//!     let mut key = keys::CoseKey::new();
//!     key.bytes =
//!     hex::decode("A601020258246D65726961646F632E6272616E64796275636B406275636B6C616E642E6578616D706C65200121582065EDA5A12577C2BAE829437FE338701A10AAA375E1BB5B5DE108DE439C08551D2258201E52ED75701163F7F9E40DDF9F341B3DC9BA860AF7E0CA7CA7E9EECD0084D19C235820AFF907C99F9AD3AAE6C4CDF21122BCE2BD68B5283E6907154AD911840FA208CF").unwrap();
//!     key.decode().unwrap();
//!
//!     // Prepare cose_sign1 message
//!     let mut sign1 = CoseMessage::new_sign();
//!     sign1.header.alg(algs::ES256, true, false);
//!     sign1.header.kid(key.kid.clone().unwrap(), true, false);
//!     sign1.payload(msg);
//!
//!     // Add key and generate the signature without AAD
//!     sign1.key(&key).unwrap();
//!     sign1.secure_content(None).unwrap();
//!
//!     // Prepare counter signature
//!     let mut ckey = keys::CoseKey::new();
//!     ckey.bytes =
//!     hex::decode("A60102024231312001215820BAC5B11CAD8F99F9C72B05CF4B9E26D244DC189F745228255A219A86D6A09EFF22582020138BF82DC1B6D562BE0FA54AB7804A3A64B6D72CCFED6B6FB6ED28BBFC117E23582057C92077664146E876760C9520D054AA93C3AFB04E306705DB6090308507B4D3").unwrap();
//!     ckey.decode().unwrap();
//!
//!     let mut counter = CoseAgent::new_counter_sig();
//!     counter.header.alg(algs::ES256, true, false);
//!     counter.header.kid(ckey.kid.clone().unwrap(), true, false);
//!
//!     // Add counter signature 1 key, counter sign and add to the cose-sign1 message
//!     counter.key(&ckey).unwrap();
//!     sign1.counter_sig(None, &mut counter).unwrap();
//!     sign1.add_counter_sig(counter).unwrap();
//!
//!     // Encode cose-sign1 message
//!     sign1.encode(true).unwrap();
//! }
//!
//! ```
//!
//! ## Decoding the message
//!
//! ```
//! use cose::message::CoseMessage;
//! use cose::agent::CoseAgent;
//! use cose::keys;
//! use cose::algs;
//! use openssl::bn::BigNum;
//! use openssl::bn::BigNumContext;
//! use openssl::ec::EcPoint;
//! use openssl::ec::{EcGroup, EcKey};
//! use openssl::hash::MessageDigest;
//! use openssl::pkey::PKey;
//! use openssl::sign::{Signer, Verifier};
//! use openssl::nid::Nid;
//! use hex;
//!
//! fn main() {
//!
//!     // Prepare cose-key
//!     let mut key = keys::CoseKey::new();
//!     key.bytes =
//!     hex::decode("A601020258246D65726961646F632E6272616E64796275636B406275636B6C616E642E6578616D706C65200121582065EDA5A12577C2BAE829437FE338701A10AAA375E1BB5B5DE108DE439C08551D2258201E52ED75701163F7F9E40DDF9F341B3DC9BA860AF7E0CA7CA7E9EECD0084D19C235820AFF907C99F9AD3AAE6C4CDF21122BCE2BD68B5283E6907154AD911840FA208CF").unwrap();
//!     key.decode().unwrap();
//!
//!     // Prepare CoseMessage with the cose-sign1 message to decode
//!     let mut verify = CoseMessage::new_sign();
//!     verify.bytes = hex::decode("d284582aa201260458246d65726961646f632e6272616e64796275636b406275636b6c616e642e6578616d706c65a1078347a2044231310126a0584043e4f6cb352d4fc0942b129e76cdf89690fe2a7a2a5d015abac74968c72b22064126ea3addec92c6ba5257be4295e631f34478f1d7a80be3ac832bd714a39cee54546869732069732074686520636f6e74656e742e58408c6d7a58caa8e23ad509ba291cb17689d61e4ad96a51b4a76d46785655df118cc4137815606d983e0bc55ab45f332aebfef85d4c50965269fc90de5651235ba1").unwrap();
//!     verify.init_decoder(None).unwrap();
//!
//!     // Add key and decode the message
//!     verify.key(&key).unwrap();
//!     verify.decode(None, None).unwrap();
//!
//!     // Counter cose-key
//!     let mut ckey = keys::CoseKey::new();
//!     ckey.bytes =
//!     hex::decode("A60102024231312001215820BAC5B11CAD8F99F9C72B05CF4B9E26D244DC189F745228255A219A86D6A09EFF22582020138BF82DC1B6D562BE0FA54AB7804A3A64B6D72CCFED6B6FB6ED28BBFC117E23582057C92077664146E876760C9520D054AA93C3AFB04E306705DB6090308507B4D3").unwrap();
//!     ckey.decode().unwrap();
//!
//!     // Add counter key and verify
//!     verify.header.counters[0].key(&ckey).unwrap();
//!     verify.counters_verify(None, 0).unwrap();
//! }
//! ```

use crate::algs;
use crate::cose_struct;
use crate::errors::{CoseError, CoseField, CoseResult, CoseResultWithRet};
use crate::headers::{CoseHeader, COUNTER_SIG};
use crate::keys;
use cbor::{Decoder, Encoder};
use std::io::Cursor;

/// COSE recipient, signer or counter-signature structure.
#[derive(Clone)]
pub struct CoseAgent {
    /// Header of the CoseAgent (recipient, signer or counter-signature).
    pub header: CoseHeader,
    /// Payload (signature, ciphertext or MAC).
    pub payload: Vec<u8>,
    pub(crate) ph_bstr: Vec<u8>,
    /// Public key.
    pub pub_key: Vec<u8>,
    /// Private/Symmetric key.
    pub s_key: Vec<u8>,
    pub(crate) context: String,
    pub(crate) crv: Option<i32>,
    pub(crate) key_ops: Vec<i32>,
    pub(crate) base_iv: Option<Vec<u8>>,
    pub(crate) enc: bool,
}
const KEY_OPS_SKEY: [i32; 8] = [
    keys::KEY_OPS_DERIVE_BITS,
    keys::KEY_OPS_DERIVE,
    keys::KEY_OPS_DECRYPT,
    keys::KEY_OPS_ENCRYPT,
    keys::KEY_OPS_WRAP,
    keys::KEY_OPS_UNWRAP,
    keys::KEY_OPS_MAC_VERIFY,
    keys::KEY_OPS_MAC,
];

const SIZE: usize = 3;

impl CoseAgent {
    /// Creates an empty CoseAgent structure.
    pub fn new() -> CoseAgent {
        CoseAgent {
            header: CoseHeader::new(),
            payload: Vec::new(),
            ph_bstr: Vec::new(),
            pub_key: Vec::new(),
            key_ops: Vec::new(),
            s_key: Vec::new(),
            crv: None,
            base_iv: None,
            context: String::new(),
            enc: false,
        }
    }

    /// Creates an empty CoseAgent structure for counter signatures.
    pub fn new_counter_sig() -> CoseAgent {
        CoseAgent {
            header: CoseHeader::new(),
            payload: Vec::new(),
            ph_bstr: Vec::new(),
            pub_key: Vec::new(),
            key_ops: Vec::new(),
            s_key: Vec::new(),
            crv: None,
            base_iv: None,
            context: cose_struct::COUNTER_SIGNATURE.to_string(),
            enc: false,
        }
    }

    /// Adds an [header](../headers/struct.CoseHeader.html).
    pub fn add_header(&mut self, header: CoseHeader) {
        self.header = header;
    }

    /// Adds a [cose-key](../keys/struct.CoseKey.html).
    pub fn key(&mut self, key: &keys::CoseKey) -> CoseResult {
        let alg = self.header.alg.ok_or(CoseError::Missing(CoseField::Alg))?;
        key.verify_kty()?;
        if algs::ECDH_ALGS.contains(&alg) {
            if !keys::ECDH_KTY.contains(key.kty.as_ref().ok_or(CoseError::Missing(CoseField::Kty))?)
            {
                return Err(CoseError::Invalid(CoseField::Kty));
            }
            if key.alg.is_some() && key.alg.unwrap() != alg {
                return Err(CoseError::AlgMismatch());
            }
        } else if (alg != algs::DIRECT
            && !algs::A_KW.contains(&alg)
            && !algs::RSA_OAEP.contains(&alg))
            && key.alg.is_some()
            && key.alg.unwrap() != alg
        {
            return Err(CoseError::AlgMismatch());
        }
        if algs::SIGNING_ALGS.contains(&alg) {
            if key.key_ops.contains(&keys::KEY_OPS_SIGN) {
                self.s_key = key.get_s_key()?;
            }
            if key.key_ops.contains(&keys::KEY_OPS_VERIFY) {
                self.pub_key = key.get_pub_key()?;
            }
            if key.key_ops.is_empty() {
                self.s_key = match key.get_s_key() {
                    Ok(v) => v,
                    Err(_) => Vec::new(),
                };
                self.pub_key = match key.get_pub_key() {
                    Ok(v) => v,
                    Err(_) => Vec::new(),
                };
            }
        } else if algs::KEY_DISTRIBUTION_ALGS.contains(&alg) || algs::ENCRYPT_ALGS.contains(&alg) {
            if KEY_OPS_SKEY.iter().any(|i| key.key_ops.contains(i)) {
                self.s_key = key.get_s_key()?;
            }
            if key.key_ops.is_empty() {
                self.s_key = match key.get_s_key() {
                    Ok(v) => v,
                    Err(_) => Vec::new(),
                };
            }
            if (algs::ECDH_ALGS.contains(&alg) || algs::OAEP_ALGS.contains(&alg))
                && key.key_ops.is_empty()
            {
                self.pub_key = key.get_pub_key()?;
            }
        }
        self.crv = key.crv;
        self.base_iv = key.base_iv.clone();
        self.key_ops = key.key_ops.clone();
        Ok(())
    }

    pub(crate) fn sign(
        &mut self,
        content: &Vec<u8>,
        external_aad: &Vec<u8>,
        body_protected: &Vec<u8>,
    ) -> CoseResult {
        if !self.key_ops.is_empty() && !self.key_ops.contains(&keys::KEY_OPS_SIGN) {
            return Err(CoseError::Invalid(CoseField::KeyOp));
        }
        self.ph_bstr = self.header.get_protected_bstr(false)?;
        self.payload = cose_struct::gen_sig(
            &self.s_key,
            &self.header.alg.ok_or(CoseError::Missing(CoseField::Alg))?,
            &self.crv,
            &external_aad,
            &self.context,
            &body_protected,
            &self.ph_bstr,
            &content,
        )?;
        Ok(())
    }
    pub(crate) fn verify(
        &self,
        content: &Vec<u8>,
        external_aad: &Vec<u8>,
        body_protected: &Vec<u8>,
    ) -> CoseResultWithRet<bool> {
        if !self.key_ops.is_empty() && !self.key_ops.contains(&keys::KEY_OPS_VERIFY) {
            return Err(CoseError::Invalid(CoseField::KeyOp));
        }
        Ok(cose_struct::verify_sig(
            &self.pub_key,
            &self.header.alg.ok_or(CoseError::Missing(CoseField::Alg))?,
            &self.crv,
            &external_aad,
            &self.context,
            &body_protected,
            &self.ph_bstr,
            &content,
            &self.payload,
        )?)
    }

    /// Adds the counter signature to the CoseAgent.
    ///
    /// Function to use when signature was produce externally to the module.
    /// This function is to use only in the context of counter signatures, not message
    /// recipients/signers.
    pub fn add_signature(&mut self, signature: Vec<u8>) -> CoseResult {
        if self.context != cose_struct::COUNTER_SIGNATURE {
            return Err(CoseError::InvalidContext(self.context.clone()));
        }
        self.payload = signature;
        Ok(())
    }

    pub(crate) fn get_sign_content(
        &mut self,
        content: &Vec<u8>,
        external_aad: &Vec<u8>,
        body_protected: &Vec<u8>,
    ) -> CoseResultWithRet<Vec<u8>> {
        if self.context != cose_struct::COUNTER_SIGNATURE {
            return Err(CoseError::InvalidContext(self.context.clone()));
        }
        self.ph_bstr = self.header.get_protected_bstr(false)?;
        cose_struct::get_to_sign(
            &external_aad,
            cose_struct::COUNTER_SIGNATURE,
            &body_protected,
            &self.ph_bstr,
            &content,
        )
    }

    /// Adds a counter signature to the signer/recipient.
    pub fn counter_sig(
        &self,
        external_aad: Option<Vec<u8>>,
        counter: &mut CoseAgent,
    ) -> CoseResult {
        if !self.enc {
            Err(CoseError::Missing(CoseField::Payload))
        } else {
            let aead = match external_aad {
                None => Vec::new(),
                Some(v) => v,
            };
            counter.sign(&self.payload, &aead, &self.ph_bstr)?;
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
        if !self.enc {
            Err(CoseError::Missing(CoseField::Payload))
        } else {
            let aead = match external_aad {
                None => Vec::new(),
                Some(v) => v,
            };
            counter.get_sign_content(&self.payload, &aead, &self.ph_bstr)
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
        if !self.enc {
            Err(CoseError::Missing(CoseField::Payload))
        } else {
            let aead = match external_aad {
                None => Vec::new(),
                Some(v) => v,
            };
            self.header.counters[*counter].get_sign_content(&self.payload, &aead, &self.ph_bstr)
        }
    }

    /// Function that verifies a given counter signature on the respective signer/recipient.
    pub fn counters_verify(&mut self, external_aad: Option<Vec<u8>>, counter: usize) -> CoseResult {
        if !self.enc {
            Err(CoseError::Missing(CoseField::Payload))
        } else {
            let aead = match external_aad {
                None => Vec::new(),
                Some(v) => v,
            };
            if self.header.counters[counter].verify(&self.payload, &aead, &self.ph_bstr)? {
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

    pub(crate) fn derive_key(
        &mut self,
        cek: &Vec<u8>,
        size: usize,
        sender: bool,
        true_alg: &i32,
    ) -> CoseResultWithRet<Vec<u8>> {
        if self.ph_bstr.is_empty() {
            self.ph_bstr = self.header.get_protected_bstr(false)?;
        }
        let alg = self
            .header
            .alg
            .as_ref()
            .ok_or(CoseError::Missing(CoseField::Alg))?;
        if algs::A_KW.contains(alg) {
            if sender {
                self.payload = algs::aes_key_wrap(&self.s_key, size, &cek)?;
            } else {
                return Ok(algs::aes_key_unwrap(&self.s_key, size, &cek)?);
            }
            return Ok(cek.to_vec());
        } else if algs::RSA_OAEP.contains(alg) {
            if sender {
                self.payload = algs::rsa_oaep_enc(&self.pub_key, &cek, alg)?;
            } else {
                return Ok(algs::rsa_oaep_dec(&self.s_key, size, &cek, alg)?);
            }
            return Ok(cek.to_vec());
        } else if algs::D_HA.contains(alg) || algs::D_HS.contains(alg) {
            let mut kdf_context = cose_struct::gen_kdf(
                true_alg,
                &self.header.party_u_identity,
                &self.header.party_u_nonce,
                &self.header.party_u_other,
                &self.header.party_v_identity,
                &self.header.party_v_nonce,
                &self.header.party_v_other,
                size as u16 * 8,
                &self.ph_bstr,
                &self.header.pub_other,
                &self.header.priv_info,
            )?;
            return Ok(algs::hkdf(
                size,
                &self.s_key,
                self.header.salt.as_ref(),
                &mut kdf_context,
                self.header.alg.unwrap(),
            )?);
        } else if algs::ECDH_H.contains(alg) || algs::ECDH_A.contains(alg) {
            let (receiver_key, sender_key, crv_rec, crv_send);
            if sender {
                if self.pub_key.is_empty() {
                    return Err(CoseError::MissingKey());
                }
                receiver_key = self.pub_key.clone();
                if !self.header.x5_private.is_empty() {
                    sender_key = self.header.x5_private.clone();
                    crv_send = None;
                } else {
                    sender_key = self.header.ecdh_key.get_s_key()?;
                    crv_send = Some(self.header.ecdh_key.crv.unwrap());
                }
                crv_rec = Some(self.crv.unwrap());
            } else {
                if self.s_key.is_empty() {
                    return Err(CoseError::MissingKey());
                }
                if self.header.x5chain_sender.is_some() {
                    algs::verify_chain(self.header.x5chain_sender.as_ref().unwrap())?;
                    receiver_key = self.header.x5chain_sender.as_ref().unwrap()[0].clone();
                    crv_rec = None;
                } else {
                    receiver_key = self.header.ecdh_key.get_pub_key()?;
                    crv_rec = Some(self.crv.unwrap());
                }
                sender_key = self.s_key.clone();
                crv_send = Some(self.crv.unwrap());
            }
            let shared = algs::ecdh_derive_key(crv_rec, crv_send, &receiver_key, &sender_key)?;

            if algs::ECDH_H.contains(alg) {
                let mut kdf_context = cose_struct::gen_kdf(
                    true_alg,
                    &self.header.party_u_identity,
                    &self.header.party_u_nonce,
                    &self.header.party_u_other,
                    &self.header.party_v_identity,
                    &self.header.party_v_nonce,
                    &self.header.party_v_other,
                    size as u16 * 8,
                    &self.ph_bstr,
                    &self.header.pub_other,
                    &self.header.priv_info,
                )?;
                return Ok(algs::hkdf(
                    size,
                    &shared,
                    self.header.salt.as_ref(),
                    &mut kdf_context,
                    self.header.alg.unwrap(),
                )?);
            } else {
                let size_akw = algs::get_cek_size(&alg)?;

                let alg_akw;
                if [algs::ECDH_ES_A128KW, algs::ECDH_SS_A128KW].contains(alg) {
                    alg_akw = algs::A128KW;
                } else if [algs::ECDH_ES_A192KW, algs::ECDH_SS_A192KW].contains(alg) {
                    alg_akw = algs::A192KW;
                } else {
                    alg_akw = algs::A256KW;
                }

                let mut kdf_context = cose_struct::gen_kdf(
                    &alg_akw,
                    &self.header.party_u_identity,
                    &self.header.party_u_nonce,
                    &self.header.party_u_other,
                    &self.header.party_v_identity,
                    &self.header.party_v_nonce,
                    &self.header.party_v_other,
                    size_akw as u16 * 8,
                    &self.ph_bstr,
                    &self.header.pub_other,
                    &self.header.priv_info,
                )?;
                let kek = algs::hkdf(
                    size_akw,
                    &shared,
                    self.header.salt.as_ref(),
                    &mut kdf_context,
                    self.header.alg.unwrap(),
                )?;
                if sender {
                    self.payload = algs::aes_key_wrap(&kek, size, &cek)?;
                } else {
                    return Ok(algs::aes_key_unwrap(&kek, size, &cek)?);
                }
                return Ok(cek.to_vec());
            }
        } else {
            return Err(CoseError::Invalid(CoseField::Alg));
        }
    }

    pub(crate) fn decode(&mut self, d: &mut Decoder<Cursor<Vec<u8>>>) -> CoseResult {
        if !self.ph_bstr.is_empty() {
            self.header.decode_protected_bstr(&self.ph_bstr)?;
        }
        self.header
            .decode_unprotected(d, self.context == cose_struct::COUNTER_SIGNATURE)?;
        self.payload = d.bytes()?;
        self.header.labels_found = Vec::new();
        Ok(())
    }

    pub(crate) fn encode(&mut self, e: &mut Encoder<Vec<u8>>) -> CoseResult {
        e.array(SIZE)?;
        e.bytes(&self.ph_bstr)?;
        self.header.encode_unprotected(e)?;
        e.bytes(&self.payload)?;
        self.header.labels_found = Vec::new();
        Ok(())
    }
}
