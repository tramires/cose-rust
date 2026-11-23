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
use crate::common::allows;
use crate::cose_struct;
use crate::errors::{CoseError, CoseField, CoseResult, CoseResultWithRet};
use crate::headers::CoseHeader;
use crate::keys;
use cbor::{Decoder, Encoder};
use std::io::Cursor;

fn load_key(
    into: &mut Vec<u8>,
    checked: bool,
    is_empty: bool,
    get: impl FnOnce() -> CoseResultWithRet<Vec<u8>>,
) -> CoseResult {
    if checked {
        *into = get()?;
    } else if is_empty {
        *into = get().unwrap_or_default();
    }
    Ok(())
}

/// COSE recipient, signer or counter-signature structure.
#[derive(Clone, Default)]
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
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates an empty CoseAgent structure for counter signatures.
    pub fn new_counter_sig() -> Self {
        CoseAgent {
            context: cose_struct::COUNTER_SIGNATURE.to_string(),
            ..Self::default()
        }
    }

    /// Adds an [header](../headers/struct.CoseHeader.html).
    pub fn add_header(&mut self, header: CoseHeader) {
        self.header = header;
    }

    /// Adds a [cose-key](../keys/struct.CoseKey.html).
    pub fn key(&mut self, key: &keys::CoseKey) -> CoseResult {
        let alg = self.header.get_alg()?;
        key.verify_kty()?;
        if algs::ECDH_ALGS.contains(&alg)
            && !keys::ECDH_KTY.contains(key.kty.as_ref().ok_or(CoseError::Missing(CoseField::Kty))?)
        {
            return Err(CoseError::Invalid(CoseField::Kty));
        }
        if alg != algs::DIRECT
            && !algs::A_KW.contains(&alg)
            && !algs::RSA_OAEP.contains(&alg)
            && key.alg.is_some_and(|key_alg| key_alg != alg)
        {
            return Err(CoseError::AlgMismatch);
        }
        let is_empty = key.key_ops.is_empty();
        let check = |ko: &i32| key.key_ops.contains(ko);
        if algs::SIGNING_ALGS.contains(&alg) {
            load_key(
                &mut self.s_key,
                check(&keys::KEY_OPS_SIGN),
                is_empty,
                || key.get_s_key(),
            )?;
            load_key(
                &mut self.pub_key,
                check(&keys::KEY_OPS_VERIFY),
                is_empty,
                || key.get_pub_key(),
            )?;
        } else if algs::KEY_DISTRIBUTION_ALGS.contains(&alg) || algs::ENCRYPT_ALGS.contains(&alg) {
            load_key(
                &mut self.s_key,
                KEY_OPS_SKEY.iter().any(check),
                is_empty,
                || key.get_s_key(),
            )?;
            if is_empty && (algs::ECDH_ALGS.contains(&alg) || algs::OAEP_ALGS.contains(&alg)) {
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
        if !allows(&self.key_ops, keys::KEY_OPS_SIGN) {
            return Err(CoseError::Invalid(CoseField::KeyOp));
        }
        self.ph_bstr = self.header.get_protected_bstr(false)?;
        let to_sign = cose_struct::sign_structure(
            &self.context,
            &body_protected,
            &self.ph_bstr,
            &external_aad,
            &content,
        )?;
        self.payload = algs::sign(self.header.get_alg()?, self.crv, &self.s_key, &to_sign)?;
        Ok(())
    }
    pub(crate) fn verify(
        &self,
        content: &Vec<u8>,
        external_aad: &Vec<u8>,
        body_protected: &Vec<u8>,
    ) -> CoseResultWithRet<bool> {
        if !allows(&self.key_ops, keys::KEY_OPS_VERIFY) {
            return Err(CoseError::Invalid(CoseField::KeyOp));
        }
        let to_ver = cose_struct::sign_structure(
            &self.context,
            &body_protected,
            &self.ph_bstr,
            &external_aad,
            &content,
        )?;
        algs::verify(
            self.header.get_alg()?,
            self.crv,
            &self.pub_key,
            &to_ver,
            &self.payload,
        )
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
        cose_struct::sign_structure(
            cose_struct::COUNTER_SIGNATURE,
            &body_protected,
            &self.ph_bstr,
            &external_aad,
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
            return Err(CoseError::NotSecured);
        }
        let aad = external_aad.unwrap_or_default();
        counter.sign(&self.payload, &aad, &self.ph_bstr)
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
            return Err(CoseError::NotSecured);
        }
        let aad = external_aad.unwrap_or_default();
        counter.get_sign_content(&self.payload, &aad, &self.ph_bstr)
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
            return Err(CoseError::NotSecured);
        }
        let aad = external_aad.unwrap_or_default();
        self.header.counters[*counter].get_sign_content(&self.payload, &aad, &self.ph_bstr)
    }

    /// Function that verifies a given counter signature on the respective signer/recipient.
    pub fn counters_verify(&mut self, external_aad: Option<Vec<u8>>, counter: usize) -> CoseResult {
        if !self.enc {
            return Err(CoseError::NotSecured);
        }
        let aad = external_aad.unwrap_or_default();
        if !self.header.counters[counter].verify(&self.payload, &aad, &self.ph_bstr)? {
            return Err(CoseError::Invalid(CoseField::CounterSignature));
        }
        Ok(())
    }

    /// Function that adds a counter signature which was signed externally with the use of
    /// [get_to_sign](#method.get_to_sign)
    pub fn add_counter_sig(&mut self, counter: CoseAgent) -> CoseResult {
        self.header.add_counter(counter)
    }

    fn kdf(&self, sk: &Vec<u8>, size: usize, alg: &i32) -> CoseResultWithRet<Vec<u8>> {
        let mut context =
            cose_struct::kdf_structure(alg, &self.header, size as u16 * 8, &self.ph_bstr)?;
        algs::hkdf(
            size,
            sk,
            self.header.salt.as_ref(),
            &mut context,
            self.header.get_alg()?,
        )
    }

    fn ecdh(&self, sender: bool) -> CoseResultWithRet<Vec<u8>> {
        let crv = self.crv.ok_or(CoseError::Missing(CoseField::Crv))?;
        let (public, private, crv_pub, crv_priv) = if sender {
            if self.pub_key.is_empty() {
                return Err(CoseError::MissingKey);
            }
            let (private, crv_priv) = if self.header.x5_private.is_empty() {
                let ecdh_crv = self
                    .header
                    .ecdh_key
                    .crv
                    .ok_or(CoseError::Missing(CoseField::Crv))?;
                (self.header.ecdh_key.get_s_key()?, Some(ecdh_crv))
            } else {
                (self.header.x5_private.clone(), None)
            };
            (self.pub_key.clone(), private, Some(crv), crv_priv)
        } else {
            if self.s_key.is_empty() {
                return Err(CoseError::MissingKey);
            }
            let (public, crv_public) = match &self.header.x5chain_sender {
                Some(chain) => {
                    algs::verify_chain(chain)?;
                    let cert = chain
                        .first()
                        .ok_or(CoseError::Missing(CoseField::X5ChainSender))?;
                    (cert.clone(), None)
                }
                None => (self.header.ecdh_key.get_pub_key()?, Some(crv)),
            };
            (public, self.s_key.clone(), crv_public, Some(crv))
        };
        algs::ecdh_derive_key(crv_pub, crv_priv, &public, &private)
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
        let alg = self.header.get_alg()?;
        if algs::A_KW.contains(&alg) {
            if !sender {
                return Ok(algs::aes_key_unwrap(&self.s_key, size, &cek)?);
            }
            self.payload = algs::aes_key_wrap(&self.s_key, size, &cek)?;
            return Ok(cek.clone());
        } else if algs::RSA_OAEP.contains(&alg) {
            if !sender {
                return algs::rsa_oaep_dec(&self.s_key, size, &cek, &alg);
            }
            self.payload = algs::rsa_oaep_enc(&self.pub_key, &cek, &alg)?;
            return Ok(cek.clone());
        } else if algs::D_HA.contains(&alg) || algs::D_HS.contains(&alg) {
            return self.kdf(&self.s_key, size, true_alg);
        } else if algs::ECDH_H.contains(&alg) || algs::ECDH_A.contains(&alg) {
            let shared = self.ecdh(sender)?;
            if algs::ECDH_H.contains(&alg) {
                return self.kdf(&shared, size, true_alg);
            } else {
                let alg_akw = match alg {
                    algs::ECDH_ES_A128KW | algs::ECDH_SS_A128KW => algs::A128KW,
                    algs::ECDH_ES_A192KW | algs::ECDH_SS_A192KW => algs::A192KW,
                    algs::ECDH_ES_A256KW | algs::ECDH_SS_A256KW => algs::A256KW,
                    _ => return Err(CoseError::Invalid(CoseField::Alg)),
                };

                let kek = self.kdf(&shared, algs::get_cek_size(&alg)?, &alg_akw)?;
                if !sender {
                    return algs::aes_key_unwrap(&kek, size, &cek);
                }
                self.payload = algs::aes_key_wrap(&kek, size, &cek)?;
                return Ok(cek.clone());
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
        self.header.labels_found.clear();
        Ok(())
    }

    pub(crate) fn encode(&mut self, e: &mut Encoder<Vec<u8>>) -> CoseResult {
        e.array(SIZE)?;
        e.bytes(&self.ph_bstr)?;
        self.header.encode_unprotected(e)?;
        e.bytes(&self.payload)?;
        self.header.labels_found.clear();
        Ok(())
    }
}
