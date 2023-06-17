//! Module to encode/decode cose-sign and cose-sign1 messages.
//!
//! # Examples
//!
//! ## cose-sign1
//!
//! cose-sign1 message with ECDSA w/ SHA-256  algorithm
//!
//! ### Encode cose-sign1 message
//! ```
//! use cose::sign::CoseSign;
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
//!     let mut sign1 = CoseSign::new();
//!     sign1.header.alg(algs::ES256, true, false);
//!     sign1.header.kid(kid, true, false);
//!     sign1.payload(msg);
//!     sign1.key(&key).unwrap();
//!
//!     // Generate the Signature
//!     sign1.gen_signature(None).unwrap();
//!
//!     // Encode the message with the payload
//!     sign1.encode(true).unwrap();
//! }
//! ```
//!
//! ### Decode cose-sign1 message
//! ```
//! use cose::sign::CoseSign;
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
//!     let mut verify = CoseSign::new();
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
//! use cose::sign::CoseSign;
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
//!     let mut sign = CoseSign::new();
//!     sign.payload(msg);
//!
//!     // Add signer 1
//!     let mut signer1 = CoseAgent::new();
//!     signer1.header.alg(algs::ES256, true, false);
//!     signer1.header.kid(s1_kid.clone(), false, false);
//!     signer1.key(&s1_key).unwrap();
//!     sign.add_signer(&mut signer1).unwrap();
//!
//!     // Add signer 2
//!     let mut signer2 = CoseAgent::new();
//!     signer2.header.alg(algs::EDDSA, true, false);
//!     signer2.header.kid(s2_kid.clone(), false, false);
//!     signer2.key(&s2_key).unwrap();
//!     sign.add_signer(&mut signer2).unwrap();
//!
//!     // Generate signature without AAD
//!     sign.gen_signature(None).unwrap();
//!
//!     // Encode the cose-sign message
//!     sign.encode(true).unwrap();
//!
//! }
//! ```
//!
//! ### Decode cose-sign message
//! ```
//! use cose::sign::CoseSign;
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
//!     let mut verify = CoseSign::new();
//!     verify.bytes =
//!     hex::decode("d8628440a054546869732069732074686520636f6e74656e742e828343a10126a1044231315840a45d63392d72cfef8bd08ec6a17e40364f8b3094558f1f8078c497718de536dceadfb4a637804b31e21572ba3714e03b0b5510e243b0240c252da3a827ba4e998343a10127a104423232584081d92439ecaf31f11f611054346d50b5fbd4e5cfe00c1c237cf673fa3948678b378eacd5eecf6f680980f818a8ecc57a8b4c733ec2fd8d03ae3ba04a02ea4a06").unwrap();
//!     verify.init_decoder(None).unwrap();
//!
//!     // Get signer 1 and verify
//!     let mut index1 = verify.get_signer(&s1_kid).unwrap()[0];
//!     verify.signers[index1].key(&s1_key).unwrap();
//!     verify.decode(None, Some(index1)).unwrap();
//!
//!     // Get signer 2 and verify
//!     let mut index2 = verify.get_signer(&s2_kid).unwrap()[0];
//!     verify.signers[index2].key(&s2_key).unwrap();
//!     verify.decode(None, Some(index2)).unwrap();
//! }
//! ```

use crate::agent::CoseAgent;
use crate::algs;
use crate::common;
use crate::errors::{CoseError, CoseResult, CoseResultWithRet};
use crate::headers;
use crate::keys;
use crate::sig_struct;
use cbor::{decoder::DecodeError, types::Tag, types::Type, Config, Decoder, Encoder};
use std::io::Cursor;

const SIZE: usize = 4;
const SIG_TAGS: [Tag; 2] = [
    Tag::Unassigned(common::SIG1_TAG),
    Tag::Unassigned(common::SIG_TAG),
];

/// Structure to encode/decode cose-sign and cose-sign1 messages
pub struct CoseSign {
    /// The header parameters of the message.
    pub header: headers::CoseHeader,
    /// The payload of the message.
    pub payload: Vec<u8>,
    signature: Vec<u8>,
    /// The COSE encoded message.
    pub bytes: Vec<u8>,
    ph_bstr: Vec<u8>,
    pub_key: Vec<u8>,
    priv_key: Vec<u8>,
    sign: bool,
    verify: bool,
    /// The signers of the message, empty if cose-sign1 message type.
    pub signers: Vec<CoseAgent>,
}

impl CoseSign {
    /// Creates a new empty COSE signature message structure.
    pub fn new() -> CoseSign {
        CoseSign {
            bytes: Vec::new(),
            header: headers::CoseHeader::new(),
            payload: Vec::new(),
            signature: Vec::new(),
            ph_bstr: Vec::new(),
            pub_key: Vec::new(),
            priv_key: Vec::new(),
            sign: false,
            verify: false,
            signers: Vec::new(),
        }
    }

    /// Add an [header](../headers/struct.CoseHeader.html) to the message.
    pub fn add_header(&mut self, header: headers::CoseHeader) {
        self.header = header;
    }

    /// Add the payload to the message.
    pub fn payload(&mut self, payload: Vec<u8>) {
        self.payload = payload;
    }

    /// Adds a signer ([agent](../agent/struct.CoseAgent.html)) to the message.
    ///
    /// Used for cose-sign messages.
    pub fn add_signer(&mut self, signer: &mut CoseAgent) -> CoseResult {
        signer.context = sig_struct::SIGNATURE.to_string();
        if !algs::SIGNING_ALGS.contains(&signer.header.alg.ok_or(CoseError::MissingAlg())?) {
            return Err(CoseError::InvalidAlg());
        }
        if !signer.key_ops.contains(&keys::KEY_OPS_SIGN) {
            return Err(CoseError::KeyOpNotSupported());
        }
        self.signers.push(signer.clone());
        Ok(())
    }

    /// Returns a signer ([agent](../agent/struct.CoseAgent.html)) of the message with a given Key ID.
    pub fn get_signer(&self, kid: &Vec<u8>) -> CoseResultWithRet<Vec<usize>> {
        let mut keys: Vec<usize> = Vec::new();
        for i in 0..self.signers.len() {
            if self.signers[i]
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
    /// This option is only available for the cose-sign1 message type, since when using cose-sign
    /// message type, the keys are respective to each signer.
    pub fn key(&mut self, cose_key: &keys::CoseKey) -> CoseResult {
        if self.signers.len() > 0 {
            return Err(CoseError::InvalidMethodForContext());
        }
        cose_key.verify_kty()?;
        if cose_key.alg.ok_or(CoseError::MissingAlg())?
            != self.header.alg.ok_or(CoseError::MissingAlg())?
        {
            return Err(CoseError::AlgsDontMatch());
        }
        if cose_key.key_ops.contains(&keys::KEY_OPS_SIGN) {
            let priv_key = cose_key.get_s_key()?;
            if priv_key.len() > 0 {
                self.sign = true;
                self.priv_key = priv_key;
            }
        }
        if cose_key.key_ops.contains(&keys::KEY_OPS_VERIFY) {
            let pub_key = cose_key.get_pub_key(self.header.alg.ok_or(CoseError::MissingAlg())?)?;
            if pub_key.len() > 0 {
                self.verify = true;
                self.pub_key = pub_key;
            }
        }
        if !self.sign && !self.verify {
            return Err(CoseError::KeyOpNotSupported());
        }
        Ok(())
    }

    /// Adds a counter signature to the message.
    ///
    /// The counter signature structure is the same type as the
    /// [signers](../agent/struct.CoseAgent.html) structure and it should be used the
    /// function [new_counter_sig](../agent/struct.CoseAgent.html#method.new_counter_sig) to initiate the structure.
    pub fn counter_sig(
        &self,
        external_aad: Option<Vec<u8>>,
        counter: &mut CoseAgent,
    ) -> CoseResult {
        if self.signature.len() == 0 {
            Err(CoseError::MissingSignature())
        } else {
            let aead = match external_aad {
                None => Vec::new(),
                Some(v) => v,
            };
            counter.sign(&self.signature, &aead, &self.ph_bstr)?;
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
        if self.signature.len() == 0 {
            Err(CoseError::MissingSignature())
        } else {
            let aead = match external_aad {
                None => Vec::new(),
                Some(v) => v,
            };
            counter.get_to_sign(&self.signature, &aead, &self.ph_bstr)
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
        if self.signature.len() == 0 {
            Err(CoseError::MissingSignature())
        } else {
            let aead = match external_aad {
                None => Vec::new(),
                Some(v) => v,
            };
            self.header.counters[*counter].get_to_sign(&self.signature, &aead, &self.ph_bstr)
        }
    }

    /// Function that verifies a given counter signature on the COSE message.
    pub fn counters_verify(&mut self, external_aad: Option<Vec<u8>>, counter: usize) -> CoseResult {
        let signature;
        if self.signers.len() > 0 {
            signature = &self.payload;
        } else {
            signature = &self.signature;
        }
        if signature.len() == 0 {
            Err(CoseError::MissingSignature())
        } else {
            let aead = match external_aad {
                None => Vec::new(),
                Some(v) => v,
            };
            if self.header.counters[counter].verify(signature, &aead, &self.ph_bstr)? {
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
        if counter.context != sig_struct::COUNTER_SIGNATURE {
            return Err(CoseError::InvalidContext());
        }
        if self.header.unprotected.contains(&headers::COUNTER_SIG) {
            self.header.counters.push(counter);
            Ok(())
        } else {
            self.header.counters.push(counter);
            self.header.remove_label(headers::COUNTER_SIG);
            self.header.unprotected.push(headers::COUNTER_SIG);
            Ok(())
        }
    }

    /// Function to sign the payload of the message for both types (cose-sign1 and cose-ign).
    ///
    /// `external_aad` parameter is used when it is desired to have an additional authentication
    /// data to reinforce security of the signature.
    pub fn gen_signature(&mut self, external_aad: Option<Vec<u8>>) -> CoseResult {
        if self.payload.len() <= 0 {
            return Err(CoseError::MissingPayload());
        }
        self.ph_bstr = self.header.get_protected_bstr(true)?;
        let aead = match external_aad {
            None => Vec::new(),
            Some(v) => v,
        };
        if self.signers.len() <= 0 {
            if !algs::SIGNING_ALGS.contains(&self.header.alg.ok_or(CoseError::MissingAlg())?) {
                Err(CoseError::InvalidAlg())
            } else if !self.sign {
                Err(CoseError::KeyOpNotSupported())
            } else {
                self.signature = sig_struct::gen_sig(
                    &self.priv_key,
                    &self.header.alg.unwrap(),
                    &aead,
                    sig_struct::SIGNATURE1,
                    &self.ph_bstr,
                    &Vec::new(),
                    &self.payload,
                )?;
                Ok(())
            }
        } else {
            for i in 0..self.signers.len() {
                if !algs::SIGNING_ALGS
                    .contains(&self.signers[i].header.alg.ok_or(CoseError::MissingAlg())?)
                {
                    return Err(CoseError::InvalidAlg());
                } else if !self.signers[i].key_ops.contains(&keys::KEY_OPS_SIGN) {
                    return Err(CoseError::KeyOpNotSupported());
                } else {
                    self.signers[i].sign(&self.payload, &aead, &self.ph_bstr)?;
                }
            }
            Ok(())
        }
    }

    /// Function to encode the COSE message after the signature is generated with
    /// [gen_signature](#method.gen_signature).
    ///
    /// The `payload` parameter is used to specified if the payload shall be present or not in
    /// the message.
    pub fn encode(&mut self, payload: bool) -> CoseResult {
        if self.signers.len() <= 0 {
            if self.signature.len() <= 0 {
                Err(CoseError::MissingSignature())
            } else {
                let mut e = Encoder::new(Vec::new());
                e.tag(Tag::Unassigned(common::SIG1_TAG))?;
                e.array(SIZE)?;
                e.bytes(self.ph_bstr.as_slice())?;
                self.header.encode_unprotected(&mut e)?;
                if payload {
                    e.bytes(self.payload.as_slice())?;
                } else {
                    e.null()?;
                }
                e.bytes(self.signature.as_slice())?;
                self.bytes = e.into_writer().to_vec();
                self.header.labels_found = Vec::new();
                Ok(())
            }
        } else {
            let mut e = Encoder::new(Vec::new());
            e.tag(Tag::Unassigned(common::SIG_TAG))?;
            e.array(SIZE)?;
            e.bytes(self.ph_bstr.as_slice())?;
            self.header.encode_unprotected(&mut e)?;
            if payload {
                e.bytes(self.payload.as_slice())?;
            } else {
                e.null()?;
            }
            let r_len = self.signers.len();
            e.array(r_len)?;
            for i in 0..r_len {
                self.signers[i].encode(&mut e)?;
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
    pub fn init_decoder(&mut self, payload: Option<Vec<u8>>) -> CoseResult {
        let input = Cursor::new(self.bytes.clone());
        let mut d = Decoder::new(Config::default(), input);
        let mut tag: Option<Tag> = None;

        match d.tag() {
            Ok(v) => {
                if !SIG_TAGS.contains(&v) {
                    return Err(CoseError::InvalidTag());
                } else {
                    tag = Some(v);
                    d.array()?;
                }
            }
            Err(ref err) => match err {
                DecodeError::UnexpectedType { datatype, info } => {
                    if *datatype != Type::Array && *info != SIZE as u8 {
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

        self.payload = match payload {
            None => d.bytes()?.to_vec(),
            Some(v) => {
                d.skip()?;
                v
            }
        };
        if self.payload.len() <= 0 {
            return Err(CoseError::MissingPayload());
        }

        let type_info = d.kernel().typeinfo()?;

        if type_info.0 == Type::Array
            && (tag == None || tag.unwrap() == Tag::Unassigned(common::SIG_TAG))
        {
            let r_len = type_info.1;
            let mut signer: CoseAgent;
            for _ in 0..r_len {
                signer = CoseAgent::new();
                signer.context = sig_struct::SIGNATURE.to_string();
                d.array()?;
                signer.ph_bstr = common::ph_bstr(d.bytes())?;
                signer.decode(&mut d)?;
                self.signers.push(signer);
            }
        } else if type_info.0 == Type::Bytes
            && (tag == None || tag.unwrap() == cbor::types::Tag::Unassigned(common::SIG1_TAG))
        {
            self.signature = d.kernel().raw_data(type_info.1, 0x500000)?;
            if self.signature.len() <= 0 {
                return Err(CoseError::MissingSignature());
            }
        }
        Ok(())
    }

    /// Function to verify the signature of the message.
    ///
    /// `external_add` is used in case of an AAD is included.
    ///
    /// `signer` parameter must be `None` if the type of the message is cose-sign1 and in case of
    /// being a cose-sign message, a signer of the message must be given with the respective key information.
    pub fn decode(&mut self, external_aad: Option<Vec<u8>>, signer: Option<usize>) -> CoseResult {
        let aead = match external_aad {
            None => Vec::new(),
            Some(v) => v,
        };
        if self.signers.len() <= 0 {
            if !self.verify {
                return Err(CoseError::KeyOpNotSupported());
            } else {
                if !sig_struct::verify_sig(
                    &self.pub_key,
                    &self.header.alg.ok_or(CoseError::MissingAlg())?,
                    &aead,
                    sig_struct::SIGNATURE1,
                    &self.ph_bstr,
                    &Vec::new(),
                    &self.payload,
                    &self.signature,
                )? {
                    return Err(CoseError::InvalidSignature());
                }
            }
        } else if signer != None {
            let index = signer.ok_or(CoseError::MissingSigner())?;
            if self.signers[index].pub_key.len() <= 0
                && !self.signers[index].key_ops.contains(&keys::KEY_OPS_VERIFY)
            {
                return Err(CoseError::KeyOpNotSupported());
            } else {
                if !self.signers[index].verify(&self.payload, &aead, &self.ph_bstr)? {
                    return Err(CoseError::InvalidSignature());
                }
            }
        } else {
            return Err(CoseError::MissingSigner());
        }
        Ok(())
    }
}
