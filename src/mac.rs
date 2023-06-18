//! Module to encode/decode cose-mac and cose-mac0 messages.
//!
//! # Examples
//!
//! The following examples demonstrate how to encode/decode a simple cose-mac0 message and a
//! cose-mac with 2 recipients, one using [A128KW](../algs/constant.A128KW.html) as the key agreement and the other using the [ECDH-ES +
//! A128KW](../algs/constant.ECDH_ES_A128KW.html) key agreement.
//!
//! ## cose-mac0
//!
//! Encode and decode cose-mac0 message with AES-MAC algorithm
//!
//! ### Encode cose-mac0 message
//! ```
//! use cose::mac::CoseMAC;
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
//!     let mut mac0 = CoseMAC::new();
//!     mac0.header.alg(algs::AES_MAC_256_128, true, false);
//!
//!     // Add the payload
//!     mac0.payload(msg);
//!      
//!     // Add cose-key
//!     mac0.key(&key).unwrap();
//!
//!     // Generate MAC tag without AAD
//!     mac0.gen_tag(None).unwrap();
//!     // Encode the cose-mac0 message with the payload included
//!     mac0.encode(true).unwrap();
//!
//! }
//! ```
//!
//! ### Decode cose-mac0 message
//! ```
//! use cose::mac::CoseMAC;
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
//!     let mut verify = CoseMAC::new();
//!     verify.bytes =
//!     hex::decode("d18444a101181aa054546869732069732074686520636f6e74656e742e50403152cc208c1d501e1dc2a789ae49e4").unwrap();
//!
//!     // Initial decoding of the message
//!     verify.init_decoder().unwrap();
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
//! use cose::mac::CoseMAC;
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
//!     r2_key.alg(algs::ES256);
//!     r2_key.crv(keys::P_256);
//!     r2_key.x(hex::decode("98F50A4FF6C05861C8860D13A638EA56C3F5AD7590BBFBF054E1C7B4D91D6280").unwrap());
//!
//!     // Prepare recipient 2 sender ephemeral key
//!     let mut r2_eph_key = keys::CoseKey::new();
//!     r2_eph_key.kty(keys::EC2);
//!     r2_eph_key.alg(algs::ES256);
//!     r2_eph_key.crv(keys::P_256);
//!     r2_eph_key.x(hex::decode("bac5b11cad8f99f9c72b05cf4b9e26d244dc189f745228255a219a86d6a09eff").unwrap());
//!     r2_eph_key.d(hex::decode("57c92077664146e876760c9520d054aa93c3afb04e306705db6090308507b4d3").unwrap());
//!     r2_eph_key.key_ops(vec![keys::KEY_OPS_DERIVE]);
//!
//!     // Prepare CoseMAC message
//!     let mut mac = CoseMAC::new();
//!     mac.header.alg(algs::AES_MAC_256_128, true, false);
//!     mac.payload(msg);
//!
//!     // Add recipient 1 (A128KW)
//!     let mut recipient1 = CoseAgent::new();
//!     recipient1.header.alg(algs::A128KW, true, false);
//!     recipient1.header.kid(r1_kid.clone(), false, false);
//!     recipient1.key(&r1_key).unwrap();
//!     mac.add_recipient(&mut recipient1).unwrap();
//!
//!     // Add recipient 2 (ECDH_ES_A128KW)
//!     let mut recipient2 = CoseAgent::new();
//!     recipient2.header.alg(algs::ECDH_ES_A128KW, true, false);
//!     recipient2.header.kid(r2_kid.clone(), false, false);
//!     recipient2.header.salt(vec![0; 32], false, false);
//!     recipient2.key(&r2_key).unwrap();
//!     recipient2.header.ephemeral_key(r2_eph_key.clone(), true, false);
//!     mac.add_recipient(&mut recipient2).unwrap();
//!
//!     // Generate tag without AAD
//!     mac.gen_tag(None).unwrap();
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
//! use cose::mac::CoseMAC;
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
//!     r2_key.alg(algs::ES256);
//!     r2_key.crv(keys::P_256);
//!     r2_key.d(hex::decode("02D1F7E6F26C43D4868D87CEB2353161740AACF1F7163647984B522A848DF1C3").unwrap());
//!     r2_key.key_ops(vec![keys::KEY_OPS_DERIVE]);
//!
//!     // Generate CoseMAC struct with the cose-mac message to decode
//!     let mut verifier = CoseMAC::new();
//!     verifier.bytes =
//!     hex::decode("d8618544a101181aa054546869732069732074686520636f6e74656e742e5064f33e4802d33bceec3fba4333ec5bf3828343a10122a10442313158281d77d288a153ab460c7c5c05e417b91becd26e9b73d2a0733c3b801db4885e51a635a2759801801b835832a201381c20a5010203262001215820bac5b11cad8f99f9c72b05cf4b9e26d244dc189f745228255a219a86d6a09eff048107a20442323233582000000000000000000000000000000000000000000000000000000000000000005828e53a16090a9caf558a6a2d2709cf195ee28ea55ae92c8e0ddddac26fbee3eb76e494ecd7cfbf49c8").unwrap();
//!     verifier.init_decoder().unwrap();
//!
//!     // Get recipient 1 and decode message
//!     let mut index1 = verifier.get_recipient(&r1_kid).unwrap()[0];
//!     verifier.recipients[index1].key(&r1_key).unwrap();
//!     verifier.decode(None, Some(index1)).unwrap();
//!
//!     // Get recipient 2 and decode message
//!     let mut index2 = verifier.get_recipient(&r2_kid).unwrap()[0];
//!     verifier.recipients[index2].key(&r2_key).unwrap();
//!     verifier.decode(None, Some(index2)).unwrap();
//! }
//! ```

use crate::agent::CoseAgent;
use crate::algs;
use crate::common;
use crate::enc_struct;
use crate::errors::{CoseError, CoseResult, CoseResultWithRet};
use crate::headers;
use crate::keys;
use crate::mac_struct;
use crate::sig_struct;
use cbor::{decoder::DecodeError, types::Tag, types::Type, Config, Decoder, Encoder};
use std::io::Cursor;

const SIZE: usize = 4;
const SIZE_N: usize = 5;
const MAC_TAGS: [Tag; 2] = [
    Tag::Unassigned(common::MAC0_TAG),
    Tag::Unassigned(common::MAC_TAG),
];

/// Structure to encode/decode cose-mac and cose-mac0 messages
pub struct CoseMAC {
    /// The header parameters of the message.
    pub header: headers::CoseHeader,
    tag: Vec<u8>,
    /// The payload of the message.
    pub payload: Vec<u8>,
    /// The COSE encoded message.
    pub bytes: Vec<u8>,
    ph_bstr: Vec<u8>,
    key: Vec<u8>,
    sign: bool,
    verify: bool,
    /// The recipients of the message, empty if cose-mac0 message type.
    pub recipients: Vec<CoseAgent>,
}

impl CoseMAC {
    /// Creates a new empty COSE MAC message structure.
    pub fn new() -> CoseMAC {
        CoseMAC {
            bytes: Vec::new(),
            header: headers::CoseHeader::new(),
            tag: Vec::new(),
            payload: Vec::new(),
            ph_bstr: Vec::new(),
            key: Vec::new(),
            sign: false,
            verify: false,
            recipients: Vec::new(),
        }
    }

    /// Adds an [header](../headers/struct.CoseHeader.html) to the message.
    pub fn add_header(&mut self, header: headers::CoseHeader) {
        self.header = header;
    }

    /// Adds the payload to the message.
    pub fn payload(&mut self, payload: Vec<u8>) {
        self.payload = payload;
    }

    /// Adds a [recipient](../agent/struct.CoseAgent.html) to the message.
    ///
    /// Used for cose-mac messages.
    pub fn add_recipient(&mut self, recipient: &mut CoseAgent) -> CoseResult {
        recipient.context = enc_struct::MAC_RECIPIENT.to_string();
        self.recipients.push(recipient.clone());
        Ok(())
    }

    /// Returns a [recipient](../agent/struct.CoseAgent.html) of the message with a given Key ID.
    pub fn get_recipient(&self, kid: &Vec<u8>) -> CoseResultWithRet<Vec<usize>> {
        let mut keys: Vec<usize> = Vec::new();
        for i in 0..self.recipients.len() {
            if self.recipients[i]
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

    /// Adds a counter signature to the message.
    ///
    /// The counter signature structure is the same as the
    /// [recipients](../agent/struct.CoseAgent.html) and it should be used the
    /// function [new_counter_sig](../agent/struct.CoseAgent.html#method.new_counter_sig) to initiate the structure.
    pub fn counter_sig(
        &self,
        external_aad: Option<Vec<u8>>,
        counter: &mut CoseAgent,
    ) -> CoseResult {
        if self.tag.len() == 0 {
            Err(CoseError::MissingTag())
        } else {
            let aead = match external_aad {
                None => Vec::new(),
                Some(v) => v,
            };
            counter.sign(&self.tag, &aead, &self.ph_bstr)?;
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
        if self.tag.len() == 0 {
            Err(CoseError::MissingTag())
        } else {
            let aead = match external_aad {
                None => Vec::new(),
                Some(v) => v,
            };
            counter.get_to_sign(&self.tag, &aead, &self.ph_bstr)
        }
    }

    /// Function to get the content to sign by the counter signature.
    ///
    /// This function is meant to be called if the counter signature process needs to be external
    /// to this crate, like a timestamp authority.
    pub fn get_to_verify(
        &mut self,
        external_aad: Option<Vec<u8>>,
        counter: &usize,
    ) -> CoseResultWithRet<Vec<u8>> {
        if self.tag.len() == 0 {
            Err(CoseError::MissingTag())
        } else {
            let aead = match external_aad {
                None => Vec::new(),
                Some(v) => v,
            };
            self.header.counters[*counter].get_to_sign(&self.tag, &aead, &self.ph_bstr)
        }
    }

    /// Function that verifies a given counter signature on the COSE message.
    pub fn counters_verify(&self, external_aad: Option<Vec<u8>>, counter: usize) -> CoseResult {
        if self.tag.len() == 0 {
            Err(CoseError::MissingTag())
        } else {
            let aead = match external_aad {
                None => Vec::new(),
                Some(v) => v,
            };
            if self.header.counters[counter].verify(&self.tag, &aead, &self.ph_bstr)? {
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

    /// Adds a [cose-key](../keys/struct.CoseKey.html) to the message.
    ///
    /// This option is only available for the cose-mac0 message type, since when using cose-mac
    /// message type, the keys are respective to each recipient.
    pub fn key(&mut self, cose_key: &keys::CoseKey) -> CoseResult {
        if self.recipients.len() > 0 {
            return Err(CoseError::InvalidMethodForContext());
        }
        cose_key.verify_kty()?;
        if cose_key.alg.ok_or(CoseError::MissingAlg())?
            != self.header.alg.ok_or(CoseError::MissingAlg())?
        {
            return Err(CoseError::AlgsDontMatch());
        }
        let key = cose_key.get_s_key()?;
        if key.len() > 0 {
            if cose_key.key_ops.contains(&keys::KEY_OPS_MAC) {
                self.sign = true;
            }
            if cose_key.key_ops.contains(&keys::KEY_OPS_MAC_VERIFY) {
                self.verify = true;
            }
            self.key = key;
        }
        if !self.sign && !self.verify {
            return Err(CoseError::KeyOpNotSupported());
        }
        Ok(())
    }

    /// Function to generate the MAC tag of the message for both types (cose-mac0 and cose-mac).
    ///
    /// `external_aad` parameter is used when it is desired to have an additional authentication
    /// data to reinforce security of the tag.
    pub fn gen_tag(&mut self, external_aad: Option<Vec<u8>>) -> CoseResult {
        if self.payload.len() <= 0 {
            return Err(CoseError::MissingPayload());
        }
        self.ph_bstr = self.header.get_protected_bstr(true)?;
        let aead = match external_aad {
            None => Vec::new(),
            Some(v) => v,
        };
        let alg = self.header.alg.ok_or(CoseError::MissingAlg())?;
        if self.recipients.len() <= 0 {
            if !algs::MAC_ALGS.contains(&alg) {
                Err(CoseError::InvalidAlg())
            } else if !self.sign {
                Err(CoseError::KeyOpNotSupported())
            } else {
                self.tag = mac_struct::gen_mac(
                    &self.key,
                    &alg,
                    &aead,
                    mac_struct::MAC0,
                    &self.ph_bstr,
                    &self.payload,
                )?;
                Ok(())
            }
        } else {
            let mut cek;
            if algs::DIRECT
                == self.recipients[0]
                    .header
                    .alg
                    .ok_or(CoseError::MissingAlg())?
            {
                if self.recipients.len() > 1 {
                    return Err(CoseError::AlgOnlySupportsOneRecipient());
                }
                if !self.recipients[0].key_ops.contains(&keys::KEY_OPS_MAC) {
                    return Err(CoseError::KeyOpNotSupported());
                } else {
                    self.recipients[0].sign(&self.payload, &aead, &self.ph_bstr)?;
                    return Ok(());
                }
            } else if algs::ECDH_H.contains(
                self.recipients[0]
                    .header
                    .alg
                    .as_ref()
                    .ok_or(CoseError::MissingAlg())?,
            ) {
                if self.recipients.len() > 1 {
                    return Err(CoseError::AlgOnlySupportsOneRecipient());
                }
                let size = algs::get_cek_size(&alg)?;
                cek = self.recipients[0].derive_key(&Vec::new(), size, true, &alg)?;
            } else {
                cek = algs::gen_random_key(&alg)?;
                for i in 0..self.recipients.len() {
                    if algs::DIRECT
                        == self.recipients[i]
                            .header
                            .alg
                            .ok_or(CoseError::MissingAlg())?
                        || algs::ECDH_H.contains(&self.recipients[i].header.alg.unwrap())
                    {
                        return Err(CoseError::AlgOnlySupportsOneRecipient());
                    }
                    cek = self.recipients[i].derive_key(&cek, cek.len(), true, &alg)?;
                }
            }
            self.tag = mac_struct::gen_mac(
                &cek,
                &alg,
                &aead,
                mac_struct::MAC,
                &self.ph_bstr,
                &self.payload,
            )?;
            Ok(())
        }
    }

    /// Function to encode the COSE message after the MAC tag is generated with
    /// [gen_tag](#method.gen_tag).
    ///
    /// The `payload` parameter is used to specified if the payload shall be present or not in
    /// the message.
    pub fn encode(&mut self, payload: bool) -> CoseResult {
        if self.recipients.len() <= 0 {
            let mut e = Encoder::new(Vec::new());
            e.tag(Tag::Unassigned(common::MAC0_TAG))?;
            e.array(SIZE)?;
            e.bytes(self.ph_bstr.as_slice())?;
            self.header.encode_unprotected(&mut e)?;
            if payload {
                e.bytes(self.payload.as_slice())?;
            } else {
                e.null()?;
            }
            e.bytes(self.tag.as_slice())?;
            self.bytes = e.into_writer().to_vec();
            self.header.labels_found = Vec::new();
            Ok(())
        } else {
            let mut e = Encoder::new(Vec::new());
            e.tag(Tag::Unassigned(common::MAC_TAG))?;
            e.array(SIZE_N)?;
            e.bytes(self.ph_bstr.as_slice())?;
            self.header.encode_unprotected(&mut e)?;
            if payload {
                e.bytes(self.payload.as_slice())?;
            } else {
                e.null()?;
            }
            e.bytes(self.tag.as_slice())?;
            let r_len = self.recipients.len();
            e.array(r_len)?;
            for i in 0..r_len {
                self.recipients[i].encode(&mut e)?;
            }
            self.bytes = e.into_writer().to_vec();
            self.header.labels_found = Vec::new();
            Ok(())
        }
    }

    /// Function to decode the initial parts of the COSE message, in order to access the required parameters to fully decode the message with [decode](#method.decode).
    ///
    /// This function requires that the attribute bytes is set in the structure with the COSE
    /// encoded message beforehand.
    pub fn init_decoder(&mut self) -> CoseResult {
        let input = Cursor::new(self.bytes.clone());
        let mut d = Decoder::new(Config::default(), input);
        let mut tag: Option<Tag> = None;

        match d.tag() {
            Ok(v) => {
                if !MAC_TAGS.contains(&v) {
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

        self.payload = d.bytes()?.to_vec();
        self.tag = d.bytes()?.to_vec();
        if self.tag.len() <= 0 {
            return Err(CoseError::MissingPayload());
        }

        let mut r_len = 0;
        let is_mac0 = match d.array() {
            Ok(v) => {
                r_len = v;
                false
            }
            Err(_) => true,
        };

        if !is_mac0 && (tag == None || tag.unwrap() == Tag::Unassigned(common::MAC_TAG)) {
            let mut recipient: CoseAgent;
            for _ in 0..r_len {
                recipient = CoseAgent::new();
                recipient.context = enc_struct::MAC_RECIPIENT.to_string();
                d.array()?;
                recipient.ph_bstr = common::ph_bstr(d.bytes())?;
                recipient.decode(&mut d)?;
                self.recipients.push(recipient);
            }
        } else if is_mac0 && (tag == None || tag.unwrap() == Tag::Unassigned(common::MAC0_TAG)) {
            if self.tag.len() <= 0 {
                return Err(CoseError::MissingTag());
            }
        }
        Ok(())
    }

    /// Function to verify the tag of the COSE message.
    ///
    /// `external_add` is used in case of an AAD is included.
    ///
    /// `recipient` parameter must be `None` if the type of the message is cose-mac0 and in case of
    /// being a cose-mac message a recipient of the message must be given here.
    pub fn decode(
        &mut self,
        external_aad: Option<Vec<u8>>,
        recipient: Option<usize>,
    ) -> CoseResult {
        let aead = match external_aad {
            None => Vec::new(),
            Some(v) => v,
        };
        let alg = self.header.alg.ok_or(CoseError::MissingAlg())?;
        if self.recipients.len() <= 0 {
            if !self.verify {
                Err(CoseError::KeyOpNotSupported())
            } else {
                if !mac_struct::verify_mac(
                    &self.key,
                    &alg,
                    &aead,
                    mac_struct::MAC0,
                    &self.ph_bstr,
                    &self.tag,
                    &self.payload,
                )? {
                    return Err(CoseError::InvalidMAC());
                } else {
                    Ok(())
                }
            }
        } else if recipient != None {
            let cek;
            let index = recipient.ok_or(CoseError::MissingRecipient())?;
            if algs::DIRECT
                == self.recipients[index]
                    .header
                    .alg
                    .ok_or(CoseError::MissingAlg())?
            {
                if !self.recipients[index]
                    .key_ops
                    .contains(&keys::KEY_OPS_MAC_VERIFY)
                {
                    return Err(CoseError::KeyOpNotSupported());
                } else {
                    if self.recipients[index].s_key.len() > 0 {
                        cek = self.recipients[index].s_key.clone();
                    } else {
                        return Err(CoseError::KeyOpNotSupported());
                    }
                }
            } else {
                let size = algs::get_cek_size(&alg)?;
                let payload = self.recipients[index].payload.clone();
                cek = self.recipients[index].derive_key(&payload, size, false, &alg)?;
            }
            if !mac_struct::verify_mac(
                &cek,
                &alg,
                &aead,
                mac_struct::MAC,
                &self.ph_bstr,
                &self.tag,
                &self.payload,
            )? {
                Err(CoseError::InvalidMAC())
            } else {
                Ok(())
            }
        } else {
            return Err(CoseError::MissingRecipient());
        }
    }
}
