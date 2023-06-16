//! Module to encode/decode cose-encrypt and cose-encrypt0.
//!
//! # Examples
//!
//!
//! ## cose-encrypt0
//!
//! cose-encrypt0 message with ChaCha20/Poly1305 algorithm
//!
//! ### Encode cose-encrypt0 message
//! ```
//! use cose::encrypt::CoseEncrypt;
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
//!     let mut enc0 = CoseEncrypt::new();
//!     enc0.header.alg(algs::CHACHA20, true, false);
//!     enc0.header.iv(hex::decode("89f52f65a1c580933b5261a7").unwrap(), true, false);
//!     enc0.payload(msg);
//!     enc0.key(&key).unwrap();
//!
//!     // Generate the ciphertext with no AAD.
//!     enc0.gen_ciphertext(None).unwrap();
//!     // Encode the cose-encrypt0 message with the ciphertext included
//!     enc0.encode(true).unwrap();
//! }
//!
//! ```
//!
//! ### Decode cose-encrypt0 message
//! ```
//! use cose::encrypt::CoseEncrypt;
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
//!     let mut dec0 = CoseEncrypt::new();
//!     dec0.bytes =
//!     hex::decode("d08352a2011818054c89f52f65a1c580933b5261a7a0582481c32c048134989007b3b5b932811ea410eeab15bd0de5d5ac5be03c84dce8c88871d6e9").unwrap();
//!
//!     // Initial decoding of the message
//!     dec0.init_decoder().unwrap();
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
//! use cose::encrypt::CoseEncrypt;
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
//!     r2_key.alg(algs::ES256);
//!     r2_key.crv(keys::P_256);
//!     r2_key.x(hex::decode("98F50A4FF6C05861C8860D13A638EA56C3F5AD7590BBFBF054E1C7B4D91D6280").unwrap());
//!
//!     // Prepare recipient 2 sender ephermeral ECDH key
//!     let mut r2_eph_key = keys::CoseKey::new();
//!     r2_eph_key.kty(keys::EC2);
//!     r2_eph_key.alg(algs::ES256);
//!     r2_eph_key.crv(keys::P_256);
//!     r2_eph_key.x(hex::decode("bac5b11cad8f99f9c72b05cf4b9e26d244dc189f745228255a219a86d6a09eff").unwrap());
//!     r2_eph_key.d(hex::decode("57c92077664146e876760c9520d054aa93c3afb04e306705db6090308507b4d3").unwrap());
//!     r2_eph_key.key_ops(vec![keys::KEY_OPS_DERIVE]);
//!
//!     // Prepare cose-encrypt message
//!     let mut enc = CoseEncrypt::new();
//!     enc.header.alg(algs::A256GCM, true, false);
//!     enc.header.iv(hex::decode("89f52f65a1c580933b5261a7").unwrap(), true, false);
//!     enc.payload(msg);
//!
//!     // Add recipient 1 (A128KW)
//!     let mut recipient1 = CoseAgent::new();
//!     recipient1.header.alg(algs::A128KW, true, false);
//!     recipient1.header.kid(r1_kid.clone(), false, false);
//!     recipient1.key(&r1_key).unwrap();
//!     enc.add_recipient(&mut recipient1).unwrap();
//!
//!     // Add recipient 2 (ECDH_ES_A128KW)
//!     let mut recipient2 = CoseAgent::new();
//!     recipient2.header.alg(algs::ECDH_ES_A128KW, true, false);
//!     recipient2.header.kid(r2_kid.clone(), false, false);
//!     recipient2.key(&r2_key).unwrap();
//!     recipient2.header.ephemeral_key(r2_eph_key, true, false);
//!     enc.add_recipient(&mut recipient2).unwrap();
//!
//!     // Generate ciphertext without AAD
//!     enc.gen_ciphertext(None).unwrap();
//!
//!     // Encode the cose-encrypt message
//!     enc.encode(true).unwrap();
//!
//! }
//! ```
//!
//! ### Decode cose-encrypt message
//! ```
//! use cose::encrypt::CoseEncrypt;
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
//!     r2_key.alg(algs::ES256);
//!     r2_key.crv(keys::P_256);
//!     r2_key.x(hex::decode("98F50A4FF6C05861C8860D13A638EA56C3F5AD7590BBFBF054E1C7B4D91D6280").unwrap());
//!     r2_key.y(hex::decode("F01400B089867804B8E9FC96C3932161F1934F4223069170D924B7E03BF822BB").unwrap());
//!     r2_key.d(hex::decode("02D1F7E6F26C43D4868D87CEB2353161740AACF1F7163647984B522A848DF1C3").unwrap());
//!     r2_key.key_ops(vec![keys::KEY_OPS_DERIVE]);
//!
//!     // Generate CoseEncrypt struct with the cose-encrypt message to decode
//!     let mut dec = CoseEncrypt::new();
//!     dec.bytes =
//!     hex::decode("d8608451a20103054c89f52f65a1c580933b5261a7a05824edc621173698fd7568f7495b6ad07e1107ed237a2341d78d594f13f980a14e6409e6e167828343a10122a104423131582881d927d7b1cb02570fc36890b3645987dd16ba3d2e018e067ab3b075ecd9652afbc0c292df80708a835832a201381c20a5010203262001215820bac5b11cad8f99f9c72b05cf4b9e26d244dc189f745228255a219a86d6a09eff048107a10442323258283343e73cfe119715def281a7eb30c4fc9c8ffa61f3a9ca7e4c31ea5e34f7209b228bc5e810500108").unwrap();
//!     dec.init_decoder().unwrap();
//!
//!     // Get recipient 1 and decode message
//!     let mut r1_i = dec.get_recipient(&r1_kid).unwrap()[0];
//!     dec.recipients[r1_i].key(&r1_key).unwrap();
//!     let resp = dec.decode(None, Some(r1_i)).unwrap();
//!     assert_eq!(resp, msg);
//!     
//!     // Get recipient 2 and decode message
//!     let mut r2_i = dec.get_recipient(&r2_kid).unwrap()[0];
//!     dec.recipients[r2_i].key(&r2_key).unwrap();
//!     let resp2 = dec.decode(None, Some(r2_i)).unwrap();
//!     assert_eq!(resp2, msg);
//! }
//! ```

use crate::agent::CoseAgent;
use crate::algs;
use crate::common;
use crate::enc_struct;
use crate::errors::{CoseError, CoseResult, CoseResultWithRet};
use crate::headers;
use crate::keys;
use crate::sig_struct;
use cbor::{decoder::DecodeError, types::Tag, types::Type, Config, Decoder, Encoder};
use std::io::Cursor;

const SIZE: usize = 3;
const SIZE_N: usize = 4;
const ENC_TAGS: [Tag; 2] = [
    Tag::Unassigned(common::ENC0_TAG),
    Tag::Unassigned(common::ENC_TAG),
];

/// Structure to encode/decode cose-encrypt and cose-encrypt0 messages
pub struct CoseEncrypt {
    /// The header parameters of the message.
    pub header: headers::CoseHeader,
    ciphertext: Vec<u8>,
    payload: Vec<u8>,
    /// The COSE encoded message.
    pub bytes: Vec<u8>,
    ph_bstr: Vec<u8>,
    key: Vec<u8>,
    enc: bool,
    dec: bool,
    /// The recipients of the message, empty if cose-encrypt0 message type.
    pub recipients: Vec<CoseAgent>,
}

impl CoseEncrypt {
    /// Creates a new empty COSE encryption message structure.
    pub fn new() -> CoseEncrypt {
        CoseEncrypt {
            bytes: Vec::new(),
            header: headers::CoseHeader::new(),
            ciphertext: Vec::new(),
            payload: Vec::new(),
            ph_bstr: Vec::new(),
            key: Vec::new(),
            enc: false,
            dec: false,
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
    /// Used for cose-encrypt message types.
    pub fn add_recipient(&mut self, recipient: &mut CoseAgent) -> CoseResult {
        recipient.context = enc_struct::ENCRYPT_RECIPIENT.to_string();
        if !algs::KEY_DISTRIBUTION_ALGS
            .contains(&recipient.header.alg.ok_or(CoseError::MissingAlg())?)
        {
            return Err(CoseError::InvalidAlg());
        }
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

    /// Adds a [cose-key](../keys/struct.CoseKey.html) to the message.
    ///
    /// This option is only available for the cose-encrypt0 message type, since when using cose-encrypt
    /// message type, the keys are respective to each recipient.
    pub fn key(&mut self, cose_key: &keys::CoseKey) -> CoseResult {
        if self.recipients.len() > 0 {
            return Err(CoseError::InvalidMethodForContext());
        }
        cose_key.verify_kty()?;
        if cose_key.alg.ok_or(CoseError::MissingAlg())?
            != self.header.alg.ok_or(CoseError::MissingAlg())?
        {
            return Err(CoseError::KeyOpNotSupported());
        }
        if self.header.partial_iv != None {
            self.header.iv = Some(algs::gen_iv(
                &mut self.header.partial_iv.as_mut().unwrap(),
                cose_key
                    .base_iv
                    .as_ref()
                    .ok_or(CoseError::MissingBaseIV())?,
            ));
        }

        let key = cose_key.get_s_key()?;
        if key.len() > 0 {
            if cose_key.key_ops.contains(&keys::KEY_OPS_ENCRYPT) {
                self.enc = true;
            }
            if cose_key.key_ops.contains(&keys::KEY_OPS_DECRYPT) {
                self.dec = true;
            }
            self.key = key;
        }
        if !self.enc && !self.dec {
            return Err(CoseError::KeyOpNotSupported());
        }
        Ok(())
    }

    /// Adds a counter signature to the message.
    ///
    /// The counter signature structure is the same as the
    /// [recipients](../agent/struct.CoseAgent.html) and it should be used the
    /// function [new_counter_sig](../agent/struct.CoseAgent.html#method.new_counter_sig) to initiate the structure as it sets the proper context.
    pub fn counter_sig(
        &self,
        external_aad: Option<Vec<u8>>,
        counter: &mut CoseAgent,
    ) -> CoseResult {
        if self.ciphertext.len() == 0 {
            Err(CoseError::MissingCiphertext())
        } else {
            let aead = match external_aad {
                None => Vec::new(),
                Some(v) => v,
            };
            counter.sign(&self.ciphertext, &aead, &self.ph_bstr)?;
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
        if self.ciphertext.len() == 0 {
            Err(CoseError::MissingCiphertext())
        } else {
            let aead = match external_aad {
                None => Vec::new(),
                Some(v) => v,
            };
            counter.get_to_sign(&self.ciphertext, &aead, &self.ph_bstr)
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
        if self.ciphertext.len() == 0 {
            Err(CoseError::MissingCiphertext())
        } else {
            let aead = match external_aad {
                None => Vec::new(),
                Some(v) => v,
            };
            self.header.counters[*counter].get_to_sign(&self.ciphertext, &aead, &self.ph_bstr)
        }
    }

    /// Function that verifies a given counter signature on the COSE message.
    pub fn counters_verify(&self, external_aad: Option<Vec<u8>>, counter: usize) -> CoseResult {
        if self.ciphertext.len() == 0 {
            Err(CoseError::MissingCiphertext())
        } else {
            let aead = match external_aad {
                None => Vec::new(),
                Some(v) => v,
            };
            if self.header.counters[counter].verify(&self.ciphertext, &aead, &self.ph_bstr)? {
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
            return Err(CoseError::InvalidAlg());
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

    /// Function to encrypt the payload in the message for both types (cose-encrypt0 and cose-encrypt).
    ///
    /// `external_aad` parameter is used when it is desired to have an additional authentication
    /// data to reinforce security of the ciphertext.
    pub fn gen_ciphertext(&mut self, external_aad: Option<Vec<u8>>) -> CoseResult {
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
            if !algs::ENCRYPT_ALGS.contains(&alg) {
                Err(CoseError::InvalidAlg())
            } else if !self.enc {
                Err(CoseError::KeyOpNotSupported())
            } else {
                self.ciphertext = enc_struct::gen_cipher(
                    &self.key,
                    &alg,
                    self.header.iv.as_ref().ok_or(CoseError::MissingIV())?,
                    &aead,
                    enc_struct::ENCRYPT0,
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
                if !self.recipients[0].key_ops.contains(&keys::KEY_OPS_ENCRYPT) {
                    return Err(CoseError::KeyOpNotSupported());
                } else {
                    self.ciphertext = self.recipients[0].enc(
                        &self.payload,
                        &aead,
                        &self.ph_bstr,
                        &alg,
                        self.header.iv.as_ref().ok_or(CoseError::MissingIV())?,
                    )?;
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
                    if algs::DIRECT == self.recipients[i].header.alg.unwrap()
                        || algs::ECDH_H.contains(self.recipients[i].header.alg.as_ref().unwrap())
                    {
                        return Err(CoseError::AlgOnlySupportsOneRecipient());
                    }
                    cek = self.recipients[i].derive_key(&cek, cek.len(), true, &alg)?;
                }
            }
            self.ciphertext = enc_struct::gen_cipher(
                &cek,
                &alg,
                self.header.iv.as_ref().ok_or(CoseError::MissingIV())?,
                &aead,
                enc_struct::ENCRYPT,
                &self.ph_bstr,
                &self.payload,
            )?;
            Ok(())
        }
    }

    /// Function to encode the COSE message after the ciphertext is generated with
    /// [gen_ciphertext](#method.gen_ciphertext).
    ///
    /// The `ciphertext` parameter is used to specified if the ciphertext shall be present or not in
    /// the message.
    pub fn encode(&mut self, ciphertext: bool) -> CoseResult {
        if self.recipients.len() <= 0 {
            if self.ciphertext.len() <= 0 {
                Err(CoseError::MissingCiphertext())
            } else {
                let mut e = Encoder::new(Vec::new());
                e.tag(Tag::Unassigned(common::ENC0_TAG))?;
                e.array(SIZE)?;
                e.bytes(self.ph_bstr.as_slice())?;
                self.header.encode_unprotected(&mut e)?;
                if ciphertext {
                    e.bytes(self.ciphertext.as_slice())?;
                } else {
                    e.null()?;
                }
                self.bytes = e.into_writer().to_vec();
                self.header.labels_found = Vec::new();
                Ok(())
            }
        } else {
            let mut e = Encoder::new(Vec::new());
            e.tag(Tag::Unassigned(common::ENC_TAG))?;
            e.array(SIZE_N)?;
            e.bytes(self.ph_bstr.as_slice())?;
            self.header.encode_unprotected(&mut e)?;
            if ciphertext {
                e.bytes(self.ciphertext.as_slice())?;
            } else {
                e.null()?;
            }
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
                if !ENC_TAGS.contains(&v) {
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

        if self.header.alg.ok_or(CoseError::MissingAlg())? == algs::DIRECT && self.ph_bstr.len() > 0
        {
            return Err(CoseError::InvalidCoseStructure());
        } else if algs::A_KW.contains(self.header.alg.as_ref().ok_or(CoseError::MissingAlg())?)
            && self.ph_bstr.len() > 0
        {
            return Err(CoseError::InvalidCoseStructure());
        }

        self.ciphertext = d.bytes()?.to_vec();
        if self.ciphertext.len() <= 0 {
            return Err(CoseError::MissingCiphertext());
        }

        let mut r_len = 0;
        let is_enc0 = match d.array() {
            Ok(v) => {
                r_len = v;
                false
            }
            Err(_) => true,
        };

        if !is_enc0 && (tag == None || tag.unwrap() == Tag::Unassigned(common::ENC_TAG)) {
            let mut recipient: CoseAgent;
            for _ in 0..r_len {
                recipient = CoseAgent::new();
                recipient.context = enc_struct::ENCRYPT_RECIPIENT.to_string();
                d.array()?;
                recipient.ph_bstr = common::ph_bstr(d.bytes())?;
                recipient.decode(&mut d)?;
                self.recipients.push(recipient);
            }
        } else if is_enc0 && (tag == None || tag.unwrap() == Tag::Unassigned(common::ENC0_TAG)) {
            if self.ciphertext.len() <= 0 {
                return Err(CoseError::MissingCiphertext());
            }
        }
        Ok(())
    }

    /// Function to decrypt the payload of the COSE message.
    ///
    /// `external_add` is used in case of an AAD is included.
    ///
    /// `recipient` parameter must be `None` if the type of the message is cose-encrypt0 and in case of
    /// being a cose-encrypt message a recipient of the message must be given here.
    pub fn decode(
        &mut self,
        external_aad: Option<Vec<u8>>,
        recipient: Option<usize>,
    ) -> CoseResultWithRet<Vec<u8>> {
        let aead = match external_aad {
            None => Vec::new(),
            Some(v) => v,
        };
        let alg = self.header.alg.ok_or(CoseError::MissingAlg())?;
        if self.recipients.len() <= 0 {
            if !self.dec {
                Err(CoseError::KeyOpNotSupported())
            } else {
                Ok(enc_struct::dec_cipher(
                    &self.key,
                    &alg,
                    self.header.iv.as_ref().ok_or(CoseError::MissingIV())?,
                    &aead,
                    enc_struct::ENCRYPT0,
                    &self.ph_bstr,
                    &self.ciphertext,
                )?)
            }
        } else if recipient != None {
            let size = algs::get_cek_size(&alg)?;
            let index = recipient.ok_or(CoseError::MissingRecipient())?;
            let cek;
            if algs::DIRECT
                == self.recipients[index]
                    .header
                    .alg
                    .ok_or(CoseError::MissingAlg())?
            {
                if !self.recipients[index]
                    .key_ops
                    .contains(&keys::KEY_OPS_DECRYPT)
                {
                    return Err(CoseError::KeyOpNotSupported());
                } else {
                    return Ok(self.recipients[index].dec(
                        &self.ciphertext,
                        &aead,
                        &self.ph_bstr,
                        &alg,
                        self.header.iv.as_ref().ok_or(CoseError::MissingIV())?,
                    )?);
                }
            } else {
                let payload = self.recipients[index].payload.clone();
                cek = self.recipients[index].derive_key(&payload, size, false, &alg)?;
            }
            Ok(enc_struct::dec_cipher(
                &cek,
                &alg,
                self.header.iv.as_ref().ok_or(CoseError::MissingIV())?,
                &aead,
                enc_struct::ENCRYPT,
                &self.ph_bstr,
                &self.ciphertext,
            )?)
        } else {
            Err(CoseError::MissingRecipient())
        }
    }
}
