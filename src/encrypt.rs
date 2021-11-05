//! Module to encode/decode cose-encrypt and cose-encrypt0 messages by providing the necessary
//! information in the [header](../headers/struct.CoseHeader.html), the respective [cose-key](../keys/struct.CoseKey.html) and the desired payload.
//!
//! In order to use the recipients bucket for this type of message, cose-encrypt, the
//! [recipients](../recipients/struct.CoseRecipient.html) are built and added to the [CoseEncrypt](struct.CoseEncrypt.html) structure after generating the ciphertext and before the final encoding of the
//! COSE message.
//!
//! # Examples
//!
//! The following examples demonstrate how to encode/decode a simple cose-encrypt0 message and a cose-encrypt
//! with 2 recipients, one using [A128KW](../algs/constant.A128KW.html) as the key agreement and the other using the [ECDH-ES +
//! A128KW](../algs/constant.ECDH_ES_A128KW.html) key agreement.
//!
//! ## cose-encrypt0
//! ```
//! use cose::encrypt;
//! use cose::keys;
//! use cose::algs;
//!
//! fn main() {
//!     let msg = b"encrypted message".to_vec();
//!     let k = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F";
//!     let iv = b"\x00\x01\x02\x03\x04\x05\x06\x07\x00\x01\x02\x03";
//!
//!     // Prepare cose-encrypt0 headers
//!     let mut enc0 = encrypt::CoseEncrypt::new();
//!     enc0.header.alg(algs::CHACHA20, true, false);
//!     enc0.header.kid(b"kid2".to_vec(), true, false);
//!     enc0.header.iv(iv.to_vec(), true, false);
//!
//!     // Add the payload
//!     enc0.payload(msg);
//!
//!     // Prepare the cose-key
//!     let mut key = keys::CoseKey::new();
//!     key.kty(keys::SYMMETRIC);
//!     key.alg(algs::CHACHA20);
//!     key.k(k.to_vec());
//!     key.key_ops(vec![keys::KEY_OPS_ENCRYPT, keys::KEY_OPS_DECRYPT]);
//!
//!     // Add cose-key
//!     enc0.key(&key).unwrap();
//!
//!     // Generate the ciphertext with no AAD.
//!     enc0.gen_ciphertext(None).unwrap();
//!     // Encode the cose-encrypt0 message with the ciphertext included in the message
//!     enc0.encode(true).unwrap();
//!
//!     // Prepare decrypter
//!     let mut dec0 = encrypt::CoseEncrypt::new();
//!     // Add the cose-encrypt0 message generated
//!     dec0.bytes = enc0.bytes;
//!     // Initial decoding of the message
//!     dec0.init_decoder().unwrap();
//!
//!     // Add cose-key
//!     dec0.key(&key).unwrap();
//!
//!     // Decrypt the cose-encrypt0 message
//!     let resp = dec0.decode(None, None).unwrap();
//!     assert_eq!(resp, b"encrypted message".to_vec());
//! }
//!
//! ```
//!
//! ## cose-encrypt
//! ```
//! use cose::encrypt;
//! use cose::keys;
//! use cose::headers;
//! use cose::algs;
//! use cose::recipients;
//!
//! fn main() {
//!     let msg = b"This is the content.".to_vec();
//!     let k = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F";
//!     let iv = b"\x00\x01\x02\x03\x04\x05\x06\x07\x00\x01\x02\x03";
//!
//!
//!     let mut enc = encrypt::CoseEncrypt::new();
//!     enc.header.alg(algs::A256GCM, true, false);
//!     enc.header.iv(iv.to_vec(), true, false);
//!     enc.payload(msg);
//!
//!     // Recipients Key IDs
//!     let r1_kid = b"11".to_vec();
//!     let r2_kid = b"22".to_vec();
//!
//!     // Prepare recipient 1 headers
//!     let mut recipient1 = recipients::CoseRecipient::new();
//!     recipient1.header.alg(algs::A128KW, true, false);
//!     recipient1.header.iv(iv.to_vec(), true, false);
//!     recipient1.header.kid(r1_kid.clone(), false, false);
//!     recipient1.header.salt(vec![0; 32], false, false);
//!
//!     // Prepare recipient 1 cose-key
//!     let mut r1_key = keys::CoseKey::new();
//!     r1_key.kty(keys::SYMMETRIC);
//!     r1_key.alg(algs::CHACHA20);
//!     r1_key.k(k.to_vec());
//!     r1_key.key_ops(vec![keys::KEY_OPS_WRAP, keys::KEY_OPS_UNWRAP]);
//!
//!     // Add recipient 1 cose-key
//!     recipient1.key(&r1_key).unwrap();
//!
//!     // Add recipient 1 to cose-encrypt message
//!     enc.add_recipient(&mut recipient1).unwrap();
//!
//!     // Prepare recipient 2 headers
//!     let mut recipient2 = recipients::CoseRecipient::new();
//!     recipient2.header.alg(algs::ECDH_ES_A128KW, true, false);
//!     recipient2.header.iv(iv.to_vec(), true, false);
//!     recipient2.header.kid(r2_kid.clone(), false, false);
//!     recipient2.header.salt(vec![0; 32], false, false);
//!
//!     // Prepare recipient 2 cose-key
//!     let mut r2_key = keys::CoseKey::new();
//!     r2_key.kty(keys::EC2);
//!     r2_key.alg(algs::ES256);
//!     r2_key.crv(keys::P_256);
//!     r2_key.x(vec![152, 245, 10, 79, 246, 192, 88, 97, 200, 134, 13, 19, 166, 56, 234, 86, 195, 245, 173, 117, 144, 187, 251, 240, 84, 225, 199, 180, 217, 29, 98, 128]);
//!     r2_key.d(vec![2, 209, 247, 230, 242, 108, 67, 212, 134, 141, 135, 206, 178, 53, 49, 97, 116, 10, 172, 241, 247, 22, 54, 71, 152, 75, 82, 42, 132, 141, 241, 195]);
//!
//!     // Add recipient 1 cose-key
//!     recipient2.key(&r2_key).unwrap();
//!
//!     // Prepare sender ephermeral ECDH key
//!     let mut r2_eph_key = keys::CoseKey::new();
//!     r2_eph_key.kty(keys::EC2);
//!     r2_eph_key.alg(algs::ES256);
//!     r2_eph_key.crv(keys::P_256);
//!     r2_eph_key.x(vec![101, 237, 165, 161, 37, 119, 194, 186, 232, 41, 67, 127, 227, 56, 112, 26, 16, 170, 163, 117, 225, 187, 91, 93, 225, 8, 222, 67, 156, 8, 85, 29]);
//!     r2_eph_key.d(vec![175, 249, 7, 201, 159, 154, 211, 170, 230, 196, 205, 242, 17, 34, 188, 226, 189, 104, 181, 40, 62, 105, 7, 21, 74, 217, 17, 132, 15, 162, 8, 207]);
//!     r2_eph_key.key_ops(vec![keys::KEY_OPS_DERIVE]);
//!
//!     // Add the ephemeral key
//!     recipient2.header.ephemeral_key(r2_eph_key.clone(), true, false);
//!
//!     // Add recipient 2 to cose-encrypt message
//!     enc.add_recipient(&mut recipient2).unwrap();
//!
//!     enc.gen_ciphertext(None).unwrap();
//!     enc.encode(true).unwrap();
//!
//!
//!     let mut dec = encrypt::CoseEncrypt::new();
//!     dec.bytes = enc.bytes;
//!     dec.init_decoder().unwrap();
//!
//!     // Get recipient 1 from the cose-encrypt message
//!     let mut recipient1 = dec.get_recipient(&r1_kid).unwrap();
//!
//!     // Add recipient 1 cose-key
//!     recipient1.key(&r1_key).unwrap();
//!
//!     // Decrypt cose-encrypt message with recipient 1
//!     let resp_1 = dec.decode(None, Some(recipient1)).unwrap();
//!     assert_eq!(resp_1, b"This is the content.".to_vec());
//!     
//!     // Get recipient 2 from the cose-encrypt message
//!     let mut recipient2 = dec.get_recipient(&r2_kid).unwrap();
//!
//!     // Add recipient 2 sender cose-key
//!     recipient2.key(&r2_eph_key).unwrap();
//!
//!     // Add recipient 2 cose-key
//!     recipient2.header.ecdh_key(r2_key);
//!
//!     // Decrypt cose-encrypt message with recipient 2
//!     let resp_2 = dec.decode(None, Some(recipient2)).unwrap();
//!     assert_eq!(resp_2, b"This is the content.".to_vec());
//! }
//! ```
//!

use crate::algs;
use crate::common;
use crate::enc_struct;
use crate::errors::{CoseError, CoseResult, CoseResultWithRet};
use crate::headers;
use crate::keys;
use crate::recipients;
use crate::sig_struct;
use cbor::{decoder::DecodeError, types::Tag, types::Type, Config, Decoder, Encoder};
use std::io::Cursor;

const SIZE: usize = 3;
const SIZE_N: usize = 4;

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
    pub recipients: Vec<recipients::CoseRecipient>,
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

    /// Adds a [recipient](../recipients/struct.CoseRecipient.html) to the message.
    ///
    /// Used for cose-encrypt message types.
    pub fn add_recipient(&mut self, recipient: &mut recipients::CoseRecipient) -> CoseResult {
        recipient.context = enc_struct::ENCRYPT_RECIPIENT.to_string();
        if !algs::KEY_DISTRIBUTION_ALGS
            .contains(&recipient.header.alg.ok_or(CoseError::MissingAlgorithm())?)
        {
            return Err(CoseError::InvalidAlgorithmForContext(
                enc_struct::ENCRYPT.to_string(),
            ));
        }
        self.recipients.push(recipient.clone());
        Ok(())
    }

    /// Returns a [recipient](../recipients/struct.CoseRecipient.html) of the message with a given Key ID.
    pub fn get_recipient(&self, kid: &Vec<u8>) -> CoseResultWithRet<recipients::CoseRecipient> {
        for i in 0..self.recipients.len() {
            if self.recipients[i]
                .header
                .kid
                .as_ref()
                .ok_or(CoseError::MissingParameter("KID".to_string()))?
                == kid
            {
                return Ok(self.recipients[i].clone());
            }
        }
        Err(CoseError::MissingRecipient())
    }

    /// Adds a [cose-key](../keys/struct.CoseKey.html) to the message.
    ///
    /// This option is only available for the cose-encrypt0 message type, since when using cose-encrypt
    /// message type, the keys are respective to each recipient.
    pub fn key(&mut self, cose_key: &keys::CoseKey) -> CoseResult {
        if self.recipients.len() > 0 {
            return Err(CoseError::InvalidOperationForContext(
                enc_struct::ENCRYPT0.to_string(),
            ));
        }
        if self.header.partial_iv != None {
            self.header.iv = Some(algs::gen_iv(
                &mut self.header.partial_iv.clone().unwrap(),
                cose_key
                    .base_iv
                    .as_ref()
                    .ok_or(CoseError::MissingParameter("base_iv".to_string()))?,
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
            return Err(CoseError::KeyUnableToEncryptOrDecrypt());
        }
        Ok(())
    }

    /// Adds a counter signature to the message.
    ///
    /// The counter signature structure is the same as the
    /// [recipients](../recipients/struct.CoseRecipient.html) and it should be used the
    /// function [new_counter_sig](../recipients/struct.CoseRecipient.html#method.new_counter_sig) to initiate the structure as it sets the proper context.
    pub fn counter_sig(
        &self,
        external_aad: Option<Vec<u8>>,
        counter: &mut recipients::CoseRecipient,
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
        counter: &mut recipients::CoseRecipient,
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

    /// Function that verifies a given counter signature on the COSE message.
    pub fn counters_verify(
        &self,
        external_aad: Option<Vec<u8>>,
        counter: &mut recipients::CoseRecipient,
    ) -> CoseResult {
        if self.ciphertext.len() == 0 {
            Err(CoseError::MissingCiphertext())
        } else {
            let aead = match external_aad {
                None => Vec::new(),
                Some(v) => v,
            };
            counter.verify(&self.ciphertext, &aead, &self.ph_bstr)?;
            Ok(())
        }
    }

    /// Function that adds a counter signature which was signed externally with the use of
    /// [get_to_sign](#method.get_to_sign)
    pub fn add_counter_sig(&mut self, counter: recipients::CoseRecipient) -> CoseResult {
        if !algs::SIGNING_ALGS.contains(&counter.header.alg.ok_or(CoseError::MissingAlgorithm())?) {
            return Err(CoseError::InvalidAlgorithmForContext(
                sig_struct::COUNTER_SIGNATURE.to_string(),
            ));
        }
        if counter.context != sig_struct::COUNTER_SIGNATURE {
            return Err(CoseError::InvalidAlgorithmForContext(
                sig_struct::COUNTER_SIGNATURE.to_string(),
            ));
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
        if self.recipients.len() <= 0 {
            if !algs::ENCRYPT_ALGS.contains(&self.header.alg.ok_or(CoseError::MissingAlgorithm())?)
            {
                Err(CoseError::InvalidAlgorithmForContext(
                    enc_struct::ENCRYPT0.to_string(),
                ))
            } else if !self.enc {
                Err(CoseError::KeyDoesntSupportEncryption())
            } else {
                self.ciphertext = enc_struct::gen_cipher(
                    &self.key,
                    &self.header.alg.unwrap(),
                    self.header
                        .iv
                        .as_ref()
                        .ok_or(CoseError::MissingParameter("iv".to_string()))?,
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
                    .ok_or(CoseError::MissingAlgorithm())?
            {
                if self.recipients.len() > 1 {
                    return Err(CoseError::AlgorithmOnlySupportsOneRecipient(
                        "direct".to_string(),
                    ));
                }
                if !self.recipients[0].key_ops.contains(&keys::KEY_OPS_ENCRYPT) {
                    return Err(CoseError::KeyDoesntSupportEncryption());
                } else {
                    self.ciphertext = self.recipients[0].enc(
                        &self.payload,
                        &aead,
                        &self.ph_bstr,
                        &self.header.alg.unwrap(),
                        self.header
                            .iv
                            .as_ref()
                            .ok_or(CoseError::MissingParameter("iv".to_string()))?,
                    )?;
                    return Ok(());
                }
            } else if [
                algs::ECDH_ES_HKDF_256,
                algs::ECDH_ES_HKDF_512,
                algs::ECDH_SS_HKDF_256,
                algs::ECDH_SS_HKDF_512,
            ]
            .contains(
                self.recipients[0]
                    .header
                    .alg
                    .as_ref()
                    .ok_or(CoseError::MissingAlgorithm())?,
            ) {
                if self.recipients.len() > 1 {
                    return Err(CoseError::AlgorithmOnlySupportsOneRecipient(
                        "ECDH HKDF".to_string(),
                    ));
                }
                let size = algs::get_cek_size(
                    self.header
                        .alg
                        .as_ref()
                        .ok_or(CoseError::MissingAlgorithm())?,
                )?;
                cek = self.recipients[0].derive_key(&Vec::new(), size, true)?;
            } else {
                cek = algs::gen_random_key(
                    self.header
                        .alg
                        .as_ref()
                        .ok_or(CoseError::MissingAlgorithm())?,
                )?;
                for i in 0..self.recipients.len() {
                    if algs::DIRECT == self.recipients[i].header.alg.unwrap()
                        || [
                            algs::ECDH_ES_HKDF_256,
                            algs::ECDH_ES_HKDF_512,
                            algs::ECDH_SS_HKDF_256,
                            algs::ECDH_SS_HKDF_512,
                        ]
                        .contains(self.recipients[i].header.alg.as_ref().unwrap())
                    {
                        return Err(CoseError::AlgorithmOnlySupportsOneRecipient(
                            "direct/ECDH HKDF".to_string(),
                        ));
                    }
                    cek = self.recipients[i].derive_key(&cek.clone(), cek.len(), true)?;
                }
            }
            self.ciphertext = enc_struct::gen_cipher(
                &cek,
                &self.header.alg.ok_or(CoseError::MissingAlgorithm())?,
                self.header
                    .iv
                    .as_ref()
                    .ok_or(CoseError::MissingParameter("iv".to_string()))?,
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
                Err(CoseError::MissingSignature())
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
                if ![
                    Tag::Unassigned(common::ENC0_TAG),
                    Tag::Unassigned(common::ENC_TAG),
                ]
                .contains(&v)
                {
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
            let mut recipient: recipients::CoseRecipient;
            for _ in 0..r_len {
                recipient = recipients::CoseRecipient::new();
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
        recipient: Option<recipients::CoseRecipient>,
    ) -> CoseResultWithRet<Vec<u8>> {
        let aead = match external_aad {
            None => Vec::new(),
            Some(v) => v,
        };
        if self.recipients.len() <= 0 {
            if !self.enc {
                Err(CoseError::KeyDoesntSupportDecryption())
            } else {
                Ok(enc_struct::dec_cipher(
                    &self.key,
                    &self.header.alg.ok_or(CoseError::MissingAlgorithm())?,
                    self.header
                        .iv
                        .as_ref()
                        .ok_or(CoseError::MissingParameter("iv".to_string()))?,
                    &aead,
                    enc_struct::ENCRYPT0,
                    &self.ph_bstr,
                    &self.ciphertext,
                )?)
            }
        } else {
            let size = algs::get_cek_size(
                self.header
                    .alg
                    .as_ref()
                    .ok_or(CoseError::MissingAlgorithm())?,
            )?;
            let mut r = recipient.ok_or(CoseError::MissingRecipient())?;
            let cek;
            if algs::DIRECT == r.header.alg.ok_or(CoseError::MissingAlgorithm())? {
                if !r.key_ops.contains(&keys::KEY_OPS_DECRYPT) {
                    return Err(CoseError::KeyDoesntSupportDecryption());
                } else {
                    return Ok(r.dec(
                        &self.ciphertext,
                        &aead,
                        &self.ph_bstr,
                        &self.header.alg.unwrap(),
                        self.header
                            .iv
                            .as_ref()
                            .ok_or(CoseError::MissingRecipient())?,
                    )?);
                }
            } else {
                cek = r.derive_key(&r.payload.clone(), size, false)?;
            }
            Ok(enc_struct::dec_cipher(
                &cek,
                &self.header.alg.unwrap(),
                self.header
                    .iv
                    .as_ref()
                    .ok_or(CoseError::MissingAlgorithm())?,
                &aead,
                enc_struct::ENCRYPT,
                &self.ph_bstr,
                &self.ciphertext,
            )?)
        }
    }
}
