//! Module to encode/decode cose-sign and cose-sign1 messages by providing the necessary
//! information in the [header](../headers/struct.CoseHeader.html), the respective [cose-key](../keys/struct.CoseKey.html) and the desired payload.
//!
//! In order to use the recipients bucket for this type of message, cose-sign, the
//! [recipients](../recipients/struct.CoseRecipient.html) are built and added to the [CoseSign](struct.CoseSign.html) structure after generating the signature and before the final encoding of the
//! COSE message.
//!
//! # Examples
//!
//! The following examples, demonstrate how to encode/decode a cose-sign1 message and a cose-sign
//! message with 2 recipients.
//!
//! ## cose-sign1
//!
//! ```
//! use cose::sign;
//! use cose::keys;
//! use cose::headers;
//! use cose::algs;
//! use hex;
//!
//! fn main() {
//!     let msg = b"signed message".to_vec();
//!
//!     // COSE_KEY to encode the message
//!     let mut key = keys::CoseKey::new();
//!     key.kty(keys::EC2);
//!     key.alg(algs::EDDSA);
//!     key.crv(keys::ED25519);
//!     key.x(
//!         hex::decode("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
//!             .unwrap(),
//!     );
//!     key.d(
//!         hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
//!             .unwrap(),
//!     );
//!     key.key_ops(vec![keys::KEY_OPS_SIGN, keys::KEY_OPS_VERIFY]);
//!
//!     // Prepare COSE_SIGN1 message
//!     let mut sign1 = sign::CoseSign::new();
//!     sign1.header.alg(algs::EDDSA, true, false);
//!     sign1.header.kid(b"kid1".to_vec(), true, false);
//!     sign1.payload(msg);
//!     sign1.key(&key).unwrap();
//!
//!     // Generate the Signature with the payload and protected buckets
//!     sign1.gen_signature(None).unwrap();
//!
//!     // Encode the message
//!     sign1.encode(true).unwrap();
//!
//!     //Decode and verify the COSE_SIGN1 message
//!     let mut verify = sign::CoseSign::new();
//!     verify.bytes = sign1.bytes;
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
//! ```
//! use cose::sign;
//! use cose::keys;
//! use cose::headers;
//! use cose::algs;
//! use cose::recipients;
//!
//! fn main() {
//!
//!     let msg = b"This is the content.".to_vec();
//!
//!     let mut sign = sign::CoseSign::new();
//!     sign.payload(msg);
//!
//!     // Recipients Key IDs
//!     let r1_kid = b"11".to_vec();
//!     let r2_kid = b"22".to_vec();
//!
//!     // Prepare recipient 1 headers
//!     let mut recipient1 = recipients::CoseRecipient::new();
//!     recipient1.header.alg(algs::ES256, true, false);
//!     recipient1.header.kid(r1_kid.clone(), false, false);
//!
//!     // Prepare recipient 1 cose-key
//!     let mut r1_key = keys::CoseKey::new();
//!     r1_key.kty(keys::EC2);
//!     r1_key.alg(algs::ES256);
//!     r1_key.crv(keys::P_256);
//!     r1_key.x(
//!         hex::decode("98f50a4ff6c05861c8860d13a638ea56c3f5ad7590bbfbf054e1c7b4d91d6280")
//!             .unwrap(),
//!     );
//!     r1_key.d(
//!         hex::decode("02d1f7e6f26c43d4868d87ceb2353161740aacf1f7163647984b522a848df1c3")
//!             .unwrap(),
//!     );
//!     r1_key.key_ops(vec![keys::KEY_OPS_SIGN, keys::KEY_OPS_VERIFY]);
//!
//!     // Add recipient 1 cose-key
//!     recipient1.key(&r1_key).unwrap();
//!     // Add recipient 1 to cose-sign message
//!     sign.add_recipient(&mut recipient1).unwrap();
//!
//!     // Prepare recipient 2 headers
//!     let mut recipient2 = recipients::CoseRecipient::new();
//!     recipient2.header.alg(algs::EDDSA, true, false);
//!     recipient2.header.kid(r2_kid.clone(), false, false);
//!
//!     // Prepare recipient 2 cose-key
//!     let mut r2_key = keys::CoseKey::new();
//!     r2_key.kty(keys::OKP);
//!     r2_key.alg(algs::EDDSA);
//!     r2_key.crv(keys::ED25519);
//!     r2_key.x(
//!         hex::decode("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
//!             .unwrap(),
//!     );
//!     r2_key.d(
//!         hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
//!             .unwrap(),
//!     );
//!     r2_key.key_ops(vec![keys::KEY_OPS_SIGN, keys::KEY_OPS_VERIFY]);
//!
//!     // Add recipient 2 cose-key
//!     recipient2.key(&r2_key).unwrap();
//!     // Add recipient 2 to cose-sign message
//!     sign.add_recipient(&mut recipient2).unwrap();
//!
//!     sign.gen_signature(None).unwrap();
//!     sign.encode(true).unwrap();
//!
//!     let mut verify = sign::CoseSign::new();
//!     verify.bytes = sign.bytes;
//!     verify.init_decoder(None).unwrap();
//!
//!     // Get recipient 1 from cose-sign message
//!     let mut recipient1 = verify.get_recipient(&r1_kid).unwrap();
//!     // Add recipient 1 cose-key
//!     recipient1.key(&r1_key).unwrap();
//!     // Verify cose-sign signature with recipient 1
//!     verify.decode(None, Some(recipient1)).unwrap();
//!
//!     // Get recipient 2 from cose-sign message
//!     let mut recipient2 = verify.get_recipient(&r2_kid).unwrap();
//!     // Add recipient 2 cose-key
//!     recipient2.key(&r2_key).unwrap();
//!     // Verify cose-sign signature with recipient 2
//!     verify.decode(None, Some(recipient2)).unwrap();
//! }
//! ```
//!

use crate::algs;
use crate::common;
use crate::errors::{CoseError, CoseResult, CoseResultWithRet};
use crate::headers;
use crate::keys;
use crate::recipients;
use crate::sig_struct;
use cbor::{decoder::DecodeError, types::Tag, types::Type, Config, Decoder, Encoder};
use std::io::Cursor;

pub const CONTEXT: &str = "Signature1";
pub const CONTEXT_N: &str = "Signature";

pub const SIZE: usize = 4;

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
    /// The recipients of the message, empty if cose-sign1 message type.
    pub recipients: Vec<recipients::CoseRecipient>,
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
            recipients: Vec::new(),
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

    /// Adds a [recipient](../recipients/struct.CoseRecipient.html) to the message.
    ///
    /// Used for cose-sign messages.
    pub fn add_recipient(&mut self, recipient: &mut recipients::CoseRecipient) -> CoseResult {
        recipient.context = CONTEXT_N.to_string();
        if !algs::SIGNING_ALGS.contains(&recipient.header.alg.ok_or(CoseError::MissingAlgorithm())?)
        {
            return Err(CoseError::InvalidAlgorithmForContext(CONTEXT_N.to_string()));
        }
        if !recipient.key_ops.contains(&keys::KEY_OPS_SIGN) {
            return Err(CoseError::KeyDoesntSupportSigning());
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
    /// This option is only available for the cose-sign1 message type, since when using cose-sign
    /// message type, the keys are respective to each recipient.
    pub fn key(&mut self, cose_key: &keys::CoseKey) -> CoseResult {
        if self.recipients.len() > 0 {
            return Err(CoseError::InvalidOperationForContext(CONTEXT.to_string()));
        }
        let priv_key = cose_key.get_s_key()?;
        let pub_key =
            cose_key.get_pub_key(self.header.alg.ok_or(CoseError::MissingAlgorithm())?)?;

        if priv_key.len() > 0 {
            self.sign = true;
            self.priv_key = priv_key;
        }
        if pub_key.len() > 0 {
            self.verify = true;
            self.pub_key = pub_key;
        }
        if !self.sign && !self.verify {
            return Err(CoseError::KeyUnableToSignOrVerify());
        }
        Ok(())
    }

    /// Adds a counter signature to the message.
    ///
    /// The counter signature structure is the same as the
    /// [recipients](../recipients/struct.CoseRecipient.html) and it should be used the
    /// function [new_counter_sig](../recipients/struct.CoseRecipient.html#method.new_counter_sig) to initiate the structure.
    pub fn counter_sig(
        &self,
        external_aad: Option<Vec<u8>>,
        counter: &mut recipients::CoseRecipient,
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
        counter: &mut recipients::CoseRecipient,
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

    /// Function that verifies a given counter signature on the COSE message.
    pub fn counters_verify(
        &mut self,
        external_aad: Option<Vec<u8>>,
        counter: &recipients::CoseRecipient,
    ) -> CoseResult {
        if self.signature.len() == 0 {
            Err(CoseError::MissingSignature())
        } else {
            let aead = match external_aad {
                None => Vec::new(),
                Some(v) => v,
            };
            counter.verify(&self.signature, &aead, &self.ph_bstr)?;
            Ok(())
        }
    }

    /// Function that adds a counter signature which was signed externally with the use of
    /// [get_to_sign](#method.get_to_sign)
    pub fn add_counter_sig(&mut self, counter: recipients::CoseRecipient) -> CoseResult {
        if !algs::SIGNING_ALGS.contains(&counter.header.alg.ok_or(CoseError::MissingAlgorithm())?) {
            return Err(CoseError::InvalidAlgorithmForContext(
                recipients::COUNTER_CONTEXT.to_string(),
            ));
        }
        if counter.context != recipients::COUNTER_CONTEXT {
            return Err(CoseError::InvalidAlgorithmForContext(
                recipients::COUNTER_CONTEXT.to_string(),
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

    /// Function to sign the payload of the message for both types (cose-sign1 and cose-ign).
    ///
    /// `external_aad` parameter is used when it is desired to have an additional authentication
    /// data to reinforce security of the signature.
    pub fn gen_signature(&mut self, external_aad: Option<Vec<u8>>) -> CoseResult {
        if self.payload.len() <= 0 {
            return Err(CoseError::MissingPayload());
        }
        self.ph_bstr = self.header.get_protected_bstr()?;
        let aead = match external_aad {
            None => Vec::new(),
            Some(v) => v,
        };
        if self.recipients.len() <= 0 {
            if !algs::SIGNING_ALGS.contains(&self.header.alg.ok_or(CoseError::MissingAlgorithm())?)
            {
                Err(CoseError::InvalidAlgorithmForContext(CONTEXT.to_string()))
            } else if !self.sign {
                Err(CoseError::KeyDoesntSupportSigning())
            } else {
                self.signature = sig_struct::gen_sig(
                    &self.priv_key,
                    &self.header.alg.ok_or(CoseError::MissingAlgorithm())?,
                    &aead,
                    CONTEXT,
                    &self.ph_bstr,
                    &Vec::new(),
                    &self.payload,
                )?;
                Ok(())
            }
        } else {
            for i in 0..self.recipients.len() {
                if !algs::SIGNING_ALGS.contains(
                    &self.recipients[i]
                        .header
                        .alg
                        .ok_or(CoseError::MissingAlgorithm())?,
                ) {
                    return Err(CoseError::InvalidAlgorithmForContext(CONTEXT.to_string()));
                } else if !self.recipients[i].key_ops.contains(&keys::KEY_OPS_SIGN) {
                    return Err(CoseError::KeyDoesntSupportSigning());
                } else {
                    self.recipients[i].sign(&self.payload, &aead, &self.ph_bstr)?;
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
        if self.recipients.len() <= 0 {
            if self.signature.len() <= 0 {
                Err(CoseError::MissingSignature())
            } else {
                let mut e = Encoder::new(Vec::new());
                e.tag(Tag::Unassigned(headers::SIG1_TAG))?;
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
                Ok(())
            }
        } else {
            let mut e = Encoder::new(Vec::new());
            e.tag(Tag::Unassigned(headers::SIG_TAG))?;
            e.array(SIZE)?;
            e.bytes(self.ph_bstr.as_slice())?;
            self.header.encode_unprotected(&mut e)?;
            if payload {
                e.bytes(self.payload.as_slice())?;
            } else {
                e.null()?;
            }
            let r_len = self.recipients.len();
            e.array(r_len)?;
            for i in 0..r_len {
                self.recipients[i].encode(&mut e)?;
            }
            self.bytes = e.into_writer().to_vec();
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
                if ![
                    Tag::Unassigned(headers::SIG1_TAG),
                    Tag::Unassigned(headers::SIG_TAG),
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
            && (tag == None || tag.unwrap() == Tag::Unassigned(headers::SIG_TAG))
        {
            let r_len = type_info.1;
            let mut recipient: recipients::CoseRecipient;
            for _ in 0..r_len {
                recipient = recipients::CoseRecipient::new();
                recipient.context = CONTEXT_N.to_string();
                d.array()?;
                recipient.ph_bstr = common::ph_bstr(d.bytes())?;
                recipient.decode(&mut d)?;
                self.recipients.push(recipient);
            }
        } else if type_info.0 == Type::Bytes
            && (tag == None || tag.unwrap() == cbor::types::Tag::Unassigned(headers::SIG1_TAG))
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
    /// `recipient` parameter must be `None` if the type of the message is cose-ign1 and in case of
    /// being a cose-sign message a recipient of the message must be given here.
    pub fn decode(
        &mut self,
        external_aad: Option<Vec<u8>>,
        recipient: Option<recipients::CoseRecipient>,
    ) -> CoseResult {
        let aead = match external_aad {
            None => Vec::new(),
            Some(v) => v,
        };
        if self.recipients.len() <= 0 {
            if !self.verify {
                Err(CoseError::KeyDoesntSupportVerification())
            } else {
                assert!(sig_struct::verify_sig(
                    &self.pub_key,
                    &self.header.alg.ok_or(CoseError::MissingAlgorithm())?,
                    &aead,
                    CONTEXT,
                    &self.ph_bstr,
                    &Vec::new(),
                    &self.payload,
                    &self.signature
                )?);
                Ok(())
            }
        } else {
            let r = recipient.ok_or(CoseError::MissingRecipient())?;
            if !r.key_ops.contains(&keys::KEY_OPS_VERIFY) {
                return Err(CoseError::KeyDoesntSupportVerification());
            } else {
                r.verify(&self.payload, &aead, &self.ph_bstr)?;
            }
            Ok(())
        }
    }
}
