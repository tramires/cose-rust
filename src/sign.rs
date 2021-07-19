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

pub struct CoseSign {
    pub header: headers::CoseHeader,
    pub payload: Vec<u8>,
    signature: Vec<u8>,
    pub bytes: Vec<u8>,
    ph_bstr: Vec<u8>,
    pub_key: Vec<u8>,
    priv_key: Vec<u8>,
    sign: bool,
    verify: bool,
    pub recipients: Vec<recipients::CoseRecipient>,
}

impl CoseSign {
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

    pub fn add_header(&mut self, header: headers::CoseHeader) {
        self.header = header;
    }
    pub fn payload(&mut self, payload: Vec<u8>) {
        self.payload = payload;
    }

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

#[cfg(feature = "json")]
#[cfg(test)]
pub mod tests {
    use super::*;
    use hex;

    #[test]
    pub fn sign1() {
        let msg = b"signed message".to_vec();
        let mut sign1 = CoseSign::new();

        sign1.header.alg(algs::EDDSA, true, false);
        sign1.header.kid(b"kid2".to_vec(), true, false);
        sign1.payload(msg);

        let mut key = keys::CoseKey::new();
        key.kty(keys::EC2);
        key.alg(algs::EDDSA);
        key.crv(keys::ED25519);
        key.x(
            hex::decode("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
                .unwrap(),
        );
        key.d(
            hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
                .unwrap(),
        );
        key.key_ops(vec![keys::KEY_OPS_SIGN, keys::KEY_OPS_VERIFY]);

        sign1.key(&key).unwrap();

        sign1.gen_signature(None).unwrap();
        sign1.encode(true).unwrap();

        let mut verify = CoseSign::new();
        verify.bytes = sign1.bytes;
        verify.init_decoder(None).unwrap();

        verify.key(&key).unwrap();
        verify.decode(None, None).unwrap();
    }

    #[test]
    pub fn sign() {
        let msg = b"This is the content.".to_vec();
        let header = headers::CoseHeader::new();

        let mut sign = CoseSign::new();
        sign.add_header(header);
        sign.payload(msg);

        let r_kid = b"11".to_vec();
        let mut r_header = headers::CoseHeader::new();
        r_header.alg(algs::ES256, true, false);
        r_header.kid(r_kid.clone(), false, false);

        let mut r_key = keys::CoseKey::new();
        r_key.kty(keys::EC2);
        r_key.alg(algs::ES256);
        r_key.crv(keys::P_256);
        r_key.x(
            hex::decode("98f50a4ff6c05861c8860d13a638ea56c3f5ad7590bbfbf054e1c7b4d91d6280")
                .unwrap(),
        );
        r_key.d(
            hex::decode("02d1f7e6f26c43d4868d87ceb2353161740aacf1f7163647984b522a848df1c3")
                .unwrap(),
        );
        r_key.key_ops(vec![keys::KEY_OPS_SIGN, keys::KEY_OPS_VERIFY]);

        let mut recipient = recipients::CoseRecipient::new();
        recipient.add_header(r_header);
        recipient.key(&r_key).unwrap();
        sign.add_recipient(&mut recipient).unwrap();

        let r2_kid = b"12".to_vec();
        let mut r2_header = headers::CoseHeader::new();
        r2_header.alg(algs::EDDSA, true, false);
        r2_header.kid(r2_kid.clone(), false, false);

        let mut r2_key = keys::CoseKey::new();
        r2_key.kty(keys::OKP);
        r2_key.alg(algs::EDDSA);
        r2_key.crv(keys::ED25519);
        r2_key.x(
            hex::decode("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
                .unwrap(),
        );
        r2_key.d(
            hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
                .unwrap(),
        );
        r2_key.key_ops(vec![keys::KEY_OPS_SIGN, keys::KEY_OPS_VERIFY]);

        let mut recipient2 = recipients::CoseRecipient::new();
        recipient2.add_header(r2_header);
        recipient2.key(&r2_key).unwrap();
        sign.add_recipient(&mut recipient2).unwrap();

        sign.gen_signature(None).unwrap();
        sign.encode(true).unwrap();
        let res = sign.bytes;

        let mut verify = CoseSign::new();
        verify.bytes = res;
        verify.init_decoder(None).unwrap();

        let mut recipient = verify.get_recipient(&r_kid).unwrap();
        recipient.key(&r_key).unwrap();
        verify.decode(None, Some(recipient)).unwrap();

        let mut recipient2 = verify.get_recipient(&r2_kid).unwrap();
        recipient2.key(&r2_key).unwrap();
        verify.decode(None, Some(recipient2)).unwrap();
    }
}
