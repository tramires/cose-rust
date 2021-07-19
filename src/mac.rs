use crate::algs;
use crate::common;
use crate::errors::{CoseError, CoseResult, CoseResultWithRet};
use crate::headers;
use crate::keys;
use crate::mac_struct;
use crate::recipients;
use cbor::{decoder::DecodeError, types::Tag, types::Type, Config, Decoder, Encoder};
use std::io::Cursor;

pub const CONTEXT: &str = "MAC0";
pub const CONTEXT_N: &str = "MAC";

pub const SIZE: usize = 4;
pub const SIZE_N: usize = 5;

pub struct CoseMAC {
    pub header: headers::CoseHeader,
    tag: Vec<u8>,
    pub payload: Vec<u8>,
    pub bytes: Vec<u8>,
    ph_bstr: Vec<u8>,
    key: Vec<u8>,
    sign: bool,
    verify: bool,
    pub recipients: Vec<recipients::CoseRecipient>,
}

impl CoseMAC {
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

    pub fn add_header(&mut self, header: headers::CoseHeader) {
        self.header = header;
    }

    pub fn payload(&mut self, payload: Vec<u8>) {
        self.payload = payload;
    }

    pub fn add_recipient(&mut self, recipient: &mut recipients::CoseRecipient) -> CoseResult {
        recipient.context = CONTEXT_N.to_string();
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
    pub fn counter_sig(
        &self,
        external_aad: Option<Vec<u8>>,
        counter: &mut recipients::CoseRecipient,
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

    pub fn counters_verify(
        &self,
        external_aad: Option<Vec<u8>>,
        counter: &mut recipients::CoseRecipient,
    ) -> CoseResult {
        if self.tag.len() == 0 {
            Err(CoseError::MissingTag())
        } else {
            let aead = match external_aad {
                None => Vec::new(),
                Some(v) => v,
            };
            counter.verify(&self.tag, &aead, &self.ph_bstr)?;
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

    pub fn key(&mut self, cose_key: &keys::CoseKey) -> CoseResult {
        if self.recipients.len() > 0 {
            return Err(CoseError::InvalidOperationForContext(CONTEXT.to_string()));
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
            return Err(CoseError::KeyUnableToSignOrVerify());
        }
        Ok(())
    }
    pub fn gen_tag(&mut self, external_aad: Option<Vec<u8>>) -> CoseResult {
        if self.payload.len() <= 0 {
            return Err(CoseError::MissingPayload());
        }
        self.ph_bstr = self.header.get_protected_bstr()?;
        let aead = match external_aad {
            None => Vec::new(),
            Some(v) => v,
        };
        if self.recipients.len() <= 0 {
            if !algs::MAC_ALGS.contains(&self.header.alg.ok_or(CoseError::MissingAlgorithm())?) {
                Err(CoseError::InvalidAlgorithmForContext(CONTEXT.to_string()))
            } else if !self.sign {
                Err(CoseError::KeyDoesntSupportSigning())
            } else {
                self.tag = mac_struct::gen_mac(
                    &self.key,
                    &self.header.alg.unwrap(),
                    &aead,
                    CONTEXT,
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
                if !self.recipients[0].key_ops.contains(&keys::KEY_OPS_MAC) {
                    return Err(CoseError::KeyDoesntSupportEncryption());
                } else {
                    self.recipients[0].sign(&self.payload, &aead, &self.ph_bstr)?;
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
                    if algs::DIRECT
                        == self.recipients[i]
                            .header
                            .alg
                            .ok_or(CoseError::MissingAlgorithm())?
                        || [
                            algs::ECDH_ES_HKDF_256,
                            algs::ECDH_ES_HKDF_512,
                            algs::ECDH_SS_HKDF_256,
                            algs::ECDH_SS_HKDF_512,
                        ]
                        .contains(
                            self.recipients[i]
                                .header
                                .alg
                                .as_ref()
                                .ok_or(CoseError::MissingAlgorithm())?,
                        )
                    {
                        return Err(CoseError::AlgorithmOnlySupportsOneRecipient(
                            "direct/ECDH HKDF".to_string(),
                        ));
                    }
                    cek = self.recipients[i].derive_key(&cek.clone(), cek.len(), true)?;
                }
            }
            self.tag = mac_struct::gen_mac(
                &cek,
                &self.header.alg.unwrap(),
                &aead,
                CONTEXT,
                &self.ph_bstr,
                &self.payload,
            )?;
            Ok(())
        }
    }

    pub fn encode(&mut self, payload: bool) -> CoseResult {
        if self.recipients.len() <= 0 {
            let mut e = Encoder::new(Vec::new());
            e.tag(Tag::Unassigned(headers::MAC0_TAG))?;
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
            Ok(())
        } else {
            let mut e = Encoder::new(Vec::new());
            e.tag(Tag::Unassigned(headers::MAC_TAG))?;
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
            Ok(())
        }
    }

    pub fn init_decoder(&mut self) -> CoseResult {
        let input = Cursor::new(self.bytes.clone());
        let mut d = Decoder::new(Config::default(), input);
        let mut tag: Option<Tag> = None;

        match d.tag() {
            Ok(v) => {
                if ![
                    Tag::Unassigned(headers::MAC0_TAG),
                    Tag::Unassigned(headers::MAC_TAG),
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

        if !is_mac0 && (tag == None || tag.unwrap() == Tag::Unassigned(headers::MAC_TAG)) {
            let mut recipient: recipients::CoseRecipient;
            for _ in 0..r_len {
                recipient = recipients::CoseRecipient::new();
                recipient.context = CONTEXT_N.to_string();
                d.array()?;
                recipient.ph_bstr = common::ph_bstr(d.bytes())?;
                recipient.decode(&mut d)?;
                self.recipients.push(recipient);
            }
        } else if is_mac0 && (tag == None || tag.unwrap() == Tag::Unassigned(headers::MAC0_TAG)) {
            if self.tag.len() <= 0 {
                return Err(CoseError::MissingTag());
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
                return Err(CoseError::KeyUnableToSignOrVerify());
            } else {
                assert!(mac_struct::verify_mac(
                    &self.key,
                    &self.header.alg.ok_or(CoseError::MissingAlgorithm())?,
                    &aead,
                    CONTEXT,
                    &self.ph_bstr,
                    &self.tag,
                    &self.payload,
                )?);
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
                    return Err(CoseError::KeyUnableToSignOrVerify());
                } else {
                    r.verify(&self.tag, &aead, &self.ph_bstr)?;
                    return Ok(());
                }
            } else {
                cek = r.derive_key(&r.payload.clone(), size, false)?;
            }
            assert!(mac_struct::verify_mac(
                &cek,
                &self.header.alg.unwrap(),
                &aead,
                CONTEXT,
                &self.ph_bstr,
                &self.tag,
                &self.payload,
            )?);
        }
        Ok(())
    }
}

#[cfg(feature = "json")]
#[cfg(test)]
pub mod tests {
    use super::*;
    use hex;

    #[test]
    pub fn mac0() {
        let msg = b"signed message".to_vec();
        let kid = b"kid2".to_vec();
        let alg = algs::AES_MAC_256_128;
        let k = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F";

        let mut header = headers::CoseHeader::new();
        header.alg(alg, true, false);
        header.kid(kid, true, false);

        let mut key = keys::CoseKey::new();
        key.kty(keys::SYMMETRIC);
        key.alg(algs::AES_MAC_256_128);
        key.k(k.to_vec());
        key.key_ops(vec![keys::KEY_OPS_MAC, keys::KEY_OPS_MAC_VERIFY]);

        let mut mac0 = CoseMAC::new();
        mac0.add_header(header);
        mac0.payload(msg);
        mac0.key(&key).unwrap();

        mac0.gen_tag(None).unwrap();
        mac0.encode(true).unwrap();
        let res = mac0.bytes;

        let mut verify = CoseMAC::new();
        verify.bytes = res;
        verify.init_decoder().unwrap();

        verify.key(&key).unwrap();
        verify.decode(None, None).unwrap();
    }

    #[test]
    pub fn direct_agree_mac() {
        let msg = b"This is the content.".to_vec();

        let mut header = headers::CoseHeader::new();
        header.alg(algs::AES_MAC_256_128, true, false);

        let mut mac = CoseMAC::new();
        mac.add_header(header);
        mac.payload(msg);

        let r_kid = b"11".to_vec();
        let mut r_header = headers::CoseHeader::new();
        r_header.alg(algs::ECDH_ES_A192KW, true, false);
        r_header.kid(r_kid.clone(), false, false);
        r_header.salt(vec![0; 32], false, false);

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

        let mut recipient = recipients::CoseRecipient::new();
        recipient.add_header(r_header);
        recipient.key(&r_key).unwrap();

        r_key.d(
            hex::decode("aff907c99f9ad3aae6c4cdf21122bce2bd68b5283e6907154ad911840fa208cf")
                .unwrap(),
        );
        r_key.x(
            hex::decode("65eda5a12577c2bae829437fe338701a10aaa375e1bb5b5de108de439c08551d")
                .unwrap(),
        );
        r_key.key_ops(vec![keys::KEY_OPS_DERIVE]);

        recipient
            .header
            .static_key_id(r_kid.clone(), &r_key, true, true);

        mac.add_recipient(&mut recipient).unwrap();

        mac.gen_tag(None).unwrap();
        mac.encode(true).unwrap();
        let res = mac.bytes;

        let mut demac = CoseMAC::new();
        demac.bytes = res;
        demac.init_decoder().unwrap();

        let mut recipient = demac.get_recipient(&r_kid).unwrap();

        r_key.x(
            hex::decode("65eda5a12577c2bae829437fe338701a10aaa375e1bb5b5de108de439c08551d")
                .unwrap(),
        );
        r_key.x(
            hex::decode("98f50a4ff6c05861c8860d13a638ea56c3f5ad7590bbfbf054e1c7b4d91d6280")
                .unwrap(),
        );
        r_key.d(
            hex::decode("02d1f7e6f26c43d4868d87ceb2353161740aacf1f7163647984b522a848df1c3")
                .unwrap(),
        );
        r_key.key_ops(vec![keys::KEY_OPS_DERIVE]);
        recipient.key(&r_key).unwrap();

        r_key.d(
            hex::decode("aff907c99f9ad3aae6c4cdf21122bce2bd68b5283e6907154ad911840fa208cf")
                .unwrap(),
        );
        r_key.x(
            hex::decode("65eda5a12577c2bae829437fe338701a10aaa375e1bb5b5de108de439c08551d")
                .unwrap(),
        );
        r_key.key_ops(vec![keys::KEY_OPS_DERIVE]);

        recipient
            .header
            .static_key_id(r_kid.clone(), &r_key, true, false);

        demac.decode(None, Some(recipient)).unwrap();
    }
}
