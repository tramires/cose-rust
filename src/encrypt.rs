use crate::algs;
use crate::common;
use crate::enc_struct;
use crate::errors::{CoseError, CoseResult, CoseResultWithRet};
use crate::headers;
use crate::keys;
use crate::recipients;
use cbor::{Config, Decoder, Encoder};
use std::io::Cursor;

pub const CONTEXT: &str = "Encrypt0";
pub const CONTEXT_N: &str = "Encrypt";

pub const SIZE: usize = 3;
pub const SIZE_N: usize = 4;

pub struct CoseEncrypt {
    pub header: headers::CoseHeader,
    ciphertext: Vec<u8>,
    payload: Vec<u8>,
    pub bytes: Vec<u8>,
    ph_bstr: Vec<u8>,
    key: Vec<u8>,
    enc: bool,
    dec: bool,
    pub recipients: Vec<recipients::CoseRecipient>,
}

impl CoseEncrypt {
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

    pub fn add_header(&mut self, header: headers::CoseHeader) {
        self.header = header;
    }

    pub fn payload(&mut self, payload: Vec<u8>) {
        self.payload = payload;
    }

    pub fn add_recipient(&mut self, recipient: &mut recipients::CoseRecipient) -> CoseResult {
        recipient.context = CONTEXT_N.to_string();
        if !algs::KEY_DISTRIBUTION_ALGS
            .contains(&recipient.header.alg.ok_or(CoseError::MissingAlgorithm())?)
        {
            return Err(CoseError::InvalidAlgorithmForContext(CONTEXT_N.to_string()));
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

    pub fn gen_ciphertext(&mut self, external_aad: Option<Vec<u8>>) -> CoseResult {
        if self.payload.len() <= 0 {
            return Err(CoseError::MissingPayload());
        }
        self.ph_bstr = self.header.get_protected_bstr()?;
        let aead = match external_aad {
            None => Vec::new(),
            Some(v) => v,
        };
        if self.recipients.len() <= 0 {
            if !algs::ENCRYPT_ALGS.contains(&self.header.alg.ok_or(CoseError::MissingAlgorithm())?)
            {
                Err(CoseError::InvalidAlgorithmForContext(CONTEXT.to_string()))
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
                    CONTEXT,
                    &self.ph_bstr,
                    &self.payload,
                )?;
                Ok(())
            }
        //SIGN
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
                CONTEXT,
                &self.ph_bstr,
                &self.payload,
            )?;
            Ok(())
        }
    }

    pub fn encode(&mut self, ciphertext: bool) -> CoseResult {
        if self.recipients.len() <= 0 {
            if self.ciphertext.len() <= 0 {
                Err(CoseError::MissingSignature())
            } else {
                let mut e = Encoder::new(Vec::new());
                e.tag(cbor::types::Tag::Unassigned(headers::ENC0_TAG))?;
                e.array(SIZE)?;
                e.bytes(self.ph_bstr.as_slice())?;
                self.header.encode_unprotected(&mut e)?;
                if ciphertext {
                    e.bytes(self.ciphertext.as_slice())?;
                } else {
                    e.null()?;
                }
                self.bytes = e.into_writer().to_vec();
                Ok(())
            }
        } else {
            let mut e = Encoder::new(Vec::new());
            e.tag(cbor::types::Tag::Unassigned(headers::ENC_TAG))?;
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
            Ok(())
        }
    }

    pub fn init_decoder(&mut self) -> CoseResult {
        let input = Cursor::new(self.bytes.clone());
        let mut decoder = Decoder::new(Config::default(), input);
        let mut tag: Option<cbor::types::Tag> = None;

        match decoder.tag() {
            Ok(v) => {
                if ![
                    cbor::types::Tag::Unassigned(headers::ENC0_TAG),
                    cbor::types::Tag::Unassigned(headers::ENC_TAG),
                ]
                .contains(&v)
                {
                    return Err(CoseError::InvalidTag());
                } else {
                    tag = Some(v);
                    decoder.array()?;
                }
            }
            Err(ref err) => match err {
                cbor::decoder::DecodeError::UnexpectedType { datatype, info } => {
                    if *datatype != cbor::types::Type::Array && *info != SIZE as u8 {
                        return Err(CoseError::InvalidCoseStructure());
                    }
                }
                _ => {
                    return Err(CoseError::InvalidCoseStructure());
                }
            },
        };

        self.ph_bstr = common::ph_bstr(decoder.bytes())?;
        if self.ph_bstr.len() > 0 {
            self.header.decode_protected_bstr(&self.ph_bstr)?;
        }
        self.header.decode_unprotected(&mut decoder, false)?;

        self.ciphertext = decoder.bytes()?.to_vec();
        if self.ciphertext.len() <= 0 {
            return Err(CoseError::MissingCiphertext());
        }

        let mut r_len = 0;
        let is_enc0 = match decoder.array() {
            Ok(v) => {
                r_len = v;
                false
            }
            Err(_) => true,
        };

        if !is_enc0
            && (tag == None || tag.unwrap() == cbor::types::Tag::Unassigned(headers::ENC_TAG))
        {
            let mut recipient: recipients::CoseRecipient;
            for _ in 0..r_len {
                recipient = recipients::CoseRecipient::new();
                recipient.context = CONTEXT_N.to_string();
                decoder.array()?;
                recipient.ph_bstr = common::ph_bstr(decoder.bytes())?;
                recipient.decode(&mut decoder)?;
                self.recipients.push(recipient);
            }
        } else if is_enc0
            && (tag == None || tag.unwrap() == cbor::types::Tag::Unassigned(headers::ENC0_TAG))
        {
            if self.ciphertext.len() <= 0 {
                return Err(CoseError::MissingCiphertext());
            }
        }
        Ok(())
    }
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
                    CONTEXT,
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
                CONTEXT,
                &self.ph_bstr,
                &self.ciphertext,
            )?)
        }
    }
}
#[cfg(feature = "json")]
#[cfg(test)]
pub mod tests {
    use super::*;
    use hex;

    #[test]
    pub fn enc0() {
        /////////////////////////////////////////// ENCRYPTER ////////////////////////////////////

        let msg = b"signed message".to_vec();
        let kid = b"kid2".to_vec();
        let alg = algs::CHACHA20;
        let k = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F";
        let iv = b"\x00\x01\x02\x03\x04\x05\x06\x07\x00\x01\x02\x03";

        //HEADER
        let mut header = headers::CoseHeader::new();
        header.alg(alg, true, false);
        header.kid(kid, true, false);
        header.iv(iv.to_vec(), true, false);

        //KEY
        let mut key = keys::CoseKey::new();
        key.kty(keys::SYMMETRIC);
        key.alg(algs::CHACHA20);
        key.k(k.to_vec());
        key.key_ops(vec![keys::KEY_OPS_ENCRYPT, keys::KEY_OPS_DECRYPT]);

        //INIT ENCRYPT0 MESSAGE
        let mut enc0 = CoseEncrypt::new();
        enc0.add_header(header);
        enc0.payload(msg);
        enc0.key(&key).unwrap();

        //GENERATE ENCRYPT0 MESSAGE
        enc0.gen_ciphertext(None).unwrap();
        enc0.encode(true).unwrap();
        let res = enc0.bytes;

        /////////////////////////////////////////// DECRYPTER ////////////////////////////////////

        //DECODE ENCRYPT0 MESSAGE
        let mut dec0 = CoseEncrypt::new();
        dec0.bytes = res;
        dec0.init_decoder().unwrap();

        //DECRYPT MESSAGE
        dec0.key(&key).unwrap();
        let resp = dec0.decode(None, None).unwrap();
        assert_eq!(resp, b"signed message".to_vec());
    }
    #[test]
    pub fn enc() {
        /////////////////////////////////////////// ENCRYPTER ////////////////////////////////////

        let msg = b"This is the content.".to_vec();
        let k = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F";
        let iv = b"\x00\x01\x02\x03\x04\x05\x06\x07\x00\x01\x02\x03";

        //HEADER
        let mut header = headers::CoseHeader::new();
        header.alg(algs::A256GCM, true, false);
        header.iv(iv.to_vec(), true, false);

        //INIT ENCRYPT MESSAGE
        let mut enc = CoseEncrypt::new();
        enc.add_header(header);
        enc.payload(msg);

        /////////////////////////////////////////

        //RECIPIENT HEADER
        let r_kid = b"11".to_vec();
        let mut r_header = headers::CoseHeader::new();
        r_header.alg(algs::DIRECT_HKDF_SHA_256, true, false);
        r_header.iv(iv.to_vec(), true, false);
        r_header.kid(r_kid.clone(), false, false);
        r_header.salt(vec![0; 32], false, false);

        //RECIPIENT KEY
        let mut r_key = keys::CoseKey::new();
        r_key.kty(keys::SYMMETRIC);
        r_key.alg(algs::CHACHA20);
        r_key.k(k.to_vec());
        r_key.key_ops(vec![keys::KEY_OPS_WRAP, keys::KEY_OPS_UNWRAP]);

        //INIT RECIPIENT AND ADD
        let mut recipient = recipients::CoseRecipient::new();
        recipient.add_header(r_header);
        recipient.key(&r_key).unwrap();
        enc.add_recipient(&mut recipient).unwrap();

        //GENERATE ENCRYPT MESSAGE
        enc.gen_ciphertext(None).unwrap();
        enc.encode(true).unwrap();
        let res = enc.bytes;

        /////////////////////////////////////////// DECYRPTER ////////////////////////////////////

        //DECODE ENCRYPT MESSAGE
        let mut dec = CoseEncrypt::new();
        dec.bytes = res;
        dec.init_decoder().unwrap();

        //GET RECIPIENT
        let mut recipient = dec.get_recipient(&r_kid).unwrap();

        //ADD KEY TO RECIPIENT
        recipient.key(&r_key).unwrap();

        //DECRYPT MESSAGE
        let resp_1 = dec.decode(None, Some(recipient)).unwrap();
        assert_eq!(resp_1, b"This is the content.".to_vec());
    }
    #[test]
    pub fn direct_agree_enc() {
        /////////////////////////////////////////// ENCRYPTER ////////////////////////////////////

        let msg = b"This is the content.".to_vec();
        let iv = b"\x00\x01\x02\x03\x04\x05\x06\x07\x00\x01\x02\x03";

        //HEADER
        let mut header = headers::CoseHeader::new();
        header.alg(algs::A256GCM, true, false);
        header.iv(iv.to_vec(), true, false);

        //INIT ENCRYPT MESSAGE
        let mut enc = CoseEncrypt::new();
        enc.add_header(header);
        enc.payload(msg);

        //////////////////////////////////////////

        //RECIPIENT HEADER
        let r_kid = b"11".to_vec();
        let mut r_header = headers::CoseHeader::new();
        r_header.alg(algs::ECDH_ES_A192KW, true, false);
        r_header.iv(iv.to_vec(), true, false);
        r_header.kid(r_kid.clone(), false, false);
        r_header.salt(vec![0; 32], false, false);

        //RECIPIENT KEY
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

        //INIT RECIPIENT
        let mut recipient = recipients::CoseRecipient::new();
        recipient.add_header(r_header);
        recipient.key(&r_key).unwrap();

        //SENDER EPHEMERAL KEY
        r_key.d(
            hex::decode("aff907c99f9ad3aae6c4cdf21122bce2bd68b5283e6907154ad911840fa208cf")
                .unwrap(),
        );
        r_key.x(
            hex::decode("65eda5a12577c2bae829437fe338701a10aaa375e1bb5b5de108de439c08551d")
                .unwrap(),
        );
        r_key.key_ops(vec![keys::KEY_OPS_DERIVE]);
        //TODO CHECK ERROR IN PROTECTED
        recipient.header.ephemeral_key(&r_key, true, false);

        //ADD RECIPIENT
        enc.add_recipient(&mut recipient).unwrap();

        //GENERATE ENCRYPT MESSAGE
        enc.gen_ciphertext(None).unwrap();
        enc.encode(true).unwrap();
        let res = enc.bytes;

        /////////////////////////////////////////// DECRYPTER ////////////////////////////////////

        //DECODE ENRYPT MESSAGE
        let mut dec = CoseEncrypt::new();
        dec.bytes = res;
        dec.init_decoder().unwrap();

        //GET RECIPIENT
        let mut recipient = dec.get_recipient(&r_kid).unwrap();

        //RECIPIENT KEY
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

        //DECRYPT MESSAGE
        let resp_1 = dec.decode(None, Some(recipient)).unwrap();
        assert_eq!(resp_1, b"This is the content.".to_vec());
    }
}
