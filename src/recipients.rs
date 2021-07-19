use crate::algs;
use crate::enc_struct;
use crate::errors::{CoseError, CoseResult, CoseResultWithRet};
use crate::headers;
use crate::kdf_struct;
use crate::keys;
use crate::sig_struct;
use cbor::{Decoder, Encoder};
use std::io::Cursor;

#[derive(Clone)]
pub struct CoseRecipient {
    pub header: headers::CoseHeader,
    pub payload: Vec<u8>,
    pub(in crate) ph_bstr: Vec<u8>,
    pub pub_key: Vec<u8>,
    pub s_key: Vec<u8>,
    pub(in crate) context: String,
    pub(in crate) crv: Option<i32>,
    pub(in crate) key_ops: Vec<i32>,
}

pub const COUNTER_CONTEXT: &str = "CounterSignature";
pub const SIZE: usize = 3;

impl CoseRecipient {
    pub fn new() -> CoseRecipient {
        CoseRecipient {
            header: headers::CoseHeader::new(),
            payload: Vec::new(),
            ph_bstr: Vec::new(),
            pub_key: Vec::new(),
            key_ops: Vec::new(),
            s_key: Vec::new(),
            crv: None,
            context: "".to_string(),
        }
    }
    pub fn new_counter_sig() -> CoseRecipient {
        CoseRecipient {
            header: headers::CoseHeader::new(),
            payload: Vec::new(),
            ph_bstr: Vec::new(),
            pub_key: Vec::new(),
            key_ops: Vec::new(),
            s_key: Vec::new(),
            crv: None,
            context: COUNTER_CONTEXT.to_string(),
        }
    }

    pub fn add_header(&mut self, header: headers::CoseHeader) {
        self.header = header;
    }

    pub fn key(&mut self, key: &keys::CoseKey) -> CoseResult {
        let alg = self
            .header
            .alg
            .as_ref()
            .ok_or(CoseError::MissingAlgorithm())?;
        if algs::SIGNING_ALGS.contains(alg) {
            if key.key_ops.contains(&keys::KEY_OPS_SIGN) {
                self.s_key = key.get_s_key()?;
            }
            if key.key_ops.contains(&keys::KEY_OPS_VERIFY) {
                self.pub_key = key.get_pub_key(*alg)?;
            }
        } else if algs::KEY_DISTRIBUTION_ALGS.contains(alg) || algs::ENCRYPT_ALGS.contains(alg) {
            if key.key_ops.contains(&keys::KEY_OPS_DERIVE_BITS)
                || key.key_ops.contains(&keys::KEY_OPS_DERIVE)
                || key.key_ops.contains(&keys::KEY_OPS_DECRYPT)
                || key.key_ops.contains(&keys::KEY_OPS_ENCRYPT)
                || key.key_ops.contains(&keys::KEY_OPS_WRAP)
                || key.key_ops.contains(&keys::KEY_OPS_UNWRAP)
            {
                self.s_key = key.get_s_key()?;
            }
            if algs::ECDH_ALGS.contains(alg) {
                if key.key_ops.len() == 0 {
                    self.pub_key = key.get_pub_key(alg.clone())?;
                }
            }
        }
        self.crv = key.crv;
        self.key_ops = key.key_ops.clone();
        Ok(())
    }
    pub fn enc(
        &mut self,
        content: &Vec<u8>,
        external_aad: &Vec<u8>,
        body_protected: &Vec<u8>,
        alg: &i32,
        iv: &Vec<u8>,
    ) -> CoseResultWithRet<Vec<u8>> {
        if !self.key_ops.contains(&keys::KEY_OPS_ENCRYPT) {
            return Err(CoseError::KeyDoesntSupportSigning());
        }
        Ok(enc_struct::gen_cipher(
            &self.s_key,
            alg,
            iv,
            &external_aad,
            &self.context,
            &body_protected,
            &content,
        )?)
    }
    pub fn dec(
        &self,
        content: &Vec<u8>,
        external_aad: &Vec<u8>,
        body_protected: &Vec<u8>,
        alg: &i32,
        iv: &Vec<u8>,
    ) -> CoseResultWithRet<Vec<u8>> {
        if !self.key_ops.contains(&keys::KEY_OPS_DECRYPT) {
            return Err(CoseError::KeyDoesntSupportVerification());
        }
        Ok(enc_struct::dec_cipher(
            &self.s_key,
            alg,
            iv,
            &external_aad,
            &self.context,
            &body_protected,
            &content,
        )?)
    }

    pub fn sign(
        &mut self,
        content: &Vec<u8>,
        external_aad: &Vec<u8>,
        body_protected: &Vec<u8>,
    ) -> CoseResult {
        self.ph_bstr = self.header.get_protected_bstr()?;
        if !self.key_ops.contains(&keys::KEY_OPS_SIGN) {
            return Err(CoseError::KeyDoesntSupportSigning());
        }
        self.payload = sig_struct::gen_sig(
            &self.s_key,
            &self.header.alg.ok_or(CoseError::MissingAlgorithm())?,
            &external_aad,
            &self.context,
            &body_protected,
            &self.ph_bstr,
            &content,
        )?;
        Ok(())
    }
    pub fn verify(
        &self,
        content: &Vec<u8>,
        external_aad: &Vec<u8>,
        body_protected: &Vec<u8>,
    ) -> CoseResult {
        if !self.key_ops.contains(&keys::KEY_OPS_VERIFY) {
            return Err(CoseError::KeyDoesntSupportVerification());
        }
        assert!(sig_struct::verify_sig(
            &self.pub_key,
            &self.header.alg.ok_or(CoseError::MissingAlgorithm())?,
            &external_aad,
            &self.context,
            &body_protected,
            &self.ph_bstr,
            &content,
            &self.payload,
        )?);
        Ok(())
    }

    pub fn add_signature(&mut self, signature: Vec<u8>) -> CoseResult {
        if self.context != COUNTER_CONTEXT {
            return Err(CoseError::FunctionOnlyAvailableForContext(
                COUNTER_CONTEXT.to_string(),
            ));
        }
        self.payload = signature;
        Ok(())
    }

    pub fn get_to_sign(
        &mut self,
        content: &Vec<u8>,
        external_aad: &Vec<u8>,
        body_protected: &Vec<u8>,
    ) -> CoseResultWithRet<Vec<u8>> {
        if self.context != COUNTER_CONTEXT {
            return Err(CoseError::FunctionOnlyAvailableForContext(
                COUNTER_CONTEXT.to_string(),
            ));
        }
        self.ph_bstr = self.header.get_protected_bstr()?;
        sig_struct::get_to_sign(
            &external_aad,
            COUNTER_CONTEXT,
            &body_protected,
            &self.ph_bstr,
            &content,
        )
    }

    pub fn derive_key(
        &mut self,
        cek: &Vec<u8>,
        size: usize,
        sender: bool,
    ) -> CoseResultWithRet<Vec<u8>> {
        if self.ph_bstr.len() <= 0 {
            self.ph_bstr = self.header.get_protected_bstr()?;
        }
        if [algs::A128KW, algs::A192KW, algs::A256KW].contains(
            self.header
                .alg
                .as_ref()
                .ok_or(CoseError::MissingAlgorithm())?,
        ) {
            if sender {
                self.payload = algs::aes_key_wrap(&self.s_key, size, &cek)?;
            } else {
                return Ok(algs::aes_key_unwrap(&self.s_key, size, &cek)?);
            }
            return Ok(cek.to_vec());
        } else if [algs::DIRECT_HKDF_AES_128, algs::DIRECT_HKDF_AES_256].contains(
            self.header
                .alg
                .as_ref()
                .ok_or(CoseError::MissingAlgorithm())?,
        ) {
            return Err(CoseError::NotImplemented(
                "DIRECT HKDF AES-128/AES-256".to_string(),
            ));
        } else if [algs::DIRECT_HKDF_SHA_256, algs::DIRECT_HKDF_SHA_512].contains(
            self.header
                .alg
                .as_ref()
                .ok_or(CoseError::MissingAlgorithm())?,
        ) {
            let salt;
            if self.header.party_u_nonce == None {
                salt = Some(
                    self.header
                        .salt
                        .as_ref()
                        .ok_or(CoseError::MissingAlgorithm())?,
                );
            } else {
                salt = Some(
                    self.header
                        .party_u_nonce
                        .as_ref()
                        .ok_or(CoseError::MissingAlgorithm())?,
                );
            }
            let mut kdf_context = kdf_struct::gen_kdf(
                self.header
                    .alg
                    .as_ref()
                    .ok_or(CoseError::MissingAlgorithm())?,
                self.header.party_u_identity.clone(),
                self.header.party_u_nonce.clone(),
                self.header.party_u_other.clone(),
                self.header.party_v_identity.clone(),
                self.header.party_v_nonce.clone(),
                self.header.party_v_other.clone(),
                size as u16 * 8,
                self.ph_bstr.clone(),
                None,
                None,
            )?;
            return Ok(algs::hkdf(
                size,
                &self.s_key,
                salt,
                &mut kdf_context,
                self.header.alg.unwrap(),
            )?);
        } else if [
            algs::ECDH_ES_HKDF_256,
            algs::ECDH_ES_HKDF_512,
            algs::ECDH_SS_HKDF_256,
            algs::ECDH_SS_HKDF_512,
        ]
        .contains(
            self.header
                .alg
                .as_ref()
                .ok_or(CoseError::MissingAlgorithm())?,
        ) {
            let (salt, receiver_key, sender_key, crv_rec, crv_send);
            if self.header.party_u_nonce == None {
                salt = Some(
                    self.header
                        .salt
                        .as_ref()
                        .ok_or(CoseError::MissingAlgorithm())?,
                );
            } else {
                salt = Some(
                    self.header
                        .party_u_nonce
                        .as_ref()
                        .ok_or(CoseError::MissingAlgorithm())?,
                );
            }

            if sender {
                receiver_key = self.pub_key.clone();
                sender_key = self.header.ecdh_key.get_s_key()?;
                crv_rec = self.crv.unwrap();
                crv_send = self.header.ecdh_key.crv.unwrap();
            } else {
                receiver_key = self.header.ecdh_key.get_pub_key(self.header.alg.unwrap())?;
                sender_key = self.s_key.clone();
                crv_send = self.crv.unwrap();
                crv_rec = self.header.ecdh_key.crv.unwrap();
            }
            let shared = algs::ecdh_derive_key(&crv_rec, &crv_send, &receiver_key, &sender_key)?;

            let mut kdf_context = kdf_struct::gen_kdf(
                self.header
                    .alg
                    .as_ref()
                    .ok_or(CoseError::MissingAlgorithm())?,
                self.header.party_u_identity.clone(),
                self.header.party_u_nonce.clone(),
                self.header.party_u_other.clone(),
                self.header.party_v_identity.clone(),
                self.header.party_v_nonce.clone(),
                self.header.party_v_other.clone(),
                size as u16 * 8,
                self.ph_bstr.clone(),
                None,
                None,
            )?;
            return Ok(algs::hkdf(
                size,
                &shared,
                salt,
                &mut kdf_context,
                self.header.alg.unwrap(),
            )?);
        } else if [
            algs::ECDH_ES_A128KW,
            algs::ECDH_ES_A192KW,
            algs::ECDH_ES_A256KW,
            algs::ECDH_SS_A128KW,
            algs::ECDH_SS_A192KW,
            algs::ECDH_SS_A256KW,
        ]
        .contains(
            self.header
                .alg
                .as_ref()
                .ok_or(CoseError::MissingAlgorithm())?,
        ) {
            let (salt, receiver_key, sender_key, crv_rec, crv_send);
            if self.header.party_u_nonce == None {
                salt = Some(
                    self.header
                        .salt
                        .as_ref()
                        .ok_or(CoseError::MissingAlgorithm())?,
                );
            } else {
                salt = Some(
                    self.header
                        .party_u_nonce
                        .as_ref()
                        .ok_or(CoseError::MissingAlgorithm())?,
                );
            }
            if sender {
                receiver_key = self.pub_key.clone();
                sender_key = self.header.ecdh_key.get_s_key()?;
                crv_rec = self.crv.unwrap();
                crv_send = self.header.ecdh_key.crv.unwrap();
            } else {
                receiver_key = self.header.ecdh_key.get_pub_key(self.header.alg.unwrap())?;
                sender_key = self.s_key.clone();
                crv_send = self.crv.unwrap();
                crv_rec = self.header.ecdh_key.crv.unwrap();
            }
            let shared = algs::ecdh_derive_key(&crv_rec, &crv_send, &receiver_key, &sender_key)?;

            let mut kdf_context = kdf_struct::gen_kdf(
                self.header
                    .alg
                    .as_ref()
                    .ok_or(CoseError::MissingAlgorithm())?,
                self.header.party_u_identity.clone(),
                self.header.party_u_nonce.clone(),
                self.header.party_u_other.clone(),
                self.header.party_v_identity.clone(),
                self.header.party_v_nonce.clone(),
                self.header.party_v_other.clone(),
                size as u16 * 8,
                self.ph_bstr.clone(),
                None,
                None,
            )?;
            let kek = algs::hkdf(
                size,
                &shared,
                salt,
                &mut kdf_context,
                self.header.alg.unwrap(),
            )?;
            if sender {
                self.payload = algs::aes_key_wrap(&kek, size, &cek)?;
            } else {
                return Ok(algs::aes_key_unwrap(&kek, size, &cek)?);
            }
            return Ok(cek.to_vec());
        } else {
            return Err(CoseError::InvalidCoseStructure());
        }
    }

    pub fn decode(&mut self, d: &mut Decoder<Cursor<Vec<u8>>>) -> CoseResult {
        self.header.decode_protected_bstr(&self.ph_bstr)?;
        self.header.decode_unprotected(d, true)?;
        self.payload = d.bytes()?;
        Ok(())
    }

    pub fn encode(&mut self, e: &mut Encoder<Vec<u8>>) -> CoseResult {
        e.array(SIZE)?;
        e.bytes(&self.ph_bstr)?;
        self.header.encode_unprotected(e)?;
        e.bytes(&self.payload)?;
        Ok(())
    }
}

#[cfg(feature = "json")]
#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::sign;
    use hex;

    #[test]
    pub fn counter_sigs() {
        let msg = b"signed message".to_vec();
        let kid = b"kid2".to_vec();
        let alg = algs::EDDSA;

        let mut header = headers::CoseHeader::new();
        header.alg(alg, true, false);
        header.kid(kid, true, false);

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

        let mut sign1 = sign::CoseSign::new();
        sign1.add_header(header);
        sign1.payload(msg);
        sign1.key(&key).unwrap();
        sign1.gen_signature(None).unwrap();

        let mut counter = CoseRecipient::new_counter_sig();
        let mut counter_header = headers::CoseHeader::new();
        counter_header.kid([0].to_vec(), true, false);
        counter_header.alg(algs::ES256, true, false);
        counter.add_header(counter_header);

        let mut cose_key = keys::CoseKey::new();
        cose_key.kty(keys::EC2);
        cose_key.alg(algs::ES256);
        cose_key.crv(keys::P_256);
        cose_key.x(
            hex::decode("98f50a4ff6c05861c8860d13a638ea56c3f5ad7590bbfbf054e1c7b4d91d6280")
                .unwrap(),
        );
        cose_key.y(
            hex::decode("f01400b089867804b8e9fc96c3932161f1934f4223069170d924b7e03bf822bb")
                .unwrap(),
        );
        cose_key.d(
            hex::decode("02d1f7e6f26c43d4868d87ceb2353161740aacf1f7163647984b522a848df1c3")
                .unwrap(),
        );
        cose_key.key_ops(vec![keys::KEY_OPS_SIGN]);
        counter.key(&cose_key).unwrap();

        sign1.counter_sig(None, &mut counter).unwrap();
        sign1.add_counter_sig(counter).unwrap();

        let mut counter = CoseRecipient::new_counter_sig();
        let mut counter_header = headers::CoseHeader::new();
        counter_header.alg(algs::ES256, true, false);
        counter_header.kid([1].to_vec(), true, false);
        counter.add_header(counter_header);

        let mut cose_key = keys::CoseKey::new();
        cose_key.kty(keys::EC2);
        cose_key.alg(algs::ES256);
        cose_key.crv(keys::P_256);
        cose_key.x(
            hex::decode("98f50a4ff6c05861c8860d13a638ea56c3f5ad7590bbfbf054e1c7b4d91d6280")
                .unwrap(),
        );
        cose_key.y(
            hex::decode("f01400b089867804b8e9fc96c3932161f1934f4223069170d924b7e03bf822bb")
                .unwrap(),
        );
        cose_key.d(
            hex::decode("02d1f7e6f26c43d4868d87ceb2353161740aacf1f7163647984b522a848df1c3")
                .unwrap(),
        );
        cose_key.key_ops(vec![keys::KEY_OPS_SIGN]);
        counter.key(&cose_key).unwrap();

        sign1.counter_sig(None, &mut counter).unwrap();
        sign1.add_counter_sig(counter).unwrap();

        let mut counter = CoseRecipient::new_counter_sig();
        let mut counter_header = headers::CoseHeader::new();
        counter_header.alg(algs::ES256, true, false);
        counter_header.kid([2].to_vec(), true, false);
        counter.add_header(counter_header);

        let mut cose_key = keys::CoseKey::new();
        cose_key.kty(keys::EC2);
        cose_key.alg(algs::ES256);
        cose_key.crv(keys::P_256);
        cose_key.x(
            hex::decode("98f50a4ff6c05861c8860d13a638ea56c3f5ad7590bbfbf054e1c7b4d91d6280")
                .unwrap(),
        );
        cose_key.y(
            hex::decode("f01400b089867804b8e9fc96c3932161f1934f4223069170d924b7e03bf822bb")
                .unwrap(),
        );
        cose_key.d(
            hex::decode("02d1f7e6f26c43d4868d87ceb2353161740aacf1f7163647984b522a848df1c3")
                .unwrap(),
        );
        cose_key.key_ops(vec![keys::KEY_OPS_SIGN]);
        counter.key(&cose_key).unwrap();

        sign1.counter_sig(None, &mut counter).unwrap();
        sign1.add_counter_sig(counter).unwrap();

        let mut counter = CoseRecipient::new_counter_sig();
        let mut counter_header = headers::CoseHeader::new();
        counter_header.alg(algs::ES256, true, false);
        counter_header.kid([3].to_vec(), true, false);
        counter.add_header(counter_header);

        let to_sign = sign1.get_to_sign(None, &mut counter).unwrap();

        let counter_priv_key3 =
            hex::decode("02d1f7e6f26c43d4868d87ceb2353161740aacf1f7163647984b522a848df1c3")
                .unwrap();

        let signature =
            algs::sign(counter.header.alg.unwrap(), &counter_priv_key3, &to_sign).unwrap();
        counter.add_signature(signature).unwrap();
        sign1.add_counter_sig(counter).unwrap();

        sign1.encode(true).unwrap();
        let res = sign1.bytes;

        let mut verify = sign::CoseSign::new();
        verify.bytes = res;
        verify.init_decoder(None).unwrap();

        verify.key(&key).unwrap();
        verify.decode(None, None).unwrap();

        let counters = verify.header.get_counters().unwrap();

        for mut c in counters {
            let mut c_key = keys::CoseKey::new();
            c_key.kty(keys::EC2);
            c_key.alg(algs::ES256);
            c_key.crv(keys::P_256);
            c_key.x(hex::decode(
                "98f50a4ff6c05861c8860d13a638ea56c3f5ad7590bbfbf054e1c7b4d91d6280",
            )
            .unwrap());
            c_key.y(hex::decode(
                "f01400b089867804b8e9fc96c3932161f1934f4223069170d924b7e03bf822bb",
            )
            .unwrap());
            c_key.d(hex::decode(
                "02d1f7e6f26c43d4868d87ceb2353161740aacf1f7163647984b522a848df1c3",
            )
            .unwrap());
            c_key.key_ops(vec![keys::KEY_OPS_VERIFY]);
            c.key(&c_key).unwrap();

            verify.counters_verify(None, &c).unwrap();
        }
    }
}
