use crate::common;
use crate::errors::{CoseError, CoseResult, CoseResultWithRet};
use crate::keys;
use crate::recipients;
use cbor::{types::Type, Config, Decoder, Encoder};
use std::io::Cursor;

// COSE tags
pub const ENC0_TAG: u64 = 16;
pub const MAC0_TAG: u64 = 17;
pub const SIG1_TAG: u64 = 18;
pub const ENC_TAG: u64 = 96;
pub const MAC_TAG: u64 = 97;
pub const SIG_TAG: u64 = 98;

// COSE types in string
pub const ENC0_TYPE: &str = "cose-encrypt0";
pub const MAC0_TYPE: &str = "cose-mac0";
pub const SIG1_TYPE: &str = "cose-sign1";
pub const ENC_TYPE: &str = "cose-encrypt";
pub const MAC_TYPE: &str = "cose-mac";
pub const SIG_TYPE: &str = "cose-sign";

// Common headers
pub const SALT: i32 = -20;
pub const ALG: i32 = 1;
pub const CRIT: i32 = 2;
pub const CONTENT_TYPE: i32 = 3;
pub const KID: i32 = 4;
pub const IV: i32 = 5;
pub const PARTIAL_IV: i32 = 6;
pub const COUNTER_SIG: i32 = 7;

// Key Distribution headers
pub const PARTY_U_IDENTITY: i32 = -21;
pub const PARTY_U_NONCE: i32 = -22;
pub const PARTY_U_OTHER: i32 = -23;
pub const PARTY_V_IDENTITY: i32 = -24;
pub const PARTY_V_NONCE: i32 = -25;
pub const PARTY_V_OTHER: i32 = -26;

// ECDH KEY AGREEMENT headers
pub const EPHEMERAL_KEY: i32 = -1;
pub const STATIC_KEY: i32 = -2;
pub const STATIC_KEY_ID: i32 = -3;

#[derive(Clone)]
pub enum ContentTypeTypes {
    Uint(u32),
    Tstr(String),
}

#[derive(Clone)]
pub struct CoseHeader {
    pub protected: Vec<i32>,
    pub unprotected: Vec<i32>,
    pub alg: Option<i32>,
    pub crit: Vec<i32>,
    pub content_type: Option<ContentTypeTypes>,
    pub kid: Option<Vec<u8>>,
    pub iv: Option<Vec<u8>>,
    pub partial_iv: Option<Vec<u8>>,
    pub salt: Option<Vec<u8>>,
    pub counters: Vec<recipients::CoseRecipient>,
    pub party_u_identity: Option<Vec<u8>>,
    pub party_u_nonce: Option<Vec<u8>>,
    pub party_u_other: Option<Vec<u8>>,
    pub party_v_identity: Option<Vec<u8>>,
    pub party_v_nonce: Option<Vec<u8>>,
    pub party_v_other: Option<Vec<u8>>,
    pub ecdh_key: keys::CoseKey,
    pub static_kid: Option<Vec<u8>>,
    labels_found: Vec<i32>,
}

impl CoseHeader {
    pub fn new() -> CoseHeader {
        CoseHeader {
            labels_found: Vec::new(),
            unprotected: Vec::new(),
            protected: Vec::new(),
            counters: Vec::new(),
            crit: Vec::new(),
            content_type: None,
            partial_iv: None,
            salt: None,
            alg: None,
            kid: None,
            iv: None,
            party_u_identity: None,
            party_v_identity: None,
            party_u_nonce: None,
            party_v_nonce: None,
            party_u_other: None,
            party_v_other: None,
            static_kid: None,
            ecdh_key: keys::CoseKey::new(),
        }
    }

    pub fn remove_label(&mut self, label: i32) {
        self.unprotected.retain(|&x| x != label);
        self.protected.retain(|&x| x != label);
    }
    pub fn reg_label_crit(&mut self, label: i32, prot: bool, crit: bool) {
        self.remove_label(label);
        if prot {
            self.protected.push(label);
        } else {
            self.unprotected.push(label);
        }
        if crit && !self.crit.contains(&label) {
            self.crit.push(ALG);
        }
    }

    pub fn alg(&mut self, alg: i32, prot: bool, crit: bool) {
        self.remove_label(ALG);
        self.reg_label_crit(ALG, prot, crit);
        self.alg = Some(alg);
    }

    pub fn kid(&mut self, kid: Vec<u8>, prot: bool, crit: bool) {
        self.reg_label_crit(KID, prot, crit);
        self.kid = Some(kid);
    }

    pub fn iv(&mut self, iv: Vec<u8>, prot: bool, crit: bool) {
        self.remove_label(PARTIAL_IV);
        self.partial_iv = None;
        self.reg_label_crit(IV, prot, crit);
        self.iv = Some(iv);
    }

    pub fn partial_iv(&mut self, partial_iv: Vec<u8>, prot: bool, crit: bool) {
        self.remove_label(IV);
        self.iv = None;
        self.reg_label_crit(PARTIAL_IV, prot, crit);
        self.partial_iv = Some(partial_iv);
    }

    pub fn salt(&mut self, salt: Vec<u8>, prot: bool, crit: bool) {
        self.reg_label_crit(SALT, prot, crit);
        self.salt = Some(salt);
    }
    pub fn content_type(&mut self, content_type: ContentTypeTypes, prot: bool, crit: bool) {
        self.reg_label_crit(CONTENT_TYPE, prot, crit);
        self.content_type = Some(content_type);
    }
    pub fn party_u_identity(&mut self, identity: Vec<u8>, prot: bool, crit: bool, u: bool) {
        if u {
            self.reg_label_crit(PARTY_U_IDENTITY, prot, crit);
            self.party_u_identity = Some(identity);
        } else {
            self.reg_label_crit(PARTY_V_IDENTITY, prot, crit);
            self.party_v_identity = Some(identity);
        }
    }
    pub fn party_u_nonce(&mut self, nonce: Vec<u8>, prot: bool, crit: bool, u: bool) {
        if u {
            self.reg_label_crit(PARTY_U_NONCE, prot, crit);
            self.party_u_nonce = Some(nonce);
        } else {
            self.reg_label_crit(PARTY_V_NONCE, prot, crit);
            self.party_v_nonce = Some(nonce);
        }
    }
    pub fn party_u_other(&mut self, other: Vec<u8>, prot: bool, crit: bool, u: bool) {
        if u {
            self.reg_label_crit(PARTY_U_OTHER, prot, crit);
            self.party_u_other = Some(other);
        } else {
            self.reg_label_crit(PARTY_V_OTHER, prot, crit);
            self.party_v_other = Some(other);
        }
    }

    pub fn ephemeral_key(&mut self, key: &keys::CoseKey, prot: bool, crit: bool) {
        self.remove_label(STATIC_KEY_ID);
        self.remove_label(STATIC_KEY);
        self.reg_label_crit(EPHEMERAL_KEY, prot, crit);
        self.ecdh_key = key.clone();
    }

    pub fn static_key(&mut self, key: &keys::CoseKey, prot: bool, crit: bool) {
        self.remove_label(STATIC_KEY_ID);
        self.remove_label(EPHEMERAL_KEY);
        self.reg_label_crit(STATIC_KEY, prot, crit);
        self.ecdh_key = key.clone();
    }

    pub fn static_key_id(&mut self, kid: Vec<u8>, key: &keys::CoseKey, prot: bool, crit: bool) {
        self.remove_label(STATIC_KEY);
        self.remove_label(EPHEMERAL_KEY);
        self.reg_label_crit(STATIC_KEY_ID, prot, crit);
        self.ecdh_key = key.clone();
        self.static_kid = Some(kid);
    }

    pub fn ecdh_key(&mut self, key: &keys::CoseKey) {
        self.ecdh_key = key.clone();
    }

    pub fn encode_unprotected(&mut self, e: &mut Encoder<Vec<u8>>) -> CoseResult {
        e.object(self.unprotected.len())?;
        for i in self.unprotected.clone() {
            e.i32(i)?;
            self.encode_label(i, e, false)?;
        }
        Ok(())
    }

    pub fn get_protected_bstr(&mut self) -> CoseResultWithRet<Vec<u8>> {
        let mut ph_bstr = Vec::new();
        let mut e = Encoder::new(Vec::new());
        let map_size = self.protected.len();
        let crit_len = self.crit.len();
        if crit_len > 0 || self.protected.len() > 0 {
            if crit_len > 0 {
                e.object(map_size + 1)?;
                e.i32(CRIT)?;
                e.array(crit_len)?;
                for i in &self.crit {
                    e.i32(*i)?;
                }
            } else {
                e.object(map_size)?;
            }
            for i in self.protected.clone() {
                if !self.labels_found.contains(&i) {
                    self.labels_found.push(i);
                } else {
                    return Err(CoseError::DuplicateLabel(i));
                };
                e.i32(i)?;
                self.encode_label(i, &mut e, true)?;
            }
            ph_bstr = e.into_writer().to_vec();
        }
        Ok(ph_bstr)
    }

    pub fn decode_unprotected(
        &mut self,
        d: &mut Decoder<Cursor<Vec<u8>>>,
        is_counter_sig: bool,
    ) -> CoseResult {
        let n_header_elements = d.object()?;
        self.unprotected = Vec::new();
        for _ in 0..n_header_elements {
            let label = d.i32()?;
            if !self.labels_found.contains(&label) {
                self.labels_found.push(label);
            } else {
                return Err(CoseError::DuplicateLabel(label));
            }
            self.decode_label(label, d, false, is_counter_sig)?;
        }
        Ok(())
    }

    pub fn decode_protected_bstr(&mut self, ph_bstr: &Vec<u8>) -> CoseResult {
        let mut d = Decoder::new(Config::default(), Cursor::new(ph_bstr.clone()));
        let n_header_elements = d.object()?;
        self.protected = Vec::new();
        for _ in 0..n_header_elements {
            let label = d.i32()?;
            if !self.labels_found.contains(&label) {
                self.labels_found.push(label);
            } else {
                return Err(CoseError::DuplicateLabel(label));
            };
            self.decode_label(label, &mut d, true, false)?;
        }
        Ok(())
    }

    pub fn encode_label(
        &mut self,
        i: i32,
        e: &mut Encoder<Vec<u8>>,
        protected: bool,
    ) -> CoseResult {
        if i == ALG {
            e.i32(self.alg.ok_or(CoseError::MissingAlgorithm())?)?;
        } else if i == KID {
            e.bytes(&self.kid.as_ref().ok_or(CoseError::MissingAlgorithm())?)?;
        } else if i == IV {
            e.bytes(&self.iv.as_ref().ok_or(CoseError::MissingAlgorithm())?)?;
        } else if i == PARTIAL_IV {
            e.bytes(
                &self
                    .partial_iv
                    .as_ref()
                    .ok_or(CoseError::MissingAlgorithm())?,
            )?;
        } else if i == SALT {
            e.bytes(&self.salt.as_ref().ok_or(CoseError::MissingAlgorithm())?)?;
        } else if i == CONTENT_TYPE {
            match &self
                .content_type
                .as_ref()
                .ok_or(CoseError::MissingAlgorithm())?
            {
                ContentTypeTypes::Uint(v) => e.u32(*v)?,
                ContentTypeTypes::Tstr(v) => e.text(v)?,
            }
        } else if i == PARTY_U_IDENTITY {
            e.bytes(
                &self
                    .party_u_identity
                    .as_ref()
                    .ok_or(CoseError::MissingAlgorithm())?,
            )?;
        } else if i == PARTY_U_NONCE {
            e.bytes(
                &self
                    .party_u_nonce
                    .as_ref()
                    .ok_or(CoseError::MissingAlgorithm())?,
            )?;
        } else if i == PARTY_U_OTHER {
            e.bytes(
                &self
                    .party_u_other
                    .as_ref()
                    .ok_or(CoseError::MissingAlgorithm())?,
            )?;
        } else if i == PARTY_V_IDENTITY {
            e.bytes(
                &self
                    .party_v_identity
                    .as_ref()
                    .ok_or(CoseError::MissingAlgorithm())?,
            )?;
        } else if i == PARTY_V_NONCE {
            e.bytes(
                &self
                    .party_v_nonce
                    .as_ref()
                    .ok_or(CoseError::MissingAlgorithm())?,
            )?;
        } else if i == PARTY_V_OTHER {
            e.bytes(
                &self
                    .party_v_other
                    .as_ref()
                    .ok_or(CoseError::MissingAlgorithm())?,
            )?;
        } else if i == EPHEMERAL_KEY || i == STATIC_KEY {
            let mut temp_key = self.ecdh_key.clone();
            temp_key.remove_label(keys::D);
            temp_key.d = None;
            temp_key.encode_key(e)?;
        } else if i == STATIC_KEY_ID {
            e.bytes(
                &self
                    .static_kid
                    .as_ref()
                    .ok_or(CoseError::MissingAlgorithm())?,
            )?;
        } else if i == COUNTER_SIG && !protected {
            if self.counters.len() > 1 {
                e.array(self.counters.len())?;
            }
            for counter in &mut self.counters {
                counter.encode(e)?;
            }
        } else {
            return Err(CoseError::InvalidLabel(i));
        }
        Ok(())
    }

    pub fn decode_label(
        &mut self,
        i: i32,
        d: &mut Decoder<Cursor<Vec<u8>>>,
        protected: bool,
        is_counter_sig: bool,
    ) -> CoseResult {
        if protected {
            self.protected.push(i);
        } else {
            self.unprotected.push(i);
        }
        if i == ALG {
            let type_info = d.kernel().typeinfo()?;
            if type_info.0 == Type::Text {
                self.alg = Some(common::get_alg_id(
                    std::str::from_utf8(&d.kernel().raw_data(type_info.1, common::MAX_BYTES)?)
                        .unwrap()
                        .to_string(),
                )?);
            } else if common::CBOR_NUMBER_TYPES.contains(&type_info.0) {
                self.alg = Some(d.kernel().i32(&type_info)?);
            } else {
                return Err(CoseError::InvalidCoseStructure());
            }
        } else if i == CRIT && protected {
            self.crit = Vec::new();
            for _ in 0..d.array()? {
                self.crit.push(d.i32()?);
            }
        } else if i == CONTENT_TYPE {
            let type_info = d.kernel().typeinfo()?;
            if type_info.0 == Type::Text {
                self.content_type = Some(ContentTypeTypes::Tstr(
                    std::str::from_utf8(&d.kernel().raw_data(type_info.1, common::MAX_BYTES)?)
                        .unwrap()
                        .to_string(),
                ));
            } else if [Type::UInt16, Type::UInt32, Type::UInt64, Type::UInt8].contains(&type_info.0)
            {
                self.content_type = Some(ContentTypeTypes::Uint(d.kernel().u32(&type_info)?));
            } else {
                return Err(CoseError::InvalidCoseStructure());
            }
        } else if i == KID {
            self.kid = Some(d.bytes()?.to_vec());
        } else if i == IV {
            self.iv = Some(d.bytes()?.to_vec());
        } else if i == SALT {
            self.salt = Some(d.bytes()?.to_vec());
        } else if i == PARTY_U_IDENTITY {
            self.party_u_identity = Some(d.bytes()?.to_vec());
        } else if i == PARTY_U_NONCE {
            self.party_u_nonce = match d.bytes() {
                Ok(value) => Some(value),
                Err(ref err) => match err {
                    cbor::decoder::DecodeError::UnexpectedType { datatype, info: _ } => {
                        if *datatype == Type::Bool {
                            None
                        } else {
                            return Err(CoseError::InvalidCoseStructure());
                        }
                    }
                    _ => {
                        return Err(CoseError::InvalidCoseStructure());
                    }
                },
            };
        } else if i == PARTY_U_OTHER {
            self.party_u_other = Some(d.bytes()?.to_vec());
        } else if i == PARTY_V_IDENTITY {
            self.party_v_identity = Some(d.bytes()?.to_vec());
        } else if i == PARTY_V_NONCE {
            self.party_v_nonce = match d.bytes() {
                Ok(value) => Some(value),
                Err(ref err) => match err {
                    cbor::decoder::DecodeError::UnexpectedType { datatype, info: _ } => {
                        if *datatype == Type::Bool {
                            None
                        } else {
                            return Err(CoseError::InvalidCoseStructure());
                        }
                    }
                    _ => {
                        return Err(CoseError::InvalidCoseStructure());
                    }
                },
            };
        } else if i == PARTY_V_OTHER {
            self.party_v_other = Some(d.bytes()?.to_vec());
        } else if i == PARTIAL_IV {
            self.partial_iv = Some(d.bytes()?.to_vec());
        } else if i == EPHEMERAL_KEY {
            self.ecdh_key.decode_key(d)?;
        } else if i == STATIC_KEY {
            self.ecdh_key.decode_key(d)?;
        } else if i == STATIC_KEY_ID {
            self.static_kid = Some(d.bytes()?.to_vec());
        } else if i == COUNTER_SIG && !is_counter_sig {
            let mut counter = recipients::CoseRecipient::new_counter_sig();
            let n = d.array()?;
            let mut n1 = 0;
            match d.bytes() {
                Ok(value) => {
                    counter.ph_bstr = value.clone();
                }
                Err(ref err) => match err {
                    cbor::decoder::DecodeError::UnexpectedType { datatype, info } => {
                        if *datatype == Type::Array {
                            n1 = *info;
                        }
                    }
                    _ => {
                        return Err(CoseError::InvalidCoseStructure());
                    }
                },
            };
            if n1 == 0 && n == 3 {
                counter.decode(d)?;
                self.counters.push(counter);
            } else {
                counter.ph_bstr = d.bytes()?;
                counter.decode(d)?;
                self.counters.push(counter);
                for _ in 1..n {
                    counter = recipients::CoseRecipient::new_counter_sig();
                    d.array()?;
                    counter.ph_bstr = d.bytes()?;
                    counter.decode(d)?;
                    self.counters.push(counter);
                }
            }
        } else {
            return Err(CoseError::InvalidLabel(i));
        }
        Ok(())
    }

    pub fn get_counters(&mut self) -> CoseResultWithRet<Vec<recipients::CoseRecipient>> {
        let mut counters: Vec<recipients::CoseRecipient> = Vec::new();
        for c in &self.counters {
            counters.push(c.clone());
        }
        Ok(counters)
    }
}
