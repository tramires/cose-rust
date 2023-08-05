//! Module to build COSE message headers (protected and unprotected).
use crate::agent::CoseAgent;
use crate::algs::HASH_ALGS;
use crate::algs::{thumbprint, verify_chain, verify_thumbprint};
use crate::common;
use crate::errors::{CoseError, CoseResult, CoseResultWithRet};
use crate::keys;
use cbor::{types::Type, Config, Decoder, Encoder};
use std::io::Cursor;

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
const UINT: [Type; 4] = [Type::UInt16, Type::UInt32, Type::UInt64, Type::UInt8];

// X5
pub const X5BAG: i32 = 32;
pub const X5CHAIN: i32 = 33;
pub const X5T: i32 = 34;
pub const X5U: i32 = 35;
pub const X5T_SENDER: i32 = -27;
pub const X5U_SENDER: i32 = -28;
pub const X5CHAIN_SENDER: i32 = -29;

/// Enum for allowing content-type to be either a `String` or a `u32` label.
#[derive(Clone, Debug)]
pub enum ContentTypeTypes {
    Uint(u32),
    Tstr(String),
}

/// Structure for COSE message headers.
#[derive(Clone)]
pub struct CoseHeader {
    /// List of labels to be included in the protected header.
    pub protected: Vec<i32>,
    /// List of labels to be included in the unprotected header.
    pub unprotected: Vec<i32>,
    /// COSE Algorithm.
    pub alg: Option<i32>,
    /// List of critical header labels.
    pub crit: Vec<i32>,
    /// COSE content-type.
    pub content_type: Option<ContentTypeTypes>,
    /// COSE Key ID.
    pub kid: Option<Vec<u8>>,
    /// Initialization Vector.
    pub iv: Option<Vec<u8>>,
    /// Partial Initialization Vector.
    pub partial_iv: Option<Vec<u8>>,
    /// Salt for the key agreement algorithms.
    pub salt: Option<Vec<u8>>,
    /// List of COSE counter signatures.
    pub counters: Vec<CoseAgent>,
    /// PartyU identity for key agreement.
    pub party_u_identity: Option<Vec<u8>>,
    /// PartyU nonce for key agreement.
    pub party_u_nonce: Option<Vec<u8>>,
    /// PartyU other information for key agreement.
    pub party_u_other: Option<Vec<u8>>,
    /// PartyV identity for key agreement.
    pub party_v_identity: Option<Vec<u8>>,
    /// PartyV nonce for key agreement.
    pub party_v_nonce: Option<Vec<u8>>,
    /// PartyV other information for key agreement.
    pub party_v_other: Option<Vec<u8>>,
    /// SuppPubInfo other
    pub pub_other: Option<Vec<u8>>,
    /// SuppPrivInfo
    pub priv_info: Option<Vec<u8>>,
    /// ECDH key of the message sender.
    pub ecdh_key: keys::CoseKey,
    /// Static COSE ECDH key ID of the message sender.
    pub static_kid: Option<Vec<u8>>,
    /// X509 bag of certificates.
    pub x5bag: Option<Vec<Vec<u8>>>,
    /// X509 chain of certificates.
    pub x5chain: Option<Vec<Vec<u8>>>,
    /// End-entity x509 thumbprint.
    pub x5t: Option<Vec<u8>>,
    /// End-entity x509 thumbprint Hash algorithm.
    pub x5t_alg: Option<i32>,
    /// X509 URI.
    pub x5u: Option<String>,
    /// x509 sender ECDH thumbprint.
    pub x5t_sender: Option<Vec<u8>>,
    /// x509 sender ECDH thumbprint algorithm.
    pub x5t_sender_alg: Option<i32>,
    /// X509 ECDH sender URI.
    pub x5u_sender: Option<String>,
    /// x509 chain of certificates sender ECDH.
    pub x5chain_sender: Option<Vec<Vec<u8>>>,
    /// x509 private key.
    pub x5_private: Vec<u8>,
    pub(crate) labels_found: Vec<i32>,
}

impl CoseHeader {
    /// Creates empty CoseHeader structure.
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
            pub_other: None,
            priv_info: None,
            static_kid: None,
            x5bag: None,
            x5chain: None,
            x5t: None,
            x5_private: Vec::new(),
            x5t_alg: None,
            x5u: None,
            x5t_sender: None,
            x5t_sender_alg: None,
            x5chain_sender: None,
            x5u_sender: None,
            ecdh_key: keys::CoseKey::new(),
        }
    }

    pub(crate) fn remove_label(&mut self, label: i32) {
        self.unprotected.retain(|&x| x != label);
        self.protected.retain(|&x| x != label);
    }

    fn reg_label(&mut self, label: i32, prot: bool, crit: bool) {
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

    /// Adds algorithm to the header.
    ///
    /// `prot` parameter is used to specify if it is to be included in protected header or not.
    /// `crit` parameter is used to specify if this is a critical label.
    pub fn alg(&mut self, alg: i32, prot: bool, crit: bool) {
        self.reg_label(ALG, prot, crit);
        self.alg = Some(alg);
    }

    /// Adds Key ID to the header.
    ///
    /// `prot` parameter is used to specify if it is to be included in protected header or not.
    /// `crit` parameter is used to specify if this is a critical label.
    pub fn kid(&mut self, kid: Vec<u8>, prot: bool, crit: bool) {
        self.reg_label(KID, prot, crit);
        self.kid = Some(kid);
    }

    /// Adds Initialization Vector to the header.
    ///
    /// `prot` parameter is used to specify if it is to be included in protected header or not.
    /// `crit` parameter is used to specify if this is a critical label.
    pub fn iv(&mut self, iv: Vec<u8>, prot: bool, crit: bool) {
        self.remove_label(PARTIAL_IV);
        self.partial_iv = None;
        self.reg_label(IV, prot, crit);
        self.iv = Some(iv);
    }

    /// Adds Partial Initialization Vector to the header.
    ///
    /// `prot` parameter is used to specify if it is to be included in protected header or not.
    /// `crit` parameter is used to specify if this is a critical label.
    pub fn partial_iv(&mut self, partial_iv: Vec<u8>, prot: bool, crit: bool) {
        self.remove_label(IV);
        self.iv = None;
        self.reg_label(PARTIAL_IV, prot, crit);
        self.partial_iv = Some(partial_iv);
    }

    /// Adds salt to the header.
    ///
    /// `prot` parameter is used to specify if it is to be included in protected header or not.
    /// `crit` parameter is used to specify if this is a critical label.
    pub fn salt(&mut self, salt: Vec<u8>, prot: bool, crit: bool) {
        self.reg_label(SALT, prot, crit);
        self.salt = Some(salt);
    }

    /// Adds content-type to the header, this can either be a text string or `u32`.
    ///
    /// `prot` parameter is used to specify if it is to be included in protected header or not.
    /// `crit` parameter is used to specify if this is a critical label.
    pub fn content_type(&mut self, content_type: ContentTypeTypes, prot: bool, crit: bool) {
        self.reg_label(CONTENT_TYPE, prot, crit);
        self.content_type = Some(content_type);
    }

    /// Adds a Party identity to the header.
    ///
    /// `prot` parameter is used to specify if it is to be included in protected header or not.
    /// `crit` parameter is used to specify if this is a critical label.
    /// `u` parameter is used to specify if this is for PartyU or not (PartyV).
    pub fn party_identity(&mut self, identity: Vec<u8>, prot: bool, crit: bool, u: bool) {
        if u {
            self.reg_label(PARTY_U_IDENTITY, prot, crit);
            self.party_u_identity = Some(identity);
        } else {
            self.reg_label(PARTY_V_IDENTITY, prot, crit);
            self.party_v_identity = Some(identity);
        }
    }

    /// Adds a Party nonce to the header.
    ///
    /// `prot` parameter is used to specify if it is to be included in protected header or not.
    /// `crit` parameter is used to specify if this is a critical label.
    /// `u` parameter is used to specify if this is for PartyU or not (PartyV).
    pub fn party_nonce(&mut self, nonce: Vec<u8>, prot: bool, crit: bool, u: bool) {
        if u {
            self.reg_label(PARTY_U_NONCE, prot, crit);
            self.party_u_nonce = Some(nonce);
        } else {
            self.reg_label(PARTY_V_NONCE, prot, crit);
            self.party_v_nonce = Some(nonce);
        }
    }

    /// Adds a Party Other information to the header.
    ///
    /// `prot` parameter is used to specify if it is to be included in protected header or not.
    /// `crit` parameter is used to specify if this is a critical label.
    /// `u` parameter is used to specify if this is for PartyU or not (PartyV).
    pub fn party_other(&mut self, other: Vec<u8>, prot: bool, crit: bool, u: bool) {
        if u {
            self.reg_label(PARTY_U_OTHER, prot, crit);
            self.party_u_other = Some(other);
        } else {
            self.reg_label(PARTY_V_OTHER, prot, crit);
            self.party_v_other = Some(other);
        }
    }

    /// Adds other to SuppPubInfo to the message.
    pub fn pub_other(&mut self, other: Vec<u8>) {
        self.pub_other = Some(other);
    }

    /// Adds SuppPrivInfo to the message.
    pub fn priv_info(&mut self, info: Vec<u8>) {
        self.priv_info = Some(info);
    }

    /// Adds a X509 bag of certificates.
    ///
    /// `prot` parameter is used to specify if it is to be included in protected header or not.
    /// `crit` parameter is used to specify if this is a critical label.
    /// `u` parameter is used to specify if this is for PartyU or not (PartyV).
    pub fn x5bag(&mut self, x5bag: Vec<Vec<u8>>, prot: bool, crit: bool) {
        self.reg_label(X5BAG, prot, crit);
        self.x5bag = Some(x5bag);
    }

    /// Adds a X509 chain of certificates.
    ///
    /// `prot` parameter is used to specify if it is to be included in protected header or not.
    /// `crit` parameter is used to specify if this is a critical label.
    /// `u` parameter is used to specify if this is for PartyU or not (PartyV).
    pub fn x5chain(&mut self, x5chain: Vec<Vec<u8>>, prot: bool, crit: bool) {
        self.reg_label(X5CHAIN, prot, crit);
        self.x5chain = Some(x5chain);
    }

    /// Adds a X509 certificate URI.
    ///
    /// `prot` parameter is used to specify if it is to be included in protected header or not.
    /// `crit` parameter is used to specify if this is a critical label.
    /// `u` parameter is used to specify if this is for PartyU or not (PartyV).
    pub fn x5u(&mut self, x5u: String, prot: bool, crit: bool) {
        self.reg_label(X5U, prot, crit);
        self.x5u = Some(x5u);
    }

    /// Adds sender X509 chain of certificates for ECDH.
    ///
    /// `prot` parameter is used to specify if it is to be included in protected header or not.
    /// `crit` parameter is used to specify if this is a critical label.
    /// `u` parameter is used to specify if this is for PartyU or not (PartyV).
    pub fn x5chain_sender(&mut self, x5chain: Vec<Vec<u8>>, prot: bool, crit: bool) {
        self.remove_label(EPHEMERAL_KEY);
        self.remove_label(STATIC_KEY_ID);
        self.remove_label(STATIC_KEY);
        self.reg_label(X5CHAIN_SENDER, prot, crit);
        self.x5chain_sender = Some(x5chain);
    }

    /// Compute and add X509 thumbprint, by providing x509 certificate and the algorithm ID to be
    /// used.
    ///
    /// `prot` parameter is used to specify if it is to be included in protected header or not.
    /// `crit` parameter is used to specify if this is a critical label.
    /// `u` parameter is used to specify if this is for PartyU or not (PartyV).
    pub fn x5t(&mut self, x5: Vec<u8>, alg: i32, prot: bool, crit: bool) -> CoseResult {
        if !HASH_ALGS.contains(&alg) {
            return Err(CoseError::InvalidAlg());
        }
        self.reg_label(X5T, prot, crit);
        self.x5t = Some(thumbprint(&x5, &alg)?);
        self.x5t_alg = Some(alg);
        Ok(())
    }

    /// Adds sender X509 private key in DER format, to be used when encoding a message with ECDH.
    ///
    /// `prot` parameter is used to specify if it is to be included in protected header or not.
    /// `crit` parameter is used to specify if this is a critical label.
    /// `u` parameter is used to specify if this is for PartyU or not (PartyV).
    pub fn x5_private(&mut self, x5: Vec<u8>) {
        self.x5_private = x5;
    }

    /// Compute and add X509 sender thumbprint for ECDH, by providing x509 certificate and the algorithm ID to be
    /// used.
    ///
    /// `prot` parameter is used to specify if it is to be included in protected header or not.
    /// `crit` parameter is used to specify if this is a critical label.
    /// `u` parameter is used to specify if this is for PartyU or not (PartyV).
    pub fn x5t_sender(&mut self, x5: Vec<u8>, alg: i32, prot: bool, crit: bool) -> CoseResult {
        if !HASH_ALGS.contains(&alg) {
            return Err(CoseError::InvalidAlg());
        }
        self.reg_label(X5T_SENDER, prot, crit);
        self.x5t_sender = Some(thumbprint(&x5, &alg)?);
        self.x5t_sender_alg = Some(alg);
        Ok(())
    }

    /// Adds sender X509 certificate URI.
    ///
    /// `prot` parameter is used to specify if it is to be included in protected header or not.
    /// `crit` parameter is used to specify if this is a critical label.
    /// `u` parameter is used to specify if this is for PartyU or not (PartyV).
    pub fn x5u_sender(&mut self, x5u: String, prot: bool, crit: bool) {
        self.reg_label(X5U_SENDER, prot, crit);
        self.x5u_sender = Some(x5u);
    }

    /// Adds an Ephemeral ECDH COSE Key to the header.
    ///
    /// `prot` parameter is used to specify if it is to be included in protected header or not.
    /// `crit` parameter is used to specify if this is a critical label.
    pub fn ephemeral_key(&mut self, key: keys::CoseKey, prot: bool, crit: bool) {
        self.remove_label(X5T_SENDER);
        self.remove_label(STATIC_KEY_ID);
        self.remove_label(STATIC_KEY);
        self.static_kid = None;
        self.reg_label(EPHEMERAL_KEY, prot, crit);
        self.ecdh_key = key;
    }

    /// Adds an Static ECDH COSE Key to the header.
    ///
    /// `prot` parameter is used to specify if it is to be included in protected header or not.
    /// `crit` parameter is used to specify if this is a critical label.
    pub fn static_key(&mut self, key: keys::CoseKey, prot: bool, crit: bool) {
        self.remove_label(X5T_SENDER);
        self.remove_label(STATIC_KEY_ID);
        self.remove_label(EPHEMERAL_KEY);
        self.static_kid = None;
        self.reg_label(STATIC_KEY, prot, crit);
        self.ecdh_key = key;
    }

    /// Adds an Static ECDH COSE Key ID to the header.
    ///
    /// `prot` parameter is used to specify if it is to be included in protected header or not.
    /// `crit` parameter is used to specify if this is a critical label.
    pub fn static_key_id(&mut self, kid: Vec<u8>, key: keys::CoseKey, prot: bool, crit: bool) {
        self.remove_label(X5T_SENDER);
        self.remove_label(STATIC_KEY);
        self.remove_label(EPHEMERAL_KEY);
        self.reg_label(STATIC_KEY_ID, prot, crit);
        self.ecdh_key = key;
        self.static_kid = Some(kid);
    }

    /// Adds an ECDH COSE Key to the header structure (It will not be included in encoding).
    ///
    /// This is meant to be used when decoding a message that uses static kid.
    pub fn ecdh_key(&mut self, key: keys::CoseKey) {
        self.ecdh_key = key;
    }

    pub(crate) fn encode_unprotected(&mut self, encoder: &mut Encoder<Vec<u8>>) -> CoseResult {
        encoder.object(self.unprotected.len())?;
        for i in 0..self.unprotected.len() {
            if !self.labels_found.contains(&self.unprotected[i]) {
                self.labels_found.push(self.unprotected[i]);
            } else {
                return Err(CoseError::DuplicateLabel(self.unprotected[i]));
            };
            encoder.i32(self.unprotected[i])?;
            self.encode_label(self.unprotected[i], encoder, false)?;
        }
        Ok(())
    }

    pub(crate) fn get_protected_bstr(&mut self, verify_label: bool) -> CoseResultWithRet<Vec<u8>> {
        let mut ph_bstr = Vec::new();
        let mut encoder = Encoder::new(Vec::new());
        let prot_len = self.protected.len();
        let crit_len = self.crit.len();
        if crit_len > 0 || prot_len > 0 {
            if crit_len > 0 {
                encoder.object(prot_len + 1)?;
                encoder.i32(CRIT)?;
                encoder.array(crit_len)?;
                for i in &self.crit {
                    encoder.i32(*i)?;
                }
            } else {
                encoder.object(prot_len)?;
            }
            for i in 0..self.protected.len() {
                if verify_label {
                    if !self.labels_found.contains(&self.protected[i]) {
                        self.labels_found.push(self.protected[i]);
                    } else {
                        return Err(CoseError::DuplicateLabel(self.protected[i]));
                    };
                }
                encoder.i32(self.protected[i])?;
                self.encode_label(self.protected[i], &mut encoder, true)?;
            }
            ph_bstr = encoder.into_writer().to_vec();
        }
        Ok(ph_bstr)
    }

    pub(crate) fn decode_unprotected(
        &mut self,
        decoder: &mut Decoder<Cursor<Vec<u8>>>,
        is_counter_sig: bool,
    ) -> CoseResult {
        let unprot_len = decoder.object()?;
        self.unprotected = Vec::new();
        for _ in 0..unprot_len {
            let label = decoder.i32()?;
            if !self.labels_found.contains(&label) {
                self.labels_found.push(label);
            } else {
                return Err(CoseError::DuplicateLabel(label));
            }
            self.decode_label(label, decoder, false, is_counter_sig)?;
        }
        Ok(())
    }

    pub(crate) fn decode_protected_bstr(&mut self, ph_bstr: &Vec<u8>) -> CoseResult {
        let mut decoder = Decoder::new(Config::default(), Cursor::new(ph_bstr.clone()));
        let prot_len = decoder.object()?;
        self.protected = Vec::new();
        for _ in 0..prot_len {
            let label = decoder.i32()?;
            if !self.labels_found.contains(&label) {
                self.labels_found.push(label);
            } else {
                return Err(CoseError::DuplicateLabel(label));
            };
            self.decode_label(label, &mut decoder, true, false)?;
        }
        Ok(())
    }

    fn encode_label(
        &mut self,
        label: i32,
        encoder: &mut Encoder<Vec<u8>>,
        protected: bool,
    ) -> CoseResult {
        if label == ALG {
            encoder.i32(self.alg.ok_or(CoseError::MissingAlg())?)?;
        } else if label == KID {
            encoder.bytes(&self.kid.as_ref().ok_or(CoseError::MissingKID())?)?;
        } else if label == IV {
            encoder.bytes(&self.iv.as_ref().ok_or(CoseError::MissingIV())?)?;
        } else if label == PARTIAL_IV {
            encoder.bytes(
                &self
                    .partial_iv
                    .as_ref()
                    .ok_or(CoseError::MissingPartialIV())?,
            )?;
        } else if label == SALT {
            encoder.bytes(&self.salt.as_ref().ok_or(CoseError::MissingSalt())?)?;
        } else if label == CONTENT_TYPE {
            match &self
                .content_type
                .as_ref()
                .ok_or(CoseError::MissingContentType())?
            {
                ContentTypeTypes::Uint(v) => encoder.u32(*v)?,
                ContentTypeTypes::Tstr(v) => encoder.text(v)?,
            }
        } else if label == PARTY_U_IDENTITY {
            encoder.bytes(
                &self
                    .party_u_identity
                    .as_ref()
                    .ok_or(CoseError::MissingPartyUID())?,
            )?;
        } else if label == PARTY_U_NONCE {
            encoder.bytes(
                &self
                    .party_u_nonce
                    .as_ref()
                    .ok_or(CoseError::MissingPartyUNonce())?,
            )?;
        } else if label == PARTY_U_OTHER {
            encoder.bytes(
                &self
                    .party_u_other
                    .as_ref()
                    .ok_or(CoseError::MissingPartyUOther())?,
            )?;
        } else if label == PARTY_V_IDENTITY {
            encoder.bytes(
                &self
                    .party_v_identity
                    .as_ref()
                    .ok_or(CoseError::MissingPartyVID())?,
            )?;
        } else if label == PARTY_V_NONCE {
            encoder.bytes(
                &self
                    .party_v_nonce
                    .as_ref()
                    .ok_or(CoseError::MissingPartyVNonce())?,
            )?;
        } else if label == PARTY_V_OTHER {
            encoder.bytes(
                &self
                    .party_v_other
                    .as_ref()
                    .ok_or(CoseError::MissingPartyVOther())?,
            )?;
        } else if [X5BAG, X5CHAIN, X5CHAIN_SENDER].contains(&label) {
            let x5;
            if label == X5BAG {
                x5 = self.x5bag.as_ref().ok_or(CoseError::MissingX5Bag())?;
            } else if label == X5CHAIN {
                x5 = self.x5chain.as_ref().ok_or(CoseError::MissingX5Chain())?;
            } else {
                x5 = self
                    .x5chain_sender
                    .as_ref()
                    .ok_or(CoseError::MissingX5Chain())?;
            }
            let x5_len = x5.len();
            if x5_len > 0 {
                if x5_len == 1 {
                    encoder.bytes(&x5[0])?;
                } else {
                    if label != X5BAG {
                        verify_chain(&x5)?;
                    }
                    encoder.array(x5_len)?;
                    for x in x5 {
                        encoder.bytes(x)?;
                    }
                }
            }
        } else if label == X5T {
            let x5t = self.x5t.as_ref().ok_or(CoseError::MissingX5T())?;
            let x5t_alg = self.x5t_alg.ok_or(CoseError::MissingX5T())?;
            if self.x5chain != None {
                verify_thumbprint(&self.x5chain.as_ref().unwrap()[0].clone(), &x5t, &x5t_alg)?;
            }
            encoder.array(2)?;
            encoder.i32(x5t_alg)?;
            encoder.bytes(x5t)?;
        } else if label == X5T_SENDER {
            let x5t_sender = self
                .x5t_sender
                .as_ref()
                .ok_or(CoseError::MissingX5TSender())?;
            let x5t_sender_alg = self.x5t_sender_alg.ok_or(CoseError::MissingX5TSender())?;
            if self.x5chain_sender != None {
                verify_thumbprint(
                    &self.x5chain_sender.as_ref().unwrap()[0].clone(),
                    &x5t_sender,
                    &x5t_sender_alg,
                )?;
            }
            encoder.array(2)?;
            encoder.i32(x5t_sender_alg)?;
            encoder.bytes(x5t_sender)?;
        } else if label == X5U {
            encoder.text(self.x5u.as_ref().ok_or(CoseError::MissingX5U())?)?;
        } else if label == X5U_SENDER {
            encoder.text(
                self.x5u_sender
                    .as_ref()
                    .ok_or(CoseError::MissingX5USender())?,
            )?;
        } else if label == EPHEMERAL_KEY || label == STATIC_KEY {
            let mut encode_ecdh = self.ecdh_key.clone();
            encode_ecdh.remove_label(keys::D);
            encode_ecdh.d = None;
            encode_ecdh.encode_key(encoder)?;
        } else if label == STATIC_KEY_ID {
            encoder.bytes(
                &self
                    .static_kid
                    .as_ref()
                    .ok_or(CoseError::MissingStaticKID())?,
            )?;
        } else if label == COUNTER_SIG && !protected {
            if self.counters.len() > 1 {
                encoder.array(self.counters.len())?;
            }
            for counter in &mut self.counters {
                counter.encode(encoder)?;
            }
        } else {
            return Err(CoseError::InvalidLabel(label));
        }
        Ok(())
    }

    fn decode_label(
        &mut self,
        label: i32,
        decoder: &mut Decoder<Cursor<Vec<u8>>>,
        protected: bool,
        is_counter_sig: bool,
    ) -> CoseResult {
        if protected {
            self.protected.push(label);
        } else {
            self.unprotected.push(label);
        }
        if label == ALG {
            let type_info = decoder.kernel().typeinfo()?;
            if type_info.0 == Type::Text {
                self.alg = Some(common::get_alg_id(
                    std::str::from_utf8(
                        &decoder.kernel().raw_data(type_info.1, common::MAX_BYTES)?,
                    )
                    .unwrap()
                    .to_string(),
                )?);
            } else if common::CBOR_NUMBER_TYPES.contains(&type_info.0) {
                self.alg = Some(decoder.kernel().i32(&type_info)?);
            } else {
                return Err(CoseError::InvalidCoseStructure());
            }
        } else if label == CRIT && protected {
            self.crit = Vec::new();
            for _ in 0..decoder.array()? {
                self.crit.push(decoder.i32()?);
            }
        } else if label == CONTENT_TYPE {
            let type_info = decoder.kernel().typeinfo()?;
            if type_info.0 == Type::Text {
                self.content_type = Some(ContentTypeTypes::Tstr(
                    std::str::from_utf8(
                        &decoder.kernel().raw_data(type_info.1, common::MAX_BYTES)?,
                    )
                    .unwrap()
                    .to_string(),
                ));
            } else if UINT.contains(&type_info.0) {
                self.content_type = Some(ContentTypeTypes::Uint(decoder.kernel().u32(&type_info)?));
            } else {
                return Err(CoseError::InvalidCoseStructure());
            }
        } else if label == KID {
            let type_info = decoder.kernel().typeinfo()?;
            if type_info.0 == Type::Bytes {
                self.kid = Some(decoder.kernel().raw_data(type_info.1, common::MAX_BYTES)?);
            } else if type_info.0 == Type::Text {
                self.kid = Some(decoder.kernel().raw_data(type_info.1, common::MAX_BYTES)?);
            } else {
                return Err(CoseError::InvalidCoseStructure());
            }
        } else if label == IV {
            self.iv = Some(decoder.bytes()?.to_vec());
        } else if label == SALT {
            self.salt = Some(decoder.bytes()?.to_vec());
        } else if label == PARTY_U_IDENTITY {
            self.party_u_identity = Some(decoder.bytes()?.to_vec());
        } else if label == PARTY_U_NONCE {
            self.party_u_nonce = match decoder.bytes() {
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
        } else if label == PARTY_U_OTHER {
            self.party_u_other = Some(decoder.bytes()?.to_vec());
        } else if label == PARTY_V_IDENTITY {
            self.party_v_identity = Some(decoder.bytes()?.to_vec());
        } else if label == PARTY_V_NONCE {
            self.party_v_nonce = match decoder.bytes() {
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
        } else if label == PARTY_V_OTHER {
            self.party_v_other = Some(decoder.bytes()?.to_vec());
        } else if label == PARTIAL_IV {
            self.partial_iv = Some(decoder.bytes()?.to_vec());
        } else if [X5BAG, X5CHAIN, X5CHAIN_SENDER].contains(&label) {
            let type_info = decoder.kernel().typeinfo()?;
            if type_info.0 == Type::Array {
                let x5_len = type_info.1;
                let mut x5 = Vec::new();
                for _ in 0..x5_len {
                    x5.push(decoder.bytes()?.to_vec());
                }
                if label == X5BAG {
                    self.x5bag = Some(x5);
                } else if label == X5CHAIN {
                    verify_chain(&x5)?;
                    self.x5chain = Some(x5);
                } else {
                    verify_chain(&x5)?;
                    self.x5chain_sender = Some(x5);
                }
            } else if type_info.0 == Type::Bytes {
                let x5 = Some(vec![decoder
                    .kernel()
                    .raw_data(type_info.1, common::MAX_BYTES)?]);
                if label == X5BAG {
                    self.x5bag = x5;
                } else if label == X5CHAIN {
                    self.x5chain = x5;
                } else {
                    self.x5chain_sender = x5;
                }
            } else {
                return Err(CoseError::InvalidCoseStructure());
            }
        } else if [X5T, X5T_SENDER].contains(&label) {
            if decoder.array()? != 2 {
                return Err(CoseError::InvalidCoseStructure());
            }
            let type_info = decoder.kernel().typeinfo()?;
            let x5t_alg;
            if type_info.0 == Type::Text {
                x5t_alg = Some(common::get_alg_id(
                    std::str::from_utf8(
                        &decoder.kernel().raw_data(type_info.1, common::MAX_BYTES)?,
                    )
                    .unwrap()
                    .to_string(),
                )?);
            } else if common::CBOR_NUMBER_TYPES.contains(&type_info.0) {
                x5t_alg = Some(decoder.kernel().i32(&type_info)?);
            } else {
                return Err(CoseError::InvalidCoseStructure());
            }
            let x5t = Some(decoder.bytes()?);
            if label == X5T {
                if self.x5chain != None {
                    verify_thumbprint(
                        &self.x5chain.as_ref().unwrap()[0].clone(),
                        &x5t.as_ref().unwrap(),
                        &x5t_alg.as_ref().unwrap(),
                    )?;
                }
                self.x5t = x5t;
                self.x5t_alg = x5t_alg;
            } else {
                if self.x5chain_sender != None {
                    verify_thumbprint(
                        &self.x5chain_sender.as_ref().unwrap()[0].clone(),
                        &x5t.as_ref().unwrap(),
                        &x5t_alg.as_ref().unwrap(),
                    )?;
                }
                self.x5t_sender = x5t;
                self.x5t_sender_alg = x5t_alg;
            }
        } else if label == X5U {
            self.x5u = Some(decoder.text()?);
        } else if label == X5U_SENDER {
            self.x5u_sender = Some(decoder.text()?);
        } else if label == EPHEMERAL_KEY {
            if [X5CHAIN_SENDER, STATIC_KEY, STATIC_KEY_ID]
                .iter()
                .any(|i| self.labels_found.contains(i))
            {
                return Err(CoseError::InvalidCoseStructure());
            }
            self.ecdh_key.decode_key(decoder)?;
        } else if label == STATIC_KEY {
            if [X5CHAIN_SENDER, EPHEMERAL_KEY, STATIC_KEY_ID]
                .iter()
                .any(|i| self.labels_found.contains(i))
            {
                return Err(CoseError::InvalidCoseStructure());
            }
            self.ecdh_key.decode_key(decoder)?;
        } else if label == STATIC_KEY_ID {
            if [X5CHAIN_SENDER, EPHEMERAL_KEY, STATIC_KEY]
                .iter()
                .any(|i| self.labels_found.contains(i))
            {
                return Err(CoseError::InvalidCoseStructure());
            }
            self.static_kid = Some(decoder.bytes()?.to_vec());
        } else if label == COUNTER_SIG && !is_counter_sig {
            let mut counter = CoseAgent::new_counter_sig();
            let n = decoder.array()?;
            let mut n1 = 0;
            match decoder.bytes() {
                Ok(value) => {
                    counter.ph_bstr = value;
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
                counter.decode(decoder)?;
                self.counters.push(counter);
            } else {
                counter.ph_bstr = decoder.bytes()?;
                counter.decode(decoder)?;
                self.counters.push(counter);
                for _ in 1..n {
                    counter = CoseAgent::new_counter_sig();
                    decoder.array()?;
                    counter.ph_bstr = decoder.bytes()?;
                    counter.decode(decoder)?;
                    self.counters.push(counter);
                }
            }
        } else {
            return Err(CoseError::InvalidLabel(label));
        }
        Ok(())
    }

    /// Method that returns a copy of all counter signatures with the key ID provided
    pub fn get_counter(&self, kid: &Vec<u8>) -> CoseResultWithRet<Vec<usize>> {
        let mut counters: Vec<usize> = Vec::new();
        for i in 0..self.counters.len() {
            if self.counters[i]
                .header
                .kid
                .as_ref()
                .ok_or(CoseError::MissingKID())?
                == kid
            {
                counters.push(i);
            }
        }
        Ok(counters)
    }
}
