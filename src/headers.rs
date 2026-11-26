//! Header parameters ([`CoseHeader`]).
use crate::agent::CoseAgent;
use crate::algs::{thumbprint, verify_chain, verify_thumbprint};
use crate::algs::{HASH_ALGS, SIGNING_ALGS};
use crate::common::{get_alg_id, required, text_int_to_id, MAX_BYTES};
use crate::cose_struct::COUNTER_SIGNATURE;
use crate::errors::{CoseError, CoseField, CoseResult, CoseResultWithRet};
use crate::keys::{self, CoseKey};
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
/// Counter signature (RFC 9338). New counter signatures use this label.
pub const COUNTER_SIGV2: i32 = 11;
/// Counter signature, RFC 8152 format (deprecated by RFC 9338; still decoded and verified).
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

const SENDER_KEY_LABELS: [i32; 4] = [STATIC_KEY_ID, STATIC_KEY, EPHEMERAL_KEY, X5CHAIN_SENDER];

/// Enum for content-type (`String` value or `u32` label).
#[derive(Clone, Debug)]
pub enum ContentTypeTypes {
    Uint(u32),
    Tstr(String),
}

fn counter_label(counter: &CoseAgent) -> i32 {
    if counter.v1 {
        COUNTER_SIG
    } else {
        COUNTER_SIGV2
    }
}

fn read_text(
    decoder: &mut Decoder<Cursor<Vec<u8>>>,
    start: u8,
    field: CoseField,
) -> CoseResultWithRet<String> {
    let bytes = decoder.kernel().raw_data(start, MAX_BYTES)?;
    String::from_utf8(bytes).map_err(|_| CoseError::Invalid(field))
}

fn encode_x5(encoder: &mut Encoder<Vec<u8>>, certs: &Vec<Vec<u8>>, is_chain: bool) -> CoseResult {
    match certs.as_slice() {
        [] => return Err(CoseError::EmptyX5),
        [cert] => encoder.bytes(cert)?,
        _ => {
            if is_chain {
                verify_chain(certs)?;
            }
            encoder.array(certs.len())?;
            for cert in certs {
                encoder.bytes(cert)?;
            }
        }
    }
    Ok(())
}

fn decode_x5(
    decoder: &mut Decoder<Cursor<Vec<u8>>>,
    is_chain: bool,
    field: CoseField,
) -> CoseResultWithRet<Vec<Vec<u8>>> {
    let type_info = decoder.kernel().typeinfo()?;
    if type_info.0 == Type::Array {
        let len = decoder.kernel().unsigned(type_info.1)?;
        if len < 2 {
            return Err(CoseError::Invalid(field));
        }
        let certs = (0..len)
            .map(|_| decoder.bytes())
            .collect::<Result<Vec<Vec<u8>>, _>>()?;
        if is_chain {
            verify_chain(&certs)?;
        }
        Ok(certs)
    } else if type_info.0 == Type::Bytes {
        Ok(vec![decoder.kernel().raw_data(type_info.1, MAX_BYTES)?])
    } else {
        Err(CoseError::Invalid(field))
    }
}

fn encode_x5t(
    encoder: &mut Encoder<Vec<u8>>,
    thumbprint: &Vec<u8>,
    alg: i32,
    chain: Option<&[Vec<u8>]>,
) -> CoseResult {
    if let Some(l) = chain.and_then(|c| c.first()) {
        verify_thumbprint(l, thumbprint, &alg)?;
    }
    encoder.array(2)?;
    encoder.i32(alg)?;
    encoder.bytes(thumbprint)?;
    Ok(())
}

fn decode_x5t(
    decoder: &mut Decoder<Cursor<Vec<u8>>>,
    chain: Option<&[Vec<u8>]>,
    field: CoseField,
) -> CoseResultWithRet<(i32, Vec<u8>)> {
    if decoder.array()? != 2 {
        return Err(CoseError::Invalid(field));
    }
    let alg = text_int_to_id(decoder, None, get_alg_id)?;
    let thumbprint = decoder.bytes()?;
    if let Some(l) = chain.and_then(|c| c.first()) {
        verify_thumbprint(l, &thumbprint, &alg)?;
    }
    Ok((alg, thumbprint))
}

#[derive(Clone, Default)]
#[doc = include_str!("../docs/CoseHeader.md")]
pub struct CoseHeader {
    pub(crate) protected: Vec<i32>,
    pub(crate) unprotected: Vec<i32>,
    pub(crate) alg: Option<i32>,
    pub(crate) crit: Vec<i32>,
    pub(crate) content_type: Option<ContentTypeTypes>,
    pub(crate) kid: Option<Vec<u8>>,
    pub(crate) iv: Option<Vec<u8>>,
    pub(crate) partial_iv: Option<Vec<u8>>,
    pub(crate) salt: Option<Vec<u8>>,
    pub(crate) counters: Vec<CoseAgent>,
    pub(crate) party_u_identity: Option<Vec<u8>>,
    pub(crate) party_u_nonce: Option<Vec<u8>>,
    pub(crate) party_u_other: Option<Vec<u8>>,
    pub(crate) party_v_identity: Option<Vec<u8>>,
    pub(crate) party_v_nonce: Option<Vec<u8>>,
    pub(crate) party_v_other: Option<Vec<u8>>,
    pub(crate) pub_other: Option<Vec<u8>>,
    pub(crate) priv_info: Option<Vec<u8>>,
    pub(crate) ecdh_key: keys::CoseKey,
    pub(crate) static_kid: Option<Vec<u8>>,
    pub(crate) x5bag: Option<Vec<Vec<u8>>>,
    pub(crate) x5chain: Option<Vec<Vec<u8>>>,
    pub(crate) x5t: Option<Vec<u8>>,
    pub(crate) x5t_alg: Option<i32>,
    pub(crate) x5u: Option<String>,
    pub(crate) x5t_sender: Option<Vec<u8>>,
    pub(crate) x5t_sender_alg: Option<i32>,
    pub(crate) x5u_sender: Option<String>,
    pub(crate) x5chain_sender: Option<Vec<Vec<u8>>>,
    pub(crate) x5_private: Vec<u8>,
    pub(crate) labels_found: Vec<i32>,
}

impl CoseHeader {
    /// Creates empty CoseHeader structure.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    getters! { copy:
        /// Algorithm identifier.
        alg -> Option<i32>,
        /// Hash algorithm of `x5t`.
        x5t_alg -> Option<i32>,
        /// Hash algorithm of `x5_sender`
        x5t_sender_alg -> Option<i32>,
    }

    getters! { by_ref:
        /// Labels marked as critical.
        crit -> &[i32],
        /// Counter signatures.
        counters -> &[CoseAgent],
        /// Ephemeral or static key used in ECDH.
        ecdh_key -> &CoseKey,
        /// Labels in the protected header.
        protected -> &[i32],
        /// Labels in the unprotected header.
        unprotected -> &[i32],
    }

    getters! { deref:
        /// Key Identifier.
        kid -> Option<&[u8]>,
        /// Full initialization vector.
        iv -> Option<&[u8]>,
        /// Partial initialization vector.
        partial_iv -> Option<&[u8]>,
        /// Salt for the key derivation.
        salt -> Option<&[u8]>,
        /// PartyU identity for key derivation context.
        party_u_identity -> Option<&[u8]>,
        /// PartyU nonce of the key derivation context.
        party_u_nonce -> Option<&[u8]>,
        /// PartyU other information of the key derivation context.
        party_u_other -> Option<&[u8]>,
        /// PartyV identity for key derivation context.
        party_v_identity -> Option<&[u8]>,
        /// PartyV nonce of the key derivation context.
        party_v_nonce -> Option<&[u8]>,
        /// PartyV other information of the key derivation context.
        party_v_other -> Option<&[u8]>,
        /// SuppPubInfo other of the key derivation context.
        pub_other -> Option<&[u8]>,
        /// SuppPrivInfo of the key derivation context.
        priv_info -> Option<&[u8]>,
        /// Key identifier of the static sender key.
        static_kid -> Option<&[u8]>,
        /// Thumbprint of the certificate.
        x5t -> Option<&[u8]>,
        /// Thumbprint of the sender certificate.
        x5t_sender -> Option<&[u8]>,
        /// Bag of certificates.
        x5bag -> Option<&[Vec<u8>]>,
        /// Certificate chain.
        x5chain -> Option<&[Vec<u8>]>,
        /// Certificate chain of the sender.
        x5chain_sender -> Option<&[Vec<u8>]>,
        /// URI of the certificate.
        x5u -> Option<&str>,
        /// URI of the sender certificate.
        x5u_sender -> Option<&str>,
    }

    /// Content type of the payload.
    #[must_use]
    pub fn content_type(&self) -> Option<&ContentTypeTypes> {
        self.content_type.as_ref()
    }

    pub(crate) fn remove_label(&mut self, label: i32) {
        self.unprotected.retain(|&x| x != label);
        self.protected.retain(|&x| x != label);
        self.crit.retain(|&x| x != label);
    }

    fn reg_label(&mut self, label: i32, prot: bool, crit: bool) {
        self.remove_label(label);
        if prot {
            self.protected.push(label);
        } else {
            self.unprotected.push(label);
        }
        if crit && !self.crit.contains(&label) {
            self.crit.push(label);
        }
    }

    fn clear_key_sender(&mut self) {
        for label in [EPHEMERAL_KEY, STATIC_KEY, STATIC_KEY_ID].iter() {
            self.remove_label(*label);
        }
        self.ecdh_key = keys::CoseKey::new();
        self.static_kid = None;
    }

    fn clear_cert_sender(&mut self) {
        self.remove_label(X5CHAIN_SENDER);
        self.x5chain_sender = None;
        self.x5_private = Vec::new();
    }

    /// Adds the algorithm identifier
    pub fn set_alg(&mut self, alg: i32, prot: bool, crit: bool) {
        self.reg_label(ALG, prot, crit);
        self.alg = Some(alg);
    }

    /// Adds the key ID
    pub fn set_kid(&mut self, kid: impl Into<Vec<u8>>, prot: bool, crit: bool) {
        self.reg_label(KID, prot, crit);
        self.kid = Some(kid.into());
    }

    /// Adds the initialization vector
    pub fn set_iv(&mut self, iv: Vec<u8>, prot: bool, crit: bool) {
        self.remove_label(PARTIAL_IV);
        self.partial_iv = None;
        self.reg_label(IV, prot, crit);
        self.iv = Some(iv);
    }

    /// Adds the partial IV
    pub fn set_partial_iv(&mut self, partial_iv: Vec<u8>, prot: bool, crit: bool) {
        self.remove_label(IV);
        self.iv = None;
        self.reg_label(PARTIAL_IV, prot, crit);
        self.partial_iv = Some(partial_iv);
    }

    /// Adds the salt
    pub fn set_salt(&mut self, salt: Vec<u8>, prot: bool, crit: bool) {
        self.reg_label(SALT, prot, crit);
        self.salt = Some(salt);
    }

    /// Adds the content-type
    pub fn set_content_type(&mut self, content_type: ContentTypeTypes, prot: bool, crit: bool) {
        self.reg_label(CONTENT_TYPE, prot, crit);
        self.content_type = Some(content_type);
    }

    /// Adds the Party identity
    ///
    /// `u`: if the parameter is for PartyU or not (PartyV).
    /// `include`: if it should be included in the message or not.
    pub fn set_party_identity(
        &mut self,
        identity: Vec<u8>,
        prot: bool,
        crit: bool,
        u: bool,
        include: bool,
    ) {
        let label = if u {
            PARTY_U_IDENTITY
        } else {
            PARTY_V_IDENTITY
        };
        if include {
            self.reg_label(label, prot, crit);
        }
        *self.bstr_field(label).expect("Invalid label").0 = Some(identity);
    }

    /// Adds the Party nonce
    ///
    /// `u`: if the parameter is for PartyU or not (PartyV).
    pub fn set_party_nonce(&mut self, nonce: Vec<u8>, prot: bool, crit: bool, u: bool) {
        let label = if u { PARTY_U_NONCE } else { PARTY_V_NONCE };
        self.reg_label(label, prot, crit);
        *self.bstr_field(label).expect("Invalid label").0 = Some(nonce);
    }

    /// Adds the Party Other information
    ///
    /// `u`: if the parameter is for PartyU or not (PartyV).
    pub fn set_party_other(&mut self, other: Vec<u8>, prot: bool, crit: bool, u: bool) {
        let label = if u { PARTY_U_OTHER } else { PARTY_V_OTHER };
        self.reg_label(label, prot, crit);
        *self.bstr_field(label).expect("Invalid label").0 = Some(other);
    }

    /// Adds other to SuppPubInfo to the message.
    pub fn set_pub_other(&mut self, other: Vec<u8>) {
        self.pub_other = Some(other);
    }

    /// Adds SuppPrivInfo to the message.
    pub fn set_priv_info(&mut self, info: Vec<u8>) {
        self.priv_info = Some(info);
    }

    /// Adds a X509 bag of certificates.
    pub fn set_x5bag(&mut self, x5bag: Vec<Vec<u8>>, prot: bool, crit: bool) {
        self.reg_label(X5BAG, prot, crit);
        self.x5bag = Some(x5bag);
    }

    /// Adds a X509 chain of certificates.
    pub fn set_x5chain(&mut self, x5chain: Vec<Vec<u8>>, prot: bool, crit: bool) {
        self.reg_label(X5CHAIN, prot, crit);
        self.x5chain = Some(x5chain);
    }

    /// Adds a X509 certificate URI.
    pub fn set_x5u(&mut self, x5u: String, prot: bool, crit: bool) {
        self.reg_label(X5U, prot, crit);
        self.x5u = Some(x5u);
    }

    /// Adds sender X509 chain of certificates for ECDH.
    pub fn set_x5chain_sender(&mut self, x5chain: Vec<Vec<u8>>, prot: bool, crit: bool) {
        self.clear_key_sender();
        self.reg_label(X5CHAIN_SENDER, prot, crit);
        self.x5chain_sender = Some(x5chain);
    }

    /// Compute and add X509 thumbprint, by providing x509 certificate and the algorithm ID to be
    /// used.
    pub fn set_x5t(&mut self, x5: Vec<u8>, alg: i32, prot: bool, crit: bool) -> CoseResult {
        if !HASH_ALGS.contains(&alg) {
            return Err(CoseError::Invalid(CoseField::Alg));
        }
        self.reg_label(X5T, prot, crit);
        self.x5t = Some(x5);
        self.x5t_alg = Some(alg);
        Ok(())
    }

    /// Adds sender X509 private key in DER format, to be used when encoding a message with ECDH.
    pub fn set_x5_private(&mut self, x5: Vec<u8>) {
        self.clear_key_sender();
        self.x5_private = x5;
    }

    /// Compute and add X509 sender thumbprint for ECDH, by providing x509 certificate and the algorithm ID to be
    /// used.
    pub fn set_x5t_sender(&mut self, x5: Vec<u8>, alg: i32, prot: bool, crit: bool) -> CoseResult {
        if !HASH_ALGS.contains(&alg) {
            return Err(CoseError::Invalid(CoseField::Alg));
        }
        self.reg_label(X5T_SENDER, prot, crit);
        self.x5t_sender = Some(thumbprint(&x5, &alg)?);
        self.x5t_sender_alg = Some(alg);
        Ok(())
    }

    /// Adds sender X509 certificate URI.
    pub fn set_x5u_sender(&mut self, x5u: String, prot: bool, crit: bool) {
        self.reg_label(X5U_SENDER, prot, crit);
        self.x5u_sender = Some(x5u);
    }

    /// Adds an Ephemeral ECDH COSE Key.
    pub fn set_ephemeral_key(&mut self, key: keys::CoseKey, prot: bool, crit: bool) {
        self.clear_key_sender();
        self.clear_cert_sender();
        self.reg_label(EPHEMERAL_KEY, prot, crit);
        self.ecdh_key = key;
    }

    /// Adds a Static ECDH COSE Key
    pub fn set_static_key(&mut self, key: keys::CoseKey, prot: bool, crit: bool) {
        self.clear_key_sender();
        self.clear_cert_sender();
        self.reg_label(STATIC_KEY, prot, crit);
        self.ecdh_key = key;
    }

    /// Adds an Static ECDH COSE Key ID
    pub fn set_static_key_id(&mut self, kid: Vec<u8>, key: keys::CoseKey, prot: bool, crit: bool) {
        self.clear_key_sender();
        self.clear_cert_sender();
        self.reg_label(STATIC_KEY_ID, prot, crit);
        self.ecdh_key = key;
        self.static_kid = Some(kid);
    }

    /// Adds an ECDH COSE Key to the header structure (It will not be included in encoding).
    ///
    /// This is meant to be used to supply the static key when decoding a message that uses static
    /// kid.
    pub fn set_ecdh_key(&mut self, key: keys::CoseKey) {
        self.ecdh_key = key;
    }

    pub(crate) fn get_alg(&self) -> CoseResultWithRet<i32> {
        self.alg.ok_or(CoseError::Missing(CoseField::Alg))
    }

    pub(crate) fn add_counter(&mut self, counter: CoseAgent) -> CoseResult {
        if !SIGNING_ALGS.contains(&counter.header.get_alg()?) {
            return Err(CoseError::Invalid(CoseField::Alg));
        }
        if counter.context != COUNTER_SIGNATURE {
            return Err(CoseError::InvalidContext(counter.context));
        }
        let counter_label = counter_label(&counter);
        if !self.unprotected.contains(&counter_label) {
            self.remove_label(counter_label);
            self.unprotected.push(counter_label);
        }
        self.counters.push(counter);
        Ok(())
    }

    fn encode_labels(
        &mut self,
        encoder: &mut Encoder<Vec<u8>>,
        prot: bool,
        track: bool,
    ) -> CoseResult {
        let labels = if prot {
            self.protected.clone()
        } else {
            self.unprotected.clone()
        };
        for label in labels {
            if track {
                self.track_label(label)?;
            }
            encoder.i32(label)?;
            self.encode_label(label, encoder, prot)?;
        }
        Ok(())
    }

    pub(crate) fn encode_unprotected(&mut self, encoder: &mut Encoder<Vec<u8>>) -> CoseResult {
        encoder.object(self.unprotected.len())?;
        self.encode_labels(encoder, false, true)
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
            self.encode_labels(&mut encoder, true, verify_label)?;
            ph_bstr = encoder.into_writer();
        }
        Ok(ph_bstr)
    }

    pub(crate) fn decode_bucket(
        &mut self,
        decoder: &mut Decoder<Cursor<Vec<u8>>>,
        protected: bool,
        is_counter_sig: bool,
    ) -> CoseResult {
        if protected {
            self.protected.clear();
        } else {
            self.unprotected.clear();
        }
        for _ in 0..decoder.object()? {
            let label = decoder.i32()?;
            self.track_label(label)?;
            self.decode_label(label, decoder, protected, is_counter_sig)?;
        }
        Ok(())
    }

    pub(crate) fn decode_unprotected(
        &mut self,
        decoder: &mut Decoder<Cursor<Vec<u8>>>,
        is_counter_sig: bool,
    ) -> CoseResult {
        self.decode_bucket(decoder, false, is_counter_sig)
    }

    pub(crate) fn decode_protected_bstr(&mut self, ph_bstr: &[u8]) -> CoseResult {
        let mut decoder = Decoder::new(Config::default(), Cursor::new(ph_bstr.to_vec()));
        self.decode_bucket(&mut decoder, true, false)
    }

    fn bstr_field(&mut self, label: i32) -> Option<(&mut Option<Vec<u8>>, CoseField)> {
        Some(match label {
            KID => (&mut self.kid, CoseField::Kid),
            IV => (&mut self.iv, CoseField::Iv),
            PARTIAL_IV => (&mut self.partial_iv, CoseField::PartialIv),
            SALT => (&mut self.salt, CoseField::Salt),
            PARTY_U_IDENTITY => (&mut self.party_u_identity, CoseField::PartyUIdentity),
            PARTY_U_NONCE => (&mut self.party_u_nonce, CoseField::PartyUNonce),
            PARTY_U_OTHER => (&mut self.party_u_other, CoseField::PartyUOther),
            PARTY_V_IDENTITY => (&mut self.party_v_identity, CoseField::PartyVIdentity),
            PARTY_V_NONCE => (&mut self.party_v_nonce, CoseField::PartyVNonce),
            PARTY_V_OTHER => (&mut self.party_v_other, CoseField::PartyVOther),
            STATIC_KEY_ID => (&mut self.static_kid, CoseField::StaticKid),
            _ => return None,
        })
    }

    fn track_label(&mut self, label: i32) -> CoseResult {
        if self.labels_found.contains(&label) {
            return Err(CoseError::DuplicateLabel(label));
        };
        self.labels_found.push(label);
        Ok(())
    }

    fn encode_label(
        &mut self,
        label: i32,
        encoder: &mut Encoder<Vec<u8>>,
        protected: bool,
    ) -> CoseResult {
        if let Some((field, name)) = self.bstr_field(label) {
            encoder.bytes(required(field, name)?)?;
            return Ok(());
        }
        match label {
            ALG => {
                encoder.i32(self.alg.ok_or(CoseError::Missing(CoseField::Alg))?)?;
            }
            CONTENT_TYPE => match required(&self.content_type, CoseField::ContentType)? {
                ContentTypeTypes::Uint(v) => encoder.u32(*v)?,
                ContentTypeTypes::Tstr(v) => encoder.text(v)?,
            },

            X5BAG => encode_x5(encoder, required(&self.x5bag, CoseField::X5Bag)?, false)?,
            X5CHAIN => encode_x5(encoder, required(&self.x5chain, CoseField::X5Chain)?, true)?,
            X5CHAIN_SENDER => encode_x5(
                encoder,
                required(&self.x5chain_sender, CoseField::X5ChainSender)?,
                true,
            )?,

            X5T => encode_x5t(
                encoder,
                required(&self.x5t, CoseField::X5T)?,
                self.x5t_alg.ok_or(CoseError::Missing(CoseField::X5TAlg))?,
                self.x5chain.as_deref(),
            )?,
            X5T_SENDER => encode_x5t(
                encoder,
                required(&self.x5t_sender, CoseField::X5TSender)?,
                self.x5t_sender_alg
                    .ok_or(CoseError::Missing(CoseField::X5TSenderAlg))?,
                self.x5chain_sender.as_deref(),
            )?,
            X5U => encoder.text(required(&self.x5u, CoseField::X5U)?)?,
            X5U_SENDER => encoder.text(required(&self.x5u_sender, CoseField::X5USender)?)?,

            EPHEMERAL_KEY | STATIC_KEY => {
                let mut encode_ecdh = self.ecdh_key.clone();
                encode_ecdh.remove_label(keys::D);
                encode_ecdh.d = None;
                if label == EPHEMERAL_KEY {
                    encode_ecdh.remove_label(keys::KID);
                    encode_ecdh.kid = None;
                }
                encode_ecdh.get_pub_key()?;
                encode_ecdh.encode_key(encoder)?;
            }
            COUNTER_SIG | COUNTER_SIGV2 if !protected => {
                let mut counters: Vec<_> = self
                    .counters
                    .iter_mut()
                    .filter(|c| counter_label(c) == label)
                    .collect();
                if counters.len() > 1 {
                    encoder.array(counters.len())?;
                }
                for counter in &mut counters {
                    counter.encode(encoder)?;
                }
            }
            _ => return Err(CoseError::InvalidLabel(label)),
        }
        Ok(())
    }

    fn check_repeated_sender_key(&self, label: i32) -> CoseResult {
        let fail = SENDER_KEY_LABELS
            .iter()
            .any(|&other| other != label && self.labels_found.contains(&other));
        if fail {
            return Err(CoseError::MultipleSenderKeys);
        }
        Ok(())
    }

    fn push_counter_sig(
        &mut self,
        decoder: &mut Decoder<Cursor<Vec<u8>>>,
        ph_bstr: Vec<u8>,
        v1: bool,
    ) -> CoseResult {
        let mut counter = CoseAgent::new_counter_sig();
        counter.v1 = v1;
        counter.ph_bstr = ph_bstr;
        counter.decode(decoder)?;
        self.counters.push(counter);
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
        if SENDER_KEY_LABELS.contains(&label) {
            self.check_repeated_sender_key(label)?;
        }
        match label {
            ALG => self.alg = Some(text_int_to_id(decoder, None, get_alg_id)?),

            CRIT if protected => {
                self.crit = Vec::new();
                for _ in 0..decoder.array()? {
                    self.crit.push(decoder.i32()?);
                }
            }
            CONTENT_TYPE => {
                let type_info = decoder.kernel().typeinfo()?;
                if type_info.0 == Type::Text {
                    self.content_type = Some(ContentTypeTypes::Tstr(read_text(
                        decoder,
                        type_info.1,
                        CoseField::ContentType,
                    )?));
                } else if UINT.contains(&type_info.0) {
                    self.content_type =
                        Some(ContentTypeTypes::Uint(decoder.kernel().u32(&type_info)?));
                } else {
                    return Err(CoseError::Invalid(CoseField::ContentType));
                }
            }
            KID => {
                let type_info = decoder.kernel().typeinfo()?;
                match type_info.0 {
                    Type::Bytes | Type::Text => {
                        self.kid = Some(decoder.kernel().raw_data(type_info.1, MAX_BYTES)?);
                    }
                    _ => return Err(CoseError::Invalid(CoseField::Kid)),
                }
            }
            PARTY_U_NONCE | PARTY_V_NONCE => {
                let nonce = match decoder.bytes() {
                    Ok(value) => Some(value),
                    Err(cbor::decoder::DecodeError::UnexpectedType {
                        datatype: Type::Bool,
                        ..
                    }) => None,
                    Err(_) => {
                        return Err(CoseError::Invalid(if label == PARTY_U_NONCE {
                            CoseField::PartyUNonce
                        } else {
                            CoseField::PartyVNonce
                        }))
                    }
                };
                if label == PARTY_U_NONCE {
                    self.party_u_nonce = nonce;
                } else {
                    self.party_v_nonce = nonce;
                }
            }
            X5BAG => self.x5bag = Some(decode_x5(decoder, false, CoseField::X5Bag)?),
            X5CHAIN => self.x5chain = Some(decode_x5(decoder, true, CoseField::X5Chain)?),
            X5CHAIN_SENDER => {
                self.x5chain_sender = Some(decode_x5(decoder, true, CoseField::X5ChainSender)?);
            }

            X5T => {
                let (alg, thumbprint) =
                    decode_x5t(decoder, self.x5chain.as_deref(), CoseField::X5T)?;
                self.x5t_alg = Some(alg);
                self.x5t = Some(thumbprint);
            }
            X5T_SENDER => {
                let (alg, thumbprint) = decode_x5t(
                    decoder,
                    self.x5chain_sender.as_deref(),
                    CoseField::X5TSender,
                )?;
                self.x5t_sender_alg = Some(alg);
                self.x5t_sender = Some(thumbprint);
            }
            X5U => {
                self.x5u = Some(decoder.text()?);
            }
            X5U_SENDER => {
                self.x5u_sender = Some(decoder.text()?);
            }
            EPHEMERAL_KEY | STATIC_KEY => self.ecdh_key.decode_key(decoder)?,

            COUNTER_SIG | COUNTER_SIGV2 if !is_counter_sig => {
                let v1 = label == COUNTER_SIG;
                let n = decoder.array()?;
                let (count, first_ph) = match decoder.bytes() {
                    Ok(ph) if n == 3 => (1, ph),
                    Err(cbor::decoder::DecodeError::UnexpectedType {
                        datatype: Type::Array,
                        info: 3,
                    }) => (n, decoder.bytes()?),
                    _ => return Err(CoseError::InvalidCoseStructure),
                };
                self.push_counter_sig(decoder, first_ph, v1)?;

                for _ in 1..count {
                    if decoder.array()? != 3 {
                        return Err(CoseError::InvalidCoseStructure);
                    }
                    let ph = decoder.bytes()?;
                    self.push_counter_sig(decoder, ph, v1)?;
                }
            }
            _ => match self.bstr_field(label) {
                Some((field, _)) => *field = Some(decoder.bytes()?),
                None => return Err(CoseError::InvalidLabel(label)),
            },
        }
        Ok(())
    }

    /// Returns the counter signatures indices on the message with the provided key ID `kid`.
    ///
    /// Key IDs are not unique, so multiple counter signatures can match.
    pub fn counter_indices(&self, kid: &[u8]) -> Vec<usize> {
        self.counters
            .iter()
            .enumerate()
            .filter(|(_, agent)| agent.header.kid.as_deref() == Some(kid))
            .map(|(i, _)| i)
            .collect()
    }
}
