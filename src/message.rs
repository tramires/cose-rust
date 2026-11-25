#![doc = include_str!("../docs/message.md")]
use crate::agent::CoseAgent;
use crate::algs;
use crate::common::{allows, ph_bstr, required, MAX_BYTES};
use crate::cose_struct;
use crate::errors::{CoseError, CoseField, CoseResult, CoseResultWithRet};
use crate::headers::CoseHeader;
use crate::keys;
use cbor::{decoder::DecodeError, types::Tag, types::Type, Config, Decoder, Encoder};
use std::io::Cursor;

const SIG: usize = 0;
const MAC: usize = 1;
const ENC: usize = 2;

const CONTEXTS: [&str; 3] = [
    cose_struct::SIGNATURE,
    cose_struct::MAC_RECIPIENT,
    cose_struct::ENCRYPT_RECIPIENT,
];
const KO: [[i32; 2]; 3] = [
    [keys::KEY_OPS_SIGN, keys::KEY_OPS_VERIFY],
    [keys::KEY_OPS_MAC, keys::KEY_OPS_MAC_VERIFY],
    [keys::KEY_OPS_ENCRYPT, keys::KEY_OPS_DECRYPT],
];

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

const SIZES: [[usize; 2]; 3] = [[4, 4], [4, 5], [3, 4]];
const TAGS: [[Tag; 2]; 3] = [
    [Tag::Unassigned(SIG1_TAG), Tag::Unassigned(SIG_TAG)],
    [Tag::Unassigned(MAC0_TAG), Tag::Unassigned(MAC_TAG)],
    [Tag::Unassigned(ENC0_TAG), Tag::Unassigned(ENC_TAG)],
];

fn secured_field(context: usize) -> CoseField {
    match context {
        SIG => CoseField::Signature,
        MAC => CoseField::Mac,
        _ => CoseField::Ciphertext,
    }
}
fn content<'a>(
    context: usize,
    payload: &'a Vec<u8>,
    secured: &'a Vec<u8>,
) -> CoseResultWithRet<&'a Vec<u8>> {
    let (content, field) = if context == ENC {
        (secured, CoseField::Ciphertext)
    } else {
        (payload, CoseField::Payload)
    };
    if content.is_empty() {
        return Err(CoseError::Missing(field));
    }
    Ok(content)
}
fn content_iv(
    header: &CoseHeader,
    base_iv: &Option<Vec<u8>>,
    alg: &i32,
) -> CoseResultWithRet<Vec<u8>> {
    if header.iv.is_some() && header.partial_iv.is_some() {
        return Err(CoseError::IvandPartialIv);
    }
    match base_iv {
        Some(v) => algs::gen_iv(required(&header.partial_iv, CoseField::PartialIv)?, v, alg),
        None => Ok(required(&header.iv, CoseField::Iv)?.clone()),
    }
}

/// Structure to encode/decode cose-sign and cose-sign1 messages
#[doc = include_str!("../docs/CoseMessage.md")]
pub struct CoseMessage {
    /// The header parameters of the message.
    pub header: CoseHeader,
    /// The payload of the message.
    pub payload: Vec<u8>,
    pub(crate) secured: Vec<u8>,
    /// The encoded message bytes.
    pub bytes: Vec<u8>,
    ph_bstr: Vec<u8>,
    pub_key: Vec<u8>,
    priv_key: Vec<u8>,
    key_encode: bool,
    key_decode: bool,
    crv: Option<i32>,
    base_iv: Option<Vec<u8>>,
    pub(crate) agents: Vec<CoseAgent>,
    context: usize,
}

impl CoseMessage {
    fn new_w_context(context: usize) -> CoseMessage {
        CoseMessage {
            bytes: Vec::new(),
            header: CoseHeader::new(),
            payload: Vec::new(),
            secured: Vec::new(),
            ph_bstr: Vec::new(),
            pub_key: Vec::new(),
            priv_key: Vec::new(),
            key_encode: false,
            key_decode: false,
            crv: None,
            base_iv: None,
            agents: Vec::new(),
            context,
        }
    }

    /// Creates a new empty COSE signature (cose-sign1 and cose-sign) message structure.
    #[must_use]
    pub fn new_sign() -> CoseMessage {
        Self::new_w_context(SIG)
    }

    /// Creates a new empty COSE encrypt (cose-encrypt0 and cose-encrypt) message structure.
    #[must_use]
    pub fn new_encrypt() -> CoseMessage {
        Self::new_w_context(ENC)
    }

    /// Creates a new empty COSE MAC (cose-mac0 and cose-mac) message structure.
    #[must_use]
    pub fn new_mac() -> CoseMessage {
        Self::new_w_context(MAC)
    }

    /// Creates the COSE message structure matching the tag of the given COSE message bytes.
    ///
    /// The message type is identified by its CBOR tag, thus the COSE
    /// message must be tagged. For untagged message, use either `new_sign`, `new_encrypt` or
    /// `new_mac`.
    pub fn new_from_bytes(bytes: Vec<u8>) -> CoseResultWithRet<CoseMessage> {
        let tag = Decoder::new(Config::default(), Cursor::new(&bytes)).tag()?;
        let context = TAGS
            .iter()
            .position(|types| types.contains(&tag))
            .ok_or(CoseError::InvalidCoseStructure)?;
        Ok(CoseMessage {
            bytes,
            ..Self::new_w_context(context)
        })
    }

    getters! { by_ref:
        /// The signers/recipients of the message.
        agents -> &[CoseAgent],
    }

    /// Adds a signer/recipient to the message.
    ///
    /// Used for multiple agent message types.
    pub fn add_agent(&mut self, agent: &mut CoseAgent) -> CoseResult {
        agent.context = CONTEXTS[self.context].to_string();
        if self.context == SIG {
            if !algs::SIGNING_ALGS.contains(&agent.header.get_alg()?) {
                return Err(CoseError::Invalid(CoseField::Alg));
            }
            if !allows(&agent.key_ops, keys::KEY_OPS_SIGN) {
                return Err(CoseError::Invalid(CoseField::KeyOp));
            }
        } else if (self.context == MAC || self.context == ENC)
            && !algs::KEY_DISTRIBUTION_ALGS.contains(&agent.header.get_alg()?)
        {
            return Err(CoseError::Invalid(CoseField::Alg));
        }
        self.agents.push(agent.clone());
        Ok(())
    }

    /// Mutable access to a signer/recipient.
    pub fn agent_mut(&mut self, i: usize) -> Option<&mut CoseAgent> {
        self.agents.get_mut(i)
    }

    /// Returns the signer/recipient indices on the message with the provided key ID `kid`.
    ///
    /// Key IDs are not unique, so multiple agents can match.
    pub fn agent_indices(&self, kid: &Vec<u8>) -> CoseResultWithRet<Vec<usize>> {
        let mut indices: Vec<usize> = Vec::new();
        for i in 0..self.agents.len() {
            if self.agents[i]
                .header
                .kid
                .as_ref()
                .ok_or(CoseError::Missing(CoseField::Kid))?
                == kid
            {
                indices.push(i);
            }
        }
        Ok(indices)
    }

    /// Adds a key to the message.
    ///
    /// This option is only available for the single agent type messages (cose-sign1, cose-encrypt0 and
    /// cose-mac0). For multiple agents type use the key is added in each agent.
    pub fn key(&mut self, cose_key: &keys::CoseKey) -> CoseResult {
        if !self.agents.is_empty() {
            return Err(CoseError::InvalidMethodMultipleAgents);
        }
        cose_key.verify_kty()?;
        if let Some(key_alg) = cose_key.alg {
            if key_alg != self.header.get_alg()? {
                return Err(CoseError::AlgMismatch);
            }
        }
        let (enc_op, dec_op) = (KO[self.context][0], KO[self.context][1]);
        if self.context == SIG {
            self.crv = cose_key.crv;
            if allows(&cose_key.key_ops, keys::KEY_OPS_SIGN) {
                let priv_key = cose_key.get_s_key().unwrap_or_default();
                if !priv_key.is_empty() {
                    self.key_encode = true;
                    self.priv_key = priv_key;
                }
            }
            if allows(&cose_key.key_ops, keys::KEY_OPS_VERIFY) {
                let pub_key = cose_key.get_pub_key().unwrap_or_default();
                if !pub_key.is_empty() {
                    self.key_decode = true;
                    self.pub_key = pub_key;
                }
            }
        } else {
            if self.context == ENC {
                self.base_iv = cose_key.base_iv.clone();
            }
            let key = cose_key.get_s_key()?;
            if !key.is_empty() {
                self.key_encode |= allows(&cose_key.key_ops, enc_op);
                self.key_decode |= allows(&cose_key.key_ops, dec_op);
                self.priv_key = key;
            }
        }
        if !self.key_encode && !self.key_decode {
            return Err(CoseError::MissingKey);
        }
        Ok(())
    }

    /// Sign and Add a counter signature to the message.
    ///
    /// `external_aad`: see [External AAD](CoseMessage#external-aad).
    pub fn sign_counter(
        &mut self,
        mut counter: CoseAgent,
        external_aad: Option<Vec<u8>>,
    ) -> CoseResult {
        let content = content(self.context, &self.payload, &self.secured)?;
        counter.sign(content, &external_aad.unwrap_or_default(), &self.ph_bstr)?;
        self.add_counter_sig(counter)
    }

    /// Verifies a counter signature on the message.
    ///
    /// `i`: Index of the counter signature to verify
    /// `external_aad`: see [External AAD](CoseMessage#external-aad).
    pub fn verify_counter(
        &mut self,
        i: usize,
        key: &keys::CoseKey,
        external_aad: Option<&[u8]>,
    ) -> CoseResult {
        let content = content(self.context, &self.payload, &self.secured)?;
        self.header
            .counters
            .get_mut(i)
            .ok_or(CoseError::Missing(CoseField::CounterSignature))?
            .key(key)?;
        let counter = &self.header.counters[i];
        if !counter.verify(content, external_aad.unwrap_or_default(), &self.ph_bstr)? {
            return Err(CoseError::Invalid(CoseField::CounterSignature));
        }
        Ok(())
    }

    /// Retrieve the content to sign by the counter signature.
    ///
    /// When the counter signature process is done externally.
    /// `external_aad`: see [External AAD](CoseMessage#external-aad).
    pub fn get_to_sign(
        &self,
        external_aad: Option<Vec<u8>>,
        counter: &mut CoseAgent,
    ) -> CoseResultWithRet<Vec<u8>> {
        let content = content(self.context, &self.payload, &self.secured)?;
        counter.get_sign_content(content, &external_aad.unwrap_or_default(), &self.ph_bstr)
    }

    /// Retrieve the counter signature to verify.
    ///
    /// When the counter signature process is done externally.
    /// `external_aad`: see [External AAD](CoseMessage#external-aad).
    pub fn get_to_verify(
        &mut self,
        external_aad: Option<Vec<u8>>,
        counter: &usize,
    ) -> CoseResultWithRet<Vec<u8>> {
        let content = content(self.context, &self.payload, &self.secured)?;
        let counter = self
            .header
            .counters
            .get_mut(*counter)
            .ok_or(CoseError::Missing(CoseField::CounterSignature))?;
        counter.get_sign_content(content, &external_aad.unwrap_or_default(), &self.ph_bstr)
    }

    /// Adds an already signed counter signature to the signer/recipient
    pub fn add_counter_sig(&mut self, counter: CoseAgent) -> CoseResult {
        self.header.add_counter(counter)
    }

    fn seal(
        &self,
        key: &Vec<u8>,
        alg: i32,
        aad: &Vec<u8>,
        base_iv: &Option<Vec<u8>>,
        single: bool,
    ) -> CoseResultWithRet<Vec<u8>> {
        if self.context == ENC {
            let iv = content_iv(&self.header, base_iv, &alg)?;
            let structure = if single {
                cose_struct::ENCRYPT0
            } else {
                cose_struct::ENCRYPT
            };
            let to_enc = cose_struct::encrypt_structure(structure, &self.ph_bstr, &aad)?;
            algs::encrypt(alg, &key, &iv, &self.payload, &to_enc)
        } else {
            let structure = if single {
                cose_struct::MAC0
            } else {
                cose_struct::MAC
            };
            let to_mac = cose_struct::mac_structure(structure, &self.ph_bstr, &aad, &self.payload)?;
            algs::mac(alg, &key, &to_mac)
        }
    }

    fn secure_single(&mut self, aad: &Vec<u8>) -> CoseResult {
        if !self.key_encode {
            return Err(CoseError::MissingKey);
        }
        let alg = self.header.get_alg()?;
        if !algs::CONTENT_ALGS[self.context].contains(&alg) {
            return Err(CoseError::Invalid(CoseField::Alg));
        }
        self.secured = if self.context == SIG {
            let to_sign = cose_struct::sign_structure(
                cose_struct::SIGNATURE1,
                &self.ph_bstr,
                &[],
                &aad,
                &self.payload,
            )?;
            algs::sign(alg, self.crv, &self.priv_key, &to_sign)?
        } else {
            self.seal(&self.priv_key, alg, aad, &self.base_iv, true)?
        };
        Ok(())
    }

    fn sign_agents(&mut self, aad: &Vec<u8>) -> CoseResult {
        for agent in &mut self.agents {
            if !algs::SIGNING_ALGS.contains(&agent.header.get_alg()?) {
                return Err(CoseError::Invalid(CoseField::Alg));
            }
            agent.sign(&self.payload, aad, &self.ph_bstr)?;
            agent.enc = true;
        }
        Ok(())
    }

    fn secure_recipients(&mut self, aad: &Vec<u8>) -> CoseResult {
        let alg = self.header.get_alg()?;
        let f_alg = self.agents[0].header.get_alg()?;
        let cek = if f_alg == algs::DIRECT {
            if self.agents.len() > 1 {
                return Err(CoseError::DirectAlgMultipleRecipients);
            }
            if !self.agents[0].header.protected.is_empty() {
                return Err(CoseError::DirectAlgProtectedHeader);
            }
            if !allows(&self.agents[0].key_ops, KO[self.context][0]) {
                return Err(CoseError::Invalid(CoseField::KeyOp));
            }
            self.agents[0].s_key.clone()
        } else if algs::ECDH_H.contains(&f_alg) {
            if self.agents.len() > 1 {
                return Err(CoseError::DirectAlgMultipleRecipients);
            }
            let size = algs::get_cek_size(alg)?;
            self.agents[0].derive_key(&Vec::new(), size, true, &alg)?
        } else {
            let mut cek = algs::gen_random_key(alg)?;
            for agent in &mut self.agents {
                let a_alg = agent.header.get_alg()?;
                if a_alg == algs::DIRECT || algs::ECDH_H.contains(&a_alg) {
                    return Err(CoseError::DirectAlgMultipleRecipients);
                }
                cek = agent.derive_key(&cek, cek.len(), true, &alg)?;
            }
            cek
        };
        for agent in &mut self.agents {
            agent.enc = true;
        }
        self.secured = self.seal(&cek, alg, aad, &self.agents[0].base_iv, false)?;
        Ok(())
    }

    /// Function to secure the content, sign, encrypt or mac depending on the COSE message type.
    ///
    /// `external_aad`: see [External AAD](CoseMessage#external-aad).
    pub fn secure_content(&mut self, external_aad: Option<Vec<u8>>) -> CoseResult {
        if self.payload.is_empty() {
            return Err(CoseError::Missing(CoseField::Payload));
        }
        self.ph_bstr = self.header.get_protected_bstr(true)?;
        let aad = external_aad.unwrap_or_default();
        if self.agents.is_empty() {
            self.secure_single(&aad)
        } else if self.context == SIG {
            self.sign_agents(&aad)
        } else {
            self.secure_recipients(&aad)
        }
    }

    /// Encode the COSE message after the content is secured by
    /// [`secure_content`](#method.secure_content).
    ///
    /// `data`: Specify if the payload/ciphertext should be included in
    /// the message.
    pub fn encode(&mut self, data: bool) -> CoseResult {
        let mult = !self.agents.is_empty();
        let t = usize::from(mult);
        if !mult && self.secured.is_empty() {
            return Err(CoseError::Missing(secured_field(self.context)));
        }
        let mut e = Encoder::new(Vec::new());
        e.tag(TAGS[self.context][t])?;
        e.array(SIZES[self.context][t])?;
        e.bytes(self.ph_bstr.as_slice())?;
        self.header.encode_unprotected(&mut e)?;
        if data {
            e.bytes(if self.context == ENC {
                &self.secured
            } else {
                &self.payload
            })?;
        } else {
            e.null()?;
        }
        if self.context == MAC || (!mult && self.context == SIG) {
            e.bytes(&self.secured)?;
        }
        if mult {
            e.array(self.agents.len())?;
            for a in &mut self.agents {
                a.encode(&mut e)?;
            }
        }
        self.bytes = e.into_writer();
        self.header.labels_found.clear();
        Ok(())
    }

    fn decode_tag(&self, d: &mut Decoder<Cursor<Vec<u8>>>) -> CoseResultWithRet<Option<Tag>> {
        Ok(match d.tag() {
            Ok(v) => {
                if !TAGS[self.context].contains(&v) {
                    return Err(CoseError::Invalid(CoseField::Tag));
                }
                d.array()?;
                Some(v)
            }
            Err(DecodeError::UnexpectedType {
                datatype: Type::Array,
                info,
            }) if SIZES[self.context].contains(&usize::from(info)) => None,
            Err(_) => return Err(CoseError::InvalidLabel(SIZES[self.context][0] as i32)),
        })
    }

    fn decode_headers(&mut self, d: &mut Decoder<Cursor<Vec<u8>>>) -> CoseResult {
        self.ph_bstr = ph_bstr(d.bytes())?;
        if !self.ph_bstr.is_empty() {
            self.header.decode_protected_bstr(&self.ph_bstr)?;
        }
        self.header.decode_unprotected(d, false)?;
        self.header.labels_found.clear();
        Ok(())
    }

    fn decode_trailer(
        &mut self,
        d: &mut Decoder<Cursor<Vec<u8>>>,
        tag: Option<&Tag>,
    ) -> CoseResult {
        if self.context == MAC {
            self.secured = d.bytes()?;
            if self.secured.is_empty() {
                return Err(CoseError::Missing(CoseField::Mac));
            }
        }

        if let Ok(type_info) = d.kernel().typeinfo() {
            let tag_type = |form: usize| tag.is_none_or(|t| *t == TAGS[self.context][form]);

            match type_info.0 {
                Type::Array if tag_type(1) => {
                    let r_len = d.kernel().unsigned(type_info.1)?;
                    for _ in 0..r_len {
                        let mut agent = CoseAgent::new();
                        agent.context = CONTEXTS[self.context].to_string();
                        d.array()?;
                        agent.ph_bstr = ph_bstr(d.bytes())?;
                        agent.decode(d)?;
                        agent.enc = true;
                        self.agents.push(agent);
                    }
                }
                Type::Bytes if tag_type(0) => {
                    if self.context == SIG {
                        self.secured = d.kernel().raw_data(type_info.1, MAX_BYTES)?;
                    }
                    if self.secured.is_empty() {
                        return Err(CoseError::Missing(secured_field(self.context)));
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }

    /// Parses [`bytes`](Self::bytes) into the message headers, content and signers/recipients.
    ///
    /// Nothing is verified or decrypted in this method: this step exposes the headers so the right
    /// key can be chosen before calling [`decode`](Self::decode).
    ///
    /// `data`: Supply the detached content, if the message was encoded without it; `None`
    /// otherwise.
    pub fn init_decoder(&mut self, data: Option<Vec<u8>>) -> CoseResult {
        let input = Cursor::new(self.bytes.clone());
        let mut d = Decoder::new(Config::default(), input);
        let tag = self.decode_tag(&mut d)?;

        self.decode_headers(&mut d)?;

        let data = match data {
            None => d.bytes()?,
            Some(v) => {
                d.skip()?;
                v
            }
        };
        if self.context == ENC {
            self.secured = data;
        } else {
            self.payload = data;
        }
        content(self.context, &self.payload, &self.secured)?;

        if (self.context == ENC && self.secured.is_empty())
            || (self.context != ENC && self.payload.is_empty())
        {
            if self.context == ENC {
                return Err(CoseError::Missing(CoseField::Ciphertext));
            } else {
                return Err(CoseError::Missing(CoseField::Payload));
            }
        }

        if self.context != SIG {
            let alg = self.header.get_alg()?;
            if (alg == algs::DIRECT || algs::A_KW.contains(&alg)) && !self.ph_bstr.is_empty() {
                return Err(CoseError::InvalidCoseStructure);
            }
        }

        self.decode_trailer(&mut d, tag.as_ref())
    }

    fn open(
        &self,
        key: &Vec<u8>,
        alg: i32,
        aad: &Vec<u8>,
        base_iv: &Option<Vec<u8>>,
        single: bool,
    ) -> CoseResultWithRet<Vec<u8>> {
        if self.context == ENC {
            let iv = content_iv(&self.header, base_iv, &alg)?;
            let structure = if single {
                cose_struct::ENCRYPT0
            } else {
                cose_struct::ENCRYPT
            };
            let to_dec = cose_struct::encrypt_structure(structure, &self.ph_bstr, &aad)?;
            algs::decrypt(alg, &key, &iv, &self.secured, &to_dec)
        } else {
            let structure = if single {
                cose_struct::MAC0
            } else {
                cose_struct::MAC
            };
            let to_ver = cose_struct::mac_structure(structure, &self.ph_bstr, &aad, &self.payload)?;
            if !algs::mac_verify(alg, &key, &to_ver, &self.secured)? {
                return Err(CoseError::Invalid(CoseField::Mac));
            }
            Ok(self.payload.clone())
        }
    }
    fn open_single(&self, aad: &Vec<u8>) -> CoseResultWithRet<Vec<u8>> {
        if !self.key_decode {
            return Err(CoseError::MissingKey);
        }
        let alg = self.header.get_alg()?;
        if self.context == SIG {
            let to_ver = cose_struct::sign_structure(
                cose_struct::SIGNATURE1,
                &self.ph_bstr,
                &[],
                &aad,
                &self.payload,
            )?;
            if !algs::verify(alg, self.crv, &self.pub_key, &to_ver, &self.secured)? {
                return Err(CoseError::Invalid(CoseField::Signature));
            }
            return Ok(self.payload.clone());
        }
        self.open(&self.priv_key, alg, aad, &self.base_iv, true)
    }

    fn verify_agent(&self, index: usize, aad: &Vec<u8>) -> CoseResultWithRet<Vec<u8>> {
        let agent = &self.agents[index];
        if agent.pub_key.is_empty() {
            return Err(CoseError::MissingKey);
        }
        if !agent.verify(&self.payload, aad, &self.ph_bstr)? {
            return Err(CoseError::Invalid(CoseField::Signature));
        }
        Ok(self.payload.clone())
    }
    fn open_recipient(&mut self, index: usize, aad: &Vec<u8>) -> CoseResultWithRet<Vec<u8>> {
        let alg = self.header.get_alg()?;
        let agent = &mut self.agents[index];
        let cek = if agent.header.get_alg()? == algs::DIRECT {
            if !allows(&agent.key_ops, KO[self.context][1]) || agent.s_key.is_empty() {
                return Err(CoseError::Invalid(CoseField::KeyOp));
            }
            agent.s_key.clone()
        } else {
            let size = algs::get_cek_size(alg)?;
            let wrapped = agent.payload.clone();
            agent.derive_key(&wrapped, size, false, &alg)?
        };
        self.open(&cek, alg, aad, &self.agents[index].base_iv, false)
    }

    /// Verifies or decrypts the message and returns its payload.
    ///
    /// Requires [`init_decoder`](Self::init_decoder) and a key set on the message with
    /// [`key`](Self::key) for signle agent messages, or on the agent (signer/recipient) for
    /// multiple agent messages.
    pub fn decode(
        &mut self,
        external_aad: Option<Vec<u8>>,
        agent: Option<usize>,
    ) -> CoseResultWithRet<Vec<u8>> {
        let aad = external_aad.unwrap_or_default();
        if self.agents.is_empty() {
            return self.open_single(&aad);
        }
        let index = agent.ok_or(CoseError::Missing(CoseField::Signer))?;
        if index >= self.agents.len() {
            return Err(CoseError::Missing(CoseField::Signer));
        }
        if self.context == SIG {
            self.verify_agent(index, &aad)
        } else {
            self.open_recipient(index, &aad)
        }
    }
}
