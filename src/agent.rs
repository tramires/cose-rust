#![doc = include_str!("../docs/agent.md")]
use crate::algs;
use crate::common::allows;
use crate::cose_struct;
use crate::errors::{CoseError, CoseField, CoseResult, CoseResultWithRet};
use crate::headers::CoseHeader;
use crate::keys;
use cbor::{Decoder, Encoder};
use std::io::Cursor;

fn load_key(
    into: &mut Vec<u8>,
    checked: bool,
    is_empty: bool,
    get: impl FnOnce() -> CoseResultWithRet<Vec<u8>>,
) -> CoseResult {
    if checked {
        *into = get()?;
    } else if is_empty {
        *into = get().unwrap_or_default();
    }
    Ok(())
}

/// COSE recipient, signer or counter-signature structure.
#[derive(Clone, Default)]
#[doc = include_str!("../docs/CoseAgent.md")]
pub struct CoseAgent {
    /// Header of the CoseAgent (recipient, signer or counter-signature).
    pub header: CoseHeader,
    pub(crate) payload: Vec<u8>,
    pub(crate) ph_bstr: Vec<u8>,
    pub(crate) pub_key: Vec<u8>,
    pub(crate) s_key: Vec<u8>,
    pub(crate) context: String,
    pub(crate) crv: Option<i32>,
    pub(crate) key_ops: Vec<i32>,
    pub(crate) base_iv: Option<Vec<u8>>,
    pub(crate) enc: bool,
    pub(crate) v1: bool,
}
const KEY_OPS_SKEY: [i32; 8] = [
    keys::KEY_OPS_DERIVE_BITS,
    keys::KEY_OPS_DERIVE,
    keys::KEY_OPS_DECRYPT,
    keys::KEY_OPS_ENCRYPT,
    keys::KEY_OPS_WRAP,
    keys::KEY_OPS_UNWRAP,
    keys::KEY_OPS_MAC_VERIFY,
    keys::KEY_OPS_MAC,
];

const SIZE: usize = 3;

impl CoseAgent {
    /// Creates an empty CoseAgent structure.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates an empty CoseAgent structure for counter signatures.
    pub fn new_counter_sig() -> Self {
        CoseAgent {
            context: cose_struct::COUNTER_SIGNATURE.to_string(),
            ..Self::default()
        }
    }

    getters! { by_ref:
        /// The signature (signers) or encrypted key (recipients) secured or decoded.
        payload-> &[u8],
    }

    /// Adds a [cose-key](crate::keys::CoseKey).
    pub fn key(&mut self, key: &keys::CoseKey) -> CoseResult {
        let alg = self.header.get_alg()?;
        key.verify_kty()?;
        if algs::is_ecdh(alg)
            && !keys::ECDH_KTY.contains(key.kty.as_ref().ok_or(CoseError::Missing(CoseField::Kty))?)
        {
            return Err(CoseError::Invalid(CoseField::Kty));
        }
        if alg != algs::DIRECT
            && !algs::A_KW.contains(&alg)
            && !algs::RSA_OAEP.contains(&alg)
            && key.alg.is_some_and(|key_alg| key_alg != alg)
        {
            return Err(CoseError::AlgMismatch);
        }
        let is_empty = key.key_ops.is_empty();
        let check = |ko: &i32| key.key_ops.contains(ko);
        if algs::SIGNING_ALGS.contains(&alg) {
            load_key(
                &mut self.s_key,
                check(&keys::KEY_OPS_SIGN),
                is_empty,
                || key.get_s_key(),
            )?;
            load_key(
                &mut self.pub_key,
                check(&keys::KEY_OPS_VERIFY),
                is_empty,
                || key.get_pub_key(),
            )?;
        } else if algs::KEY_DISTRIBUTION_ALGS.contains(&alg) || algs::ENCRYPT_ALGS.contains(&alg) {
            load_key(
                &mut self.s_key,
                KEY_OPS_SKEY.iter().any(check),
                is_empty,
                || key.get_s_key(),
            )?;
            if is_empty && (algs::is_ecdh(alg) || algs::RSA_OAEP.contains(&alg)) {
                self.pub_key = key.get_pub_key().unwrap_or_default();
            }
        }
        self.crv = key.crv;
        self.base_iv = key.base_iv.clone();
        self.key_ops = key.key_ops.clone();
        Ok(())
    }

    pub(crate) fn to_be_signed(
        &self,
        body_protected: &[u8],
        external_aad: &[u8],
        content: &[u8],
        other: Option<&[u8]>,
    ) -> CoseResultWithRet<Vec<u8>> {
        let other = if self.v1 { None } else { other };
        cose_struct::sign_structure(
            &self.context,
            body_protected,
            &self.ph_bstr,
            external_aad,
            content,
            other,
        )
    }

    pub(crate) fn sign(
        &mut self,
        content: &[u8],
        external_aad: &[u8],
        body_protected: &[u8],
        other: Option<&[u8]>,
    ) -> CoseResult {
        if !allows(&self.key_ops, keys::KEY_OPS_SIGN) {
            return Err(CoseError::Invalid(CoseField::KeyOp));
        }
        self.ph_bstr = self.header.get_protected_bstr(false)?;
        let to_sign = self.to_be_signed(&body_protected, &external_aad, &content, other)?;
        self.payload = algs::sign(self.header.get_alg()?, self.crv, &self.s_key, &to_sign)?;
        Ok(())
    }
    pub(crate) fn verify(
        &self,
        content: &[u8],
        external_aad: &[u8],
        body_protected: &[u8],
        other: Option<&[u8]>,
    ) -> CoseResultWithRet<bool> {
        if !allows(&self.key_ops, keys::KEY_OPS_VERIFY) {
            return Err(CoseError::Invalid(CoseField::KeyOp));
        }
        let to_ver = self.to_be_signed(&body_protected, &external_aad, &content, other)?;
        algs::verify(
            self.header.get_alg()?,
            self.crv,
            &self.pub_key,
            &to_ver,
            &self.payload,
        )
    }

    /// Sign and Add a counter signature to the signer/recipient.
    ///
    /// - `external_aad`: see [External AAD](crate::message#external-aad).
    pub fn sign_counter(
        &mut self,
        mut counter: CoseAgent,
        external_aad: Option<&[u8]>,
    ) -> CoseResult {
        if !self.enc {
            return Err(CoseError::NotSecured);
        }
        let aad = external_aad.unwrap_or_default();
        counter.sign(&self.payload, &aad, &self.ph_bstr, None)?;
        self.add_counter_sig(counter)
    }

    /// Verifies a counter signature on the respective signer/recipient.
    ///
    /// - `i`: Index of the counter signature to verify
    /// - `external_aad`: see [External AAD](crate::message#external-aad).
    pub fn verify_counter(
        &mut self,
        i: usize,
        key: &keys::CoseKey,
        external_aad: Option<&[u8]>,
    ) -> CoseResult {
        if !self.enc {
            return Err(CoseError::NotSecured);
        }
        self.header
            .counters
            .get_mut(i)
            .ok_or(CoseError::Missing(CoseField::CounterSignature))?
            .key(key)?;
        let counter = &self.header.counters[i];
        if !counter.verify(
            &self.payload,
            external_aad.unwrap_or_default(),
            &self.ph_bstr,
            None,
        )? {
            return Err(CoseError::Invalid(CoseField::CounterSignature));
        }
        Ok(())
    }

    /// Adds a counter signature to the CoseAgent.
    ///
    /// When a counter signature was produced externally.
    pub fn add_signature(&mut self, signature: Vec<u8>) -> CoseResult {
        if self.context != cose_struct::COUNTER_SIGNATURE {
            return Err(CoseError::InvalidContext(self.context.clone()));
        }
        self.payload = signature;
        Ok(())
    }

    pub(crate) fn get_sign_content(
        &mut self,
        content: &[u8],
        external_aad: &[u8],
        body_protected: &[u8],
        other: Option<&[u8]>,
    ) -> CoseResultWithRet<Vec<u8>> {
        if self.context != cose_struct::COUNTER_SIGNATURE {
            return Err(CoseError::InvalidContext(self.context.clone()));
        }
        self.ph_bstr = self.header.get_protected_bstr(false)?;
        self.to_be_signed(&body_protected, &external_aad, &content, other)
    }

    /// Retrieve the content to sign by the counter signature.
    ///
    /// When the counter signature process is done externally.
    /// - `external_aad`: see [External AAD](crate::message#external-aad).
    pub fn counter_to_sign(
        &self,
        counter: &mut CoseAgent,
        external_aad: Option<&[u8]>,
    ) -> CoseResultWithRet<Vec<u8>> {
        if !self.enc {
            return Err(CoseError::NotSecured);
        }
        counter.get_sign_content(
            &self.payload,
            &external_aad.unwrap_or_default(),
            &self.ph_bstr,
            None,
        )
    }

    /// Retrieve the counter signature to verify.
    ///
    /// When the counter signature process is done externally.
    /// - `external_aad`: see [External AAD](crate::message#external-aad).
    pub fn counter_to_verify(
        &self,
        i: usize,
        external_aad: Option<&[u8]>,
    ) -> CoseResultWithRet<Vec<u8>> {
        if !self.enc {
            return Err(CoseError::NotSecured);
        }
        self.header
            .counters
            .get(i)
            .ok_or(CoseError::Missing(CoseField::CounterSignature))?
            .to_be_signed(
                &self.ph_bstr,
                &external_aad.unwrap_or_default(),
                &self.payload,
                None,
            )
    }

    /// Adds an already signed counter signature to the signer/recipient
    pub fn add_counter_sig(&mut self, counter: CoseAgent) -> CoseResult {
        self.header.add_counter(counter)
    }

    fn kdf(&self, sk: &Vec<u8>, size: usize, alg: &i32) -> CoseResultWithRet<Vec<u8>> {
        let mut context =
            cose_struct::kdf_structure(alg, &self.header, size as u16 * 8, &self.ph_bstr)?;
        algs::hkdf(
            size,
            sk,
            self.header.salt.as_ref(),
            &mut context,
            self.header.get_alg()?,
        )
    }

    fn ecdh(&self, sender: bool) -> CoseResultWithRet<Vec<u8>> {
        let crv = self.crv.ok_or(CoseError::Missing(CoseField::Crv))?;
        let (public, private, crv_pub, crv_priv) = if sender {
            if self.pub_key.is_empty() {
                return Err(CoseError::MissingKey);
            }
            let (private, crv_priv) = if self.header.x5_private.is_empty() {
                let ecdh_crv = self
                    .header
                    .ecdh_key
                    .crv
                    .ok_or(CoseError::Missing(CoseField::Crv))?;
                (self.header.ecdh_key.get_s_key()?, Some(ecdh_crv))
            } else {
                (self.header.x5_private.clone(), None)
            };
            (self.pub_key.clone(), private, Some(crv), crv_priv)
        } else {
            if self.s_key.is_empty() {
                return Err(CoseError::MissingKey);
            }
            let (public, crv_public) = match &self.header.x5chain_sender {
                Some(chain) => {
                    algs::verify_chain(chain)?;
                    let cert = chain
                        .first()
                        .ok_or(CoseError::Missing(CoseField::X5ChainSender))?;
                    (cert.clone(), None)
                }
                None => (self.header.ecdh_key.get_pub_key()?, Some(crv)),
            };
            (public, self.s_key.clone(), crv_public, Some(crv))
        };
        algs::ecdh_derive_key(crv_pub, crv_priv, &public, &private)
    }

    pub(crate) fn derive_key(
        &mut self,
        cek: &Vec<u8>,
        size: usize,
        sender: bool,
        true_alg: &i32,
    ) -> CoseResultWithRet<Vec<u8>> {
        if self.ph_bstr.is_empty() {
            self.ph_bstr = self.header.get_protected_bstr(false)?;
        }
        let alg = self.header.get_alg()?;
        if algs::A_KW.contains(&alg) {
            if !sender {
                return Ok(algs::aes_key_unwrap(&self.s_key, size, &cek)?);
            }
            self.payload = algs::aes_key_wrap(&self.s_key, size, &cek)?;
            return Ok(cek.clone());
        } else if algs::RSA_OAEP.contains(&alg) {
            if !sender {
                return algs::rsa_oaep_dec(&self.s_key, size, &cek, alg);
            }
            self.payload = algs::rsa_oaep_enc(&self.pub_key, &cek, alg)?;
            return Ok(cek.clone());
        } else if algs::DIRECT_HKDF.contains(&alg) {
            return self.kdf(&self.s_key, size, true_alg);
        } else if algs::ECDH_H.contains(&alg) || algs::ECDH_A.contains(&alg) {
            let shared = self.ecdh(sender)?;
            if algs::ECDH_H.contains(&alg) {
                return self.kdf(&shared, size, true_alg);
            } else {
                let alg_akw = match alg {
                    algs::ECDH_ES_A128KW | algs::ECDH_SS_A128KW => algs::A128KW,
                    algs::ECDH_ES_A192KW | algs::ECDH_SS_A192KW => algs::A192KW,
                    algs::ECDH_ES_A256KW | algs::ECDH_SS_A256KW => algs::A256KW,
                    _ => return Err(CoseError::Invalid(CoseField::Alg)),
                };

                let kek = self.kdf(&shared, algs::get_cek_size(alg)?, &alg_akw)?;
                if !sender {
                    return algs::aes_key_unwrap(&kek, size, &cek);
                }
                self.payload = algs::aes_key_wrap(&kek, size, &cek)?;
                return Ok(cek.clone());
            }
        } else {
            return Err(CoseError::Invalid(CoseField::Alg));
        }
    }

    pub(crate) fn decode(&mut self, d: &mut Decoder<Cursor<Vec<u8>>>) -> CoseResult {
        if !self.ph_bstr.is_empty() {
            self.header.decode_protected_bstr(&self.ph_bstr)?;
        }
        self.header
            .decode_unprotected(d, self.context == cose_struct::COUNTER_SIGNATURE)?;
        self.payload = d.bytes()?;
        self.header.labels_found.clear();
        Ok(())
    }

    pub(crate) fn encode(&mut self, e: &mut Encoder<Vec<u8>>) -> CoseResult {
        e.array(SIZE)?;
        e.bytes(&self.ph_bstr)?;
        self.header.encode_unprotected(e)?;
        e.bytes(&self.payload)?;
        self.header.labels_found.clear();
        Ok(())
    }
}
