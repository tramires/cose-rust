//! Module to encode/decode cose-keys/cose-keySets.
//!
//! # cose-keySet example
//! ```
//! use cose::keys;
//! use cose::algs;
//! use hex;
//!
//! fn main() {
//!     let mut key = keys::CoseKey::new();
//!     key.kty(keys::EC2);
//!     key.alg(algs::ES256);
//!     key.crv(keys::P_256);
//!     key.d(hex::decode("57c92077664146e876760c9520d054aa93c3afb04e306705db6090308507b4d3").unwrap());
//!     key.key_ops(vec![keys::KEY_OPS_SIGN]);
//!
//!     key.encode().unwrap();
//!
//!     let mut decode_key = keys::CoseKey::new();
//!     decode_key.bytes = key.bytes;
//!
//!     decode_key.decode().unwrap();
//!
//!     assert_eq!(decode_key.d, key.d);
//!     assert_eq!(decode_key.kty, key.kty);
//!     assert_eq!(decode_key.crv, key.crv);
//!     assert_eq!(decode_key.alg, key.alg);
//!
//!     let mut key_set = keys::CoseKeySet::new();
//!     key_set.add_key(&decode_key);
//!     key_set.encode();
//!
//!     let mut decode_key_set = keys::CoseKeySet::new();
//!     decode_key_set.bytes = key_set.bytes;
//!     decode_key_set.decode();
//!
//!     assert_eq!(decode_key_set.cose_keys[0].d, key.d);
//!     assert_eq!(decode_key_set.cose_keys[0].kty, key.kty);
//!     assert_eq!(decode_key_set.cose_keys[0].crv, key.crv);
//!     assert_eq!(decode_key_set.cose_keys[0].alg, key.alg);
//! }
//! ```

use crate::common::{
    get_alg_id, get_crv_id, get_key_op_id, get_kty_id, text_int_to_id, CBOR_NUMBER_TYPES, MAX_BYTES,
};
use crate::errors::{CoseError, CoseField, CoseResult, CoseResultWithRet};
use cbor::{types::Type, Config, Decoder, Encoder};
use openssl::bn::BigNum;
use openssl::rsa::Rsa;
use std::io::Cursor;
use std::str::from_utf8;

pub(crate) const ECDH_KTY: [i32; 2] = [OKP, EC2];

//COMMON PARAMETERS
pub const D: i32 = -4;
pub const Y: i32 = -3;
pub const X: i32 = -2;
pub const CRV_K: i32 = -1;
pub const KTY: i32 = 1;
pub const KID: i32 = 2;
pub const ALG: i32 = 3;
pub const KEY_OPS: i32 = 4;
pub const BASE_IV: i32 = 5;

//RSA PARAMETERS
pub const N: i32 = -1;
pub const E: i32 = -2;
pub const RSA_D: i32 = -3;
pub const P: i32 = -4;
pub const Q: i32 = -5;
pub const DP: i32 = -6;
pub const DQ: i32 = -7;
pub const QINV: i32 = -8;
pub const OTHER: i32 = -9;
pub const RI: i32 = -10;
pub const DI: i32 = -11;
pub const TI: i32 = -12;

//KEY TYPES
pub const OKP: i32 = 1;
pub const EC2: i32 = 2;
pub const RSA: i32 = 3;
pub const SYMMETRIC: i32 = 4;
pub const RESERVED: i32 = 0;
pub(crate) const KTY_ALL: [i32; 5] = [RESERVED, OKP, EC2, RSA, SYMMETRIC];
pub(crate) const KTY_NAMES: [&str; 5] = ["Reserved", "OKP", "EC2", "RSA", "Symmetric"];

//KEY OPERATIONS
pub const KEY_OPS_SIGN: i32 = 1;
pub const KEY_OPS_VERIFY: i32 = 2;
pub const KEY_OPS_ENCRYPT: i32 = 3;
pub const KEY_OPS_DECRYPT: i32 = 4;
pub const KEY_OPS_WRAP: i32 = 5;
pub const KEY_OPS_UNWRAP: i32 = 6;
pub const KEY_OPS_DERIVE: i32 = 7;
pub const KEY_OPS_DERIVE_BITS: i32 = 8;
pub const KEY_OPS_MAC: i32 = 9;
pub const KEY_OPS_MAC_VERIFY: i32 = 10;
pub(crate) const KEY_OPS_ALL: [i32; 10] = [
    KEY_OPS_SIGN,
    KEY_OPS_VERIFY,
    KEY_OPS_ENCRYPT,
    KEY_OPS_DECRYPT,
    KEY_OPS_WRAP,
    KEY_OPS_UNWRAP,
    KEY_OPS_DERIVE,
    KEY_OPS_DERIVE_BITS,
    KEY_OPS_MAC,
    KEY_OPS_MAC_VERIFY,
];
pub(crate) const KEY_OPS_NAMES: [&str; 10] = [
    "sign",
    "verify",
    "encrypt",
    "decrypt",
    "wrap key",
    "unwrap key",
    "derive key",
    "derive bits",
    "MAC create",
    "MAC verify",
];

//CURVES
pub const P_256: i32 = 1;
pub const SECP256K1: i32 = 8;
pub const P_384: i32 = 2;
pub const P_521: i32 = 3;
pub const X25519: i32 = 4;
pub const X448: i32 = 5;
pub const ED25519: i32 = 6;
pub const ED448: i32 = 7;
pub(crate) const CURVES_ALL: [i32; 8] =
    [P_256, P_384, P_521, X25519, X448, ED25519, ED448, SECP256K1];
pub(crate) const EC2_CRVS: [i32; 4] = [P_256, P_384, P_521, SECP256K1];
pub(crate) const CURVES_NAMES: [&str; 8] = [
    "P-256",
    "P-384",
    "P-521",
    "X25519",
    "X448",
    "Ed25519",
    "Ed448",
    "secp256k1",
];

fn require(fields: &[(&Option<Vec<u8>>, CoseField)]) -> CoseResult {
    match fields.iter().find(|(v, _)| v.is_none()) {
        Some((_, f)) => Err(CoseError::Missing(*f)),
        None => Ok(()),
    }
}

fn not_allowed(fields: &[(&Option<Vec<u8>>, CoseField)]) -> CoseResult {
    match fields.iter().find(|(v, _)| v.is_some()) {
        Some((_, f)) => Err(CoseError::Invalid(*f)),
        None => Ok(()),
    }
}

/// cose-key structure.
#[derive(Clone, Default)]
pub struct CoseKey {
    /// cose-key encoded bytes.
    pub bytes: Vec<u8>,
    used: Vec<i32>,
    /// Key Type.
    pub kty: Option<i32>,
    /// Base Initialization Vector.
    pub base_iv: Option<Vec<u8>>,
    /// List of Key Operations.
    pub key_ops: Vec<i32>,
    /// COSE Algorithm.
    pub alg: Option<i32>,
    /// Public Key X parameter for OKP/EC2 Keys.
    pub x: Option<Vec<u8>>,
    /// Public Key Y parameter for EC2 Keys.
    pub y: Option<Vec<u8>>,
    /// Public Key Y parity for EC2 Keys.
    pub y_parity: Option<bool>,
    /// Private Key D parameter for OKP/EC2 Keys.
    pub d: Option<Vec<u8>>,
    /// Key value for Symmetric Keys.
    pub k: Option<Vec<u8>>,
    /// Key ID.
    pub kid: Option<Vec<u8>>,
    /// COSE curve for OKP/EC2 keys.
    pub crv: Option<i32>,
    pub n: Option<Vec<u8>>,
    pub e: Option<Vec<u8>>,
    pub rsa_d: Option<Vec<u8>>,
    pub p: Option<Vec<u8>>,
    pub q: Option<Vec<u8>>,
    pub dp: Option<Vec<u8>>,
    pub dq: Option<Vec<u8>>,
    pub qinv: Option<Vec<u8>>,
    pub other: Option<Vec<Vec<Vec<u8>>>>,
}

impl CoseKey {
    /// Creates an empty CoseKey structure
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn reg_label(&mut self, label: i32) {
        self.used.retain(|&x| x != label);
        self.used.push(label);
    }

    pub(crate) fn remove_label(&mut self, label: i32) {
        self.used.retain(|&x| x != label);
    }

    /// Adds Key Type to the cose-key.
    pub fn kty(&mut self, kty: i32) {
        self.reg_label(KTY);
        self.kty = Some(kty);
    }
    /// Removes algorithm from the cose-key.
    pub fn unset_alg(&mut self) {
        self.remove_label(ALG);
        self.alg = None;
    }

    /// Adds Key ID to the cose-key.
    pub fn kid(&mut self, kid: Vec<u8>) {
        self.reg_label(KID);
        self.kid = Some(kid);
    }

    /// Adds Algorithm to cose-key.
    pub fn alg(&mut self, alg: i32) {
        self.reg_label(ALG);
        self.alg = Some(alg);
    }

    /// Adds Key Operations to the cose-key.
    pub fn key_ops(&mut self, key_ops: Vec<i32>) {
        self.reg_label(KEY_OPS);
        self.key_ops = key_ops;
    }

    /// Adds Base Initialization Vector to the cose-key.
    pub fn base_iv(&mut self, base_iv: Vec<u8>) {
        self.reg_label(BASE_IV);
        self.base_iv = Some(base_iv);
    }

    /// Adds Curve to the cose-key.
    pub fn crv(&mut self, crv: i32) {
        self.reg_label(CRV_K);
        self.crv = Some(crv);
    }

    /// Adds X parameter to the cose-key.
    pub fn x(&mut self, x: Vec<u8>) {
        self.reg_label(X);
        self.x = Some(x);
    }

    /// Adds Y parameter to the cose-key.
    pub fn y(&mut self, y: Vec<u8>) {
        self.y_parity = None;
        self.reg_label(Y);
        self.y = Some(y);
    }

    /// Adds Y parity to the cose-key.
    pub fn y_parity(&mut self, parity: bool) {
        self.y = None;
        self.reg_label(Y);
        self.y_parity = Some(parity);
    }

    /// Adds D parameter to the cose-key.
    pub fn d(&mut self, d: Vec<u8>) {
        self.reg_label(D);
        self.d = Some(d);
    }

    /// Adds Symmetric Key value to the cose-key.
    pub fn k(&mut self, k: Vec<u8>) {
        self.reg_label(CRV_K);
        self.k = Some(k);
    }

    /// Adds RSA modulus N to the cose-key.
    pub fn n(&mut self, n: Vec<u8>) {
        self.reg_label(N);
        self.n = Some(n);
    }

    /// Adds RSA public exponent E parameter to the cose-key.
    pub fn e(&mut self, e: Vec<u8>) {
        self.reg_label(E);
        self.e = Some(e);
    }

    /// Adds RSA private exponent d to the cose-key.
    pub fn rsa_d(&mut self, rsa_d: Vec<u8>) {
        self.reg_label(RSA_D);
        self.rsa_d = Some(rsa_d);
    }

    /// Adds RSA prime factor P of N parameter to the cose-key.
    pub fn p(&mut self, p: Vec<u8>) {
        self.reg_label(P);
        self.p = Some(p);
    }

    /// Adds RSA prime factor Q of N parameter to the cose-key.
    pub fn q(&mut self, q: Vec<u8>) {
        self.reg_label(Q);
        self.q = Some(q);
    }

    /// Adds RSA dP (d mod (p-1))  parameter to the cose-key.
    pub fn dp(&mut self, dp: Vec<u8>) {
        self.reg_label(DP);
        self.dp = Some(dp);
    }

    /// Adds RSA dQ (d mod (q-1))  parameter to the cose-key.
    pub fn dq(&mut self, dq: Vec<u8>) {
        self.reg_label(DQ);
        self.dq = Some(dq);
    }

    /// Adds RSA qInv (CRT coefficient q^(-1) mod p) parameter to the cose-key.
    pub fn qinv(&mut self, qinv: Vec<u8>) {
        self.reg_label(QINV);
        self.qinv = Some(qinv);
    }

    /// Adds RSA Other prime infos parameter to the cose-key.
    pub fn other(&mut self, other: Vec<Vec<Vec<u8>>>) {
        self.reg_label(OTHER);
        self.other = Some(other);
    }

    pub(crate) fn verify_curve(&self) -> CoseResult {
        let kty = self.kty.ok_or(CoseError::Missing(CoseField::Kty))?;
        if kty == SYMMETRIC || kty == RSA {
            return Ok(());
        }
        let crv = self.crv.ok_or(CoseError::Missing(CoseField::Crv))?;

        if kty == OKP && [ED25519, ED448, X25519, X448].contains(&crv) {
            Ok(())
        } else if kty == EC2 && EC2_CRVS.contains(&crv) {
            Ok(())
        } else {
            Err(CoseError::Invalid(CoseField::Crv))
        }
    }

    pub(crate) fn verify_kty(&self) -> CoseResult {
        if !KTY_ALL.contains(&self.kty.ok_or(CoseError::Missing(CoseField::Kty))?) {
            return Err(CoseError::Invalid(CoseField::Kty));
        }
        self.verify_curve()?;
        Ok(())
    }

    /// Method to encode the cose-Key.
    pub fn encode(&mut self) -> CoseResult {
        let mut e = Encoder::new(Vec::new());
        if self.alg != None {
            self.verify_kty()?;
        } else {
            self.verify_curve()?;
        }
        self.encode_key(&mut e)?;
        self.bytes = e.into_writer();
        Ok(())
    }

    pub(crate) fn verify_key_ops(&self) -> CoseResult {
        let kty = self.kty.ok_or(CoseError::Missing(CoseField::Kty))?;
        let has = |kos: &[i32]| self.key_ops.iter().any(|ko| kos.contains(ko));
        let public = has(&[KEY_OPS_VERIFY]);
        let private = has(&[KEY_OPS_SIGN, KEY_OPS_DERIVE, KEY_OPS_DERIVE_BITS]);
        match kty {
            _ if self.key_ops.is_empty() => {}
            EC2 | OKP => {
                if public {
                    require(&[(&self.x, CoseField::X)])?;
                    if kty == EC2 && self.y.is_none() && self.y_parity.is_none() {
                        return Err(CoseError::Missing(CoseField::Y));
                    }
                }
                if private {
                    require(&[(&self.d, CoseField::D)])?;
                }
                if public || private {
                    self.crv.ok_or(CoseError::Missing(CoseField::Crv))?;
                }
            }
            SYMMETRIC => {
                if has(&[
                    KEY_OPS_ENCRYPT,
                    KEY_OPS_MAC_VERIFY,
                    KEY_OPS_MAC,
                    KEY_OPS_DECRYPT,
                    KEY_OPS_UNWRAP,
                    KEY_OPS_WRAP,
                ]) {
                    not_allowed(&[
                        (&self.x, CoseField::X),
                        (&self.y, CoseField::Y),
                        (&self.d, CoseField::D),
                    ])?;
                    if self.y_parity.is_some() {
                        return Err(CoseError::Invalid(CoseField::Y));
                    }
                    require(&[(&self.k, CoseField::K)])?;
                }
            }
            RSA => {
                let private_comp = [
                    (&self.rsa_d, CoseField::RsaD),
                    (&self.p, CoseField::P),
                    (&self.q, CoseField::Q),
                    (&self.dp, CoseField::DP),
                    (&self.dq, CoseField::DQ),
                    (&self.qinv, CoseField::QInv),
                ];
                if public {
                    require(&[(&self.n, CoseField::N), (&self.e, CoseField::E)])?;
                    not_allowed(&private_comp)?;
                    if self.other.is_some() {
                        return Err(CoseError::Invalid(CoseField::Other));
                    }
                }
                if private {
                    require(&[(&self.n, CoseField::N), (&self.e, CoseField::E)])?;
                    require(&private_comp)?;
                    if self
                        .other
                        .as_ref()
                        .is_some_and(|o| o.iter().any(|p| p.len() != 3))
                    {
                        return Err(CoseError::Invalid(CoseField::Other));
                    }
                }
            }
            _ => {
                return Err(CoseError::Invalid(CoseField::Kty));
            }
        }
        return Ok(());
    }

    pub(crate) fn encode_key(&self, e: &mut Encoder<Vec<u8>>) -> CoseResult {
        let kty = self.kty.ok_or(CoseError::Missing(CoseField::Kty))?;
        self.verify_key_ops()?;
        let rsa = kty == RSA;
        e.object(self.used.len())?;
        for &label in &self.used {
            e.i32(label)?;
            match (label, self.crv, self.y_parity) {
                (KTY, ..) => e.i32(kty)?,
                (ALG, ..) => e.i32(self.alg.ok_or(CoseError::Missing(CoseField::Alg))?)?,
                (CRV_K, Some(crv), _) => e.i32(crv)?,
                (Y, _, Some(parity)) if !rsa => e.bool(parity)?,
                (KEY_OPS, ..) => {
                    e.array(self.key_ops.len())?;
                    for ko in &self.key_ops {
                        e.i32(*ko)?;
                    }
                }
                (OTHER, ..) => {
                    let other = self
                        .other
                        .as_ref()
                        .ok_or(CoseError::Missing(CoseField::Other))?;
                    e.array(other.len())?;
                    for v in other {
                        e.object(3)?;
                        e.i32(RI)?;
                        e.bytes(&v[0])?;
                        e.i32(DI)?;
                        e.bytes(&v[1])?;
                        e.i32(TI)?;
                        e.bytes(&v[2])?;
                    }
                }
                _ => {
                    let (field, name) = match (label, rsa) {
                        (KID, _) => (&self.kid, CoseField::Kid),
                        (BASE_IV, _) => (&self.base_iv, CoseField::BaseIv),
                        (CRV_K, true) => (&self.n, CoseField::N),
                        (CRV_K, false) => (&self.k, CoseField::K),
                        (X, true) => (&self.e, CoseField::E),
                        (X, false) => (&self.x, CoseField::X),
                        (Y, true) => (&self.rsa_d, CoseField::RsaD),
                        (Y, false) => (&self.y, CoseField::Y),
                        (D, true) => (&self.p, CoseField::P),
                        (D, false) => (&self.d, CoseField::D),
                        (Q, _) => (&self.q, CoseField::Q),
                        (DP, _) => (&self.dp, CoseField::DP),
                        (DQ, _) => (&self.dq, CoseField::DQ),
                        (QINV, _) => (&self.qinv, CoseField::QInv),
                        _ => return Err(CoseError::InvalidLabel(label)),
                    };
                    e.bytes(field.as_deref().ok_or(CoseError::Missing(name))?)?;
                }
            }
        }
        Ok(())
    }

    /// Method to decode a cose-Key.
    pub fn decode(&mut self) -> CoseResult {
        let mut d = Decoder::new(Config::default(), Cursor::new(self.bytes.clone()));
        self.decode_key(&mut d)?;
        if self.alg.is_some() {
            self.verify_kty()?;
        } else {
            self.verify_curve()?;
        }
        Ok(())
    }

    pub(crate) fn decode_key(&mut self, d: &mut Decoder<Cursor<Vec<u8>>>) -> CoseResult {
        let mut label: i32;
        self.used.clear();
        for _ in 0..d.object()? {
            label = d.i32()?;
            if self.used.contains(&label) {
                return Err(CoseError::DuplicateLabel(label));
            }
            match label {
                KTY => self.kty = Some(text_int_to_id(d, None, get_kty_id)?),
                ALG => self.alg = Some(text_int_to_id(d, None, get_alg_id)?),
                KID => self.kid = Some(d.bytes()?),
                KEY_OPS => {
                    self.key_ops = (0..d.array()?)
                        .map(|_| text_int_to_id(d, None, get_key_op_id))
                        .collect::<CoseResultWithRet<_>>()?;
                }
                BASE_IV => self.base_iv = Some(d.bytes()?),
                CRV_K => {
                    let t = d.kernel().typeinfo()?;
                    if t.0 == Type::Bytes {
                        self.k = Some(d.kernel().raw_data(t.1, MAX_BYTES)?);
                    } else {
                        self.crv = Some(text_int_to_id(d, Some(t), get_crv_id)?);
                    }
                }
                X => self.x = Some(d.bytes()?),
                Y => {
                    let type_info = d.kernel().typeinfo()?;
                    if type_info.0 == Type::Bytes {
                        self.y = Some(d.kernel().raw_data(type_info.1, MAX_BYTES)?);
                    } else if type_info.0 == Type::Bool {
                        self.y_parity = Some(d.kernel().bool(&type_info)?);
                    } else {
                        return Err(CoseError::InvalidCoseStructure());
                    }
                }
                D => self.d = Some(d.bytes()?),
                Q => self.q = Some(d.bytes()?),
                DP => self.dp = Some(d.bytes()?),
                DQ => self.dq = Some(d.bytes()?),
                QINV => self.qinv = Some(d.bytes()?),
                OTHER => {
                    let mut other = Vec::new();
                    for _ in 0..d.array()? {
                        if d.object()? != 3 {
                            return Err(CoseError::Invalid(CoseField::Other));
                        }
                        let mut ri = Vec::new();
                        let mut di = Vec::new();
                        let mut ti = Vec::new();

                        for _ in 0..3 {
                            let other_label = d.i32()?;
                            if other_label == RI {
                                ri = d.bytes()?;
                            } else if other_label == DI {
                                di = d.bytes()?;
                            } else if other_label == TI {
                                ti = d.bytes()?;
                            } else {
                                return Err(CoseError::Invalid(CoseField::Other));
                            }
                        }
                        other.push([ri, di, ti].to_vec());
                    }
                    self.other = Some(other);
                }
                _ => {
                    return Err(CoseError::InvalidLabel(label));
                }
            }
            self.used.push(label);
        }
        if self.kty.ok_or(CoseError::Missing(CoseField::Kty))? == RSA {
            if self.k.is_some() {
                self.n = self.k.take();
            }
            if self.x.is_some() {
                self.e = self.x.take();
            }
            if self.y.is_some() {
                self.rsa_d = self.y.take();
            }
            if self.d.is_some() {
                self.p = self.d.take();
            }
        }
        self.verify_key_ops()?;
        Ok(())
    }

    pub(crate) fn get_s_key(&self) -> CoseResultWithRet<Vec<u8>> {
        let kty = self.kty.ok_or(CoseError::Missing(CoseField::Kty))?;
        match kty {
            EC2 | OKP => self
                .d
                .clone()
                .filter(|d| !d.is_empty())
                .ok_or(CoseError::Missing(CoseField::D)),
            SYMMETRIC => self
                .k
                .clone()
                .filter(|k| !k.is_empty())
                .ok_or(CoseError::Missing(CoseField::K)),
            RSA => Ok(Rsa::from_private_components(
                BigNum::from_slice(self.n.as_ref().ok_or(CoseError::Missing(CoseField::N))?)?,
                BigNum::from_slice(self.e.as_ref().ok_or(CoseError::Missing(CoseField::E))?)?,
                BigNum::from_slice(
                    self.rsa_d
                        .as_ref()
                        .ok_or(CoseError::Missing(CoseField::RsaD))?,
                )?,
                BigNum::from_slice(self.p.as_ref().ok_or(CoseError::Missing(CoseField::P))?)?,
                BigNum::from_slice(self.q.as_ref().ok_or(CoseError::Missing(CoseField::Q))?)?,
                BigNum::from_slice(self.dp.as_ref().ok_or(CoseError::Missing(CoseField::DP))?)?,
                BigNum::from_slice(self.dq.as_ref().ok_or(CoseError::Missing(CoseField::DQ))?)?,
                BigNum::from_slice(
                    self.qinv
                        .as_ref()
                        .ok_or(CoseError::Missing(CoseField::QInv))?,
                )?,
            )?
            .private_key_to_der()?),
            _ => Err(CoseError::Invalid(CoseField::Kty)),
        }
    }
    pub(crate) fn get_pub_key(&self) -> CoseResultWithRet<Vec<u8>> {
        let kty = self.kty.ok_or(CoseError::Missing(CoseField::Kty))?;
        match kty {
            EC2 | OKP => {
                let mut x = self
                    .x
                    .clone()
                    .filter(|x| !x.is_empty())
                    .ok_or(CoseError::Missing(CoseField::X))?;

                if kty == OKP {
                    return Ok(x);
                }

                let prefix_bytes = match (&self.y, self.y_parity) {
                    (Some(y), _) if !y.is_empty() => return Ok([&[4], &x[..], &y[..]].concat()),
                    (_, Some(parity)) => {
                        if parity {
                            3
                        } else {
                            2
                        }
                    }
                    _ => return Err(CoseError::Missing(CoseField::Y)),
                };
                Ok([&[prefix_bytes], &x[..]].concat())
            }
            RSA => Ok(Rsa::from_public_components(
                BigNum::from_slice(self.n.as_ref().ok_or(CoseError::Missing(CoseField::N))?)?,
                BigNum::from_slice(self.e.as_ref().ok_or(CoseError::Missing(CoseField::E))?)?,
            )?
            .public_key_to_der()?),
            _ => Err(CoseError::Invalid(CoseField::Kty)),
        }
    }
}

/// cose-keySet structure.
pub struct CoseKeySet {
    /// List of the cose-keys.
    pub cose_keys: Vec<CoseKey>,
    /// COSE encoded key set.
    pub bytes: Vec<u8>,
}

impl CoseKeySet {
    /// Creates a new empty structure.
    pub fn new() -> CoseKeySet {
        CoseKeySet {
            cose_keys: Vec::new(),
            bytes: Vec::new(),
        }
    }

    /// Adds a cose-key to the cose-keySet.
    pub fn add_key(&mut self, key: &CoseKey) {
        self.cose_keys.push(key.clone());
    }

    /// Encodes the cose-keySet.
    pub fn encode(&mut self) -> CoseResult {
        if self.cose_keys.is_empty() {
            return Err(CoseError::MissingKey());
        }
        let mut e = Encoder::new(Vec::new());
        e.array(self.cose_keys.len())?;
        for key in &self.cose_keys {
            key.encode_key(&mut e)?;
        }
        self.bytes = e.into_writer();
        Ok(())
    }

    /// Decodes an encoded cose-keySet.
    ///
    /// The COSE encoded bytes of the cose-keySet must be set with the structure attribute bytes beforehand.
    pub fn decode(&mut self) -> CoseResult {
        let mut d = Decoder::new(Config::default(), Cursor::new(self.bytes.clone()));
        let len = d.array()?;
        if len == 0 {
            return Err(CoseError::MissingKey());
        }
        self.cose_keys = (0..len)
            .map(|_| {
                let mut key = CoseKey::new();
                key.decode_key(&mut d)?;
                Ok(key)
            })
            .collect::<CoseResultWithRet<_>>()?;
        Ok(())
    }

    /// Function that returns a cose-key from the cose-keySet with a given Key ID.
    pub fn get_key(&self, kid: &Vec<u8>) -> CoseResultWithRet<CoseKey> {
        self.cose_keys
            .iter()
            .find(|key| key.kid.as_deref() == Some(kid))
            .cloned()
            .ok_or(CoseError::MissingKey())
    }
}
