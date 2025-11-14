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
//!     key_set.add_key(decode_key);
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

use crate::algs;
use crate::common;
use crate::errors::{CoseError, CoseResult, CoseResultWithRet};
use cbor::{decoder::DecodeError, types::Type, Config, Decoder, Encoder};
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

/// cose-key structure.
#[derive(Clone)]
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
    pub fn new() -> CoseKey {
        CoseKey {
            bytes: Vec::new(),
            used: Vec::new(),
            key_ops: Vec::new(),
            base_iv: None,
            kty: None,
            alg: None,
            x: None,
            y: None,
            y_parity: None,
            d: None,
            k: None,
            kid: None,
            crv: None,
            n: None,
            e: None,
            rsa_d: None,
            p: None,
            q: None,
            dp: None,
            dq: None,
            qinv: None,
            other: None,
        }
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
    /// Adds Key ID to the cose-key.
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
    pub fn n(&mut self, n: Vec<u8>) {
        self.reg_label(N);
        self.n = Some(n);
    }
    pub fn e(&mut self, e: Vec<u8>) {
        self.reg_label(E);
        self.e = Some(e);
    }
    pub fn rsa_d(&mut self, rsa_d: Vec<u8>) {
        self.reg_label(RSA_D);
        self.rsa_d = Some(rsa_d);
    }
    pub fn p(&mut self, p: Vec<u8>) {
        self.reg_label(P);
        self.p = Some(p);
    }
    pub fn q(&mut self, q: Vec<u8>) {
        self.reg_label(Q);
        self.q = Some(q);
    }
    pub fn dp(&mut self, dp: Vec<u8>) {
        self.reg_label(DP);
        self.dp = Some(dp);
    }
    pub fn dq(&mut self, dq: Vec<u8>) {
        self.reg_label(DQ);
        self.dq = Some(dq);
    }
    pub fn qinv(&mut self, qinv: Vec<u8>) {
        self.reg_label(QINV);
        self.qinv = Some(qinv);
    }
    pub fn other(&mut self, other: Vec<Vec<Vec<u8>>>) {
        self.reg_label(OTHER);
        self.other = Some(other);
    }

    pub(crate) fn verify_curve(&self) -> CoseResult {
        let kty = self.kty.ok_or(CoseError::MissingKTY())?;
        if kty == SYMMETRIC || kty == RSA {
            return Ok(());
        }
        let crv = self.crv.ok_or(CoseError::MissingCRV())?;

        if kty == OKP && [ED25519, ED448, X25519, X448].contains(&crv) {
            Ok(())
        } else if kty == EC2 && EC2_CRVS.contains(&crv) {
            Ok(())
        } else {
            Err(CoseError::InvalidCRV())
        }
    }

    pub(crate) fn verify_kty(&self) -> CoseResult {
        if !KTY_ALL.contains(&self.kty.ok_or(CoseError::MissingKTY())?) {
            return Err(CoseError::InvalidKTY());
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
        self.bytes = e.into_writer().to_vec();
        Ok(())
    }

    pub(crate) fn verify_key_ops(&self) -> CoseResult {
        let kty = self.kty.ok_or(CoseError::MissingKTY())?;
        if !self.key_ops.is_empty() {
            match kty {
                EC2 | OKP => {
                    if self.key_ops.contains(&KEY_OPS_VERIFY) {
                        if self.x == None {
                            return Err(CoseError::MissingX());
                        } else if kty == EC2 && self.y.is_none() && self.y_parity.is_none() {
                            return Err(CoseError::MissingY());
                        } else if self.crv == None {
                            return Err(CoseError::MissingCRV());
                        }
                    }
                    if self.key_ops.contains(&KEY_OPS_SIGN)
                        || self.key_ops.contains(&KEY_OPS_DERIVE)
                        || self.key_ops.contains(&KEY_OPS_DERIVE_BITS)
                    {
                        if self.d == None {
                            return Err(CoseError::MissingD());
                        } else if self.crv == None {
                            return Err(CoseError::MissingCRV());
                        }
                    }
                }
                SYMMETRIC => {
                    if self.key_ops.contains(&KEY_OPS_ENCRYPT)
                        || self.key_ops.contains(&KEY_OPS_MAC_VERIFY)
                        || self.key_ops.contains(&KEY_OPS_MAC)
                        || self.key_ops.contains(&KEY_OPS_DECRYPT)
                        || self.key_ops.contains(&KEY_OPS_UNWRAP)
                        || self.key_ops.contains(&KEY_OPS_WRAP)
                    {
                        if self.x != None {
                            return Err(CoseError::MissingX());
                        } else if self.y.is_some() || self.y_parity.is_some() {
                            return Err(CoseError::MissingY());
                        } else if self.d != None {
                            return Err(CoseError::MissingD());
                        }
                        if self.k == None {
                            return Err(CoseError::MissingK());
                        }
                    }
                }
                RSA => {
                    if self.key_ops.contains(&KEY_OPS_VERIFY) {
                        if self.n.is_none() {
                            return Err(CoseError::MissingN());
                        } else if self.e.is_none() {
                            return Err(CoseError::MissingE());
                        } else if [
                            &self.rsa_d,
                            &self.p,
                            &self.q,
                            &self.dp,
                            &self.dq,
                            &self.qinv,
                        ]
                        .iter()
                        .any(|v| v.is_some())
                            || self.other.is_some()
                        {
                            return Err(CoseError::MissingE());
                        }
                    }
                    if self.key_ops.contains(&KEY_OPS_SIGN)
                        || self.key_ops.contains(&KEY_OPS_DERIVE)
                        || self.key_ops.contains(&KEY_OPS_DERIVE_BITS)
                    {
                        if [
                            &self.n,
                            &self.e,
                            &self.rsa_d,
                            &self.p,
                            &self.q,
                            &self.dp,
                            &self.dq,
                            &self.qinv,
                        ]
                        .iter()
                        .any(|v| v.is_none())
                        {
                            return Err(CoseError::MissingE());
                        }
                        if self.other.is_some() {
                            for primes in self.other.as_ref().unwrap() {
                                if primes.len() != 3 {
                                    return Err(CoseError::InvalidOther());
                                }
                            }
                        }
                    }
                }
                _ => {
                    return Err(CoseError::InvalidKTY());
                }
            }
        }
        return Ok(());
    }

    pub(crate) fn encode_key(&self, e: &mut Encoder<Vec<u8>>) -> CoseResult {
        let kty = self.kty.ok_or(CoseError::MissingKTY())?;
        self.verify_key_ops()?;
        let key_ops_len = self.key_ops.len();
        if key_ops_len > 0 {
            if kty == EC2 || kty == OKP {
                if self.key_ops.contains(&KEY_OPS_VERIFY)
                    || self.key_ops.contains(&KEY_OPS_DERIVE)
                    || self.key_ops.contains(&KEY_OPS_DERIVE_BITS)
                {
                    if self.x == None {
                        return Err(CoseError::MissingX());
                    } else if self.crv == None {
                        return Err(CoseError::MissingCRV());
                    }
                }
                if self.key_ops.contains(&KEY_OPS_SIGN) {
                    if self.d == None {
                        return Err(CoseError::MissingD());
                    } else if self.crv == None {
                        return Err(CoseError::MissingCRV());
                    }
                }
            } else if kty == SYMMETRIC {
                if self.key_ops.contains(&KEY_OPS_ENCRYPT)
                    || self.key_ops.contains(&KEY_OPS_MAC_VERIFY)
                    || self.key_ops.contains(&KEY_OPS_MAC)
                    || self.key_ops.contains(&KEY_OPS_DECRYPT)
                    || self.key_ops.contains(&KEY_OPS_UNWRAP)
                    || self.key_ops.contains(&KEY_OPS_WRAP)
                {
                    if self.x != None {
                        return Err(CoseError::InvalidX());
                    } else if self.y != None {
                        return Err(CoseError::InvalidY());
                    } else if self.d != None {
                        return Err(CoseError::InvalidD());
                    }
                    if self.k == None {
                        return Err(CoseError::MissingK());
                    }
                }
            }
        }
        e.object(self.used.len())?;
        for i in &self.used {
            e.i32(*i)?;

            if *i == KTY {
                e.i32(kty)?;
            } else if *i == KEY_OPS {
                e.array(self.key_ops.len())?;
                for x in &self.key_ops {
                    e.i32(*x)?;
                }
            } else if *i == CRV_K {
                if self.crv != None {
                    e.i32(self.crv.ok_or(CoseError::MissingCRV())?)?;
                } else if self.kty.ok_or(CoseError::MissingKTY())? == RSA {
                    e.bytes(&self.n.as_ref().ok_or(CoseError::MissingN())?)?;
                } else {
                    e.bytes(&self.k.as_ref().ok_or(CoseError::MissingK())?)?;
                }
            } else if *i == KID {
                e.bytes(&self.kid.as_ref().ok_or(CoseError::MissingKID())?)?;
            } else if *i == ALG {
                e.i32(self.alg.ok_or(CoseError::MissingAlg())?)?;
            } else if *i == BASE_IV {
                e.bytes(&self.base_iv.as_ref().ok_or(CoseError::MissingBaseIV())?)?;
            } else if *i == X {
                if self.kty.ok_or(CoseError::MissingKTY())? == RSA {
                    e.bytes(&self.e.as_ref().ok_or(CoseError::MissingE())?)?;
                } else {
                    e.bytes(&self.x.as_ref().ok_or(CoseError::MissingX())?)?;
                }
            } else if *i == Y {
                if self.kty.ok_or(CoseError::MissingKTY())? == RSA {
                    e.bytes(&self.rsa_d.as_ref().ok_or(CoseError::MissingRsaD())?)?;
                } else {
                    if self.y_parity.is_none() {
                        e.bytes(&self.y.as_ref().ok_or(CoseError::MissingY())?)?;
                    } else {
                        e.bool(self.y_parity.ok_or(CoseError::MissingY())?)?;
                    }
                }
            } else if *i == D {
                if self.kty.ok_or(CoseError::MissingKTY())? == RSA {
                    e.bytes(&self.p.as_ref().ok_or(CoseError::MissingP())?)?;
                } else {
                    e.bytes(&self.d.as_ref().ok_or(CoseError::MissingD())?)?;
                }
            } else if *i == Q {
                e.bytes(&self.q.as_ref().ok_or(CoseError::MissingQ())?)?
            } else if *i == DP {
                e.bytes(&self.dp.as_ref().ok_or(CoseError::MissingDP())?)?
            } else if *i == DQ {
                e.bytes(&self.dq.as_ref().ok_or(CoseError::MissingDQ())?)?
            } else if *i == QINV {
                e.bytes(&self.qinv.as_ref().ok_or(CoseError::MissingQINV())?)?
            } else if *i == OTHER {
                let other = self.other.as_ref().ok_or(CoseError::MissingOther())?;
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
            } else {
                return Err(CoseError::InvalidLabel(*i));
            }
        }
        Ok(())
    }

    /// Method to decode a cose-Key.
    pub fn decode(&mut self) -> CoseResult {
        let input = Cursor::new(self.bytes.clone());
        let mut d = Decoder::new(Config::default(), input);
        self.decode_key(&mut d)?;
        if self.alg != None {
            self.verify_kty()?;
        } else {
            self.verify_curve()?;
        }
        Ok(())
    }

    pub(crate) fn decode_key(&mut self, d: &mut Decoder<Cursor<Vec<u8>>>) -> CoseResult {
        let mut label: i32;
        let mut labels_found = Vec::new();
        self.used = Vec::new();
        for _ in 0..d.object()? {
            label = d.i32()?;
            if !labels_found.contains(&label) {
                labels_found.push(label);
            } else {
                return Err(CoseError::DuplicateLabel(label));
            }
            if label == KTY {
                let type_info = d.kernel().typeinfo()?;
                if type_info.0 == Type::Text {
                    self.kty = Some(common::get_kty_id(
                        from_utf8(&d.kernel().raw_data(type_info.1, common::MAX_BYTES)?)
                            .unwrap()
                            .to_string(),
                    )?);
                } else if common::CBOR_NUMBER_TYPES.contains(&type_info.0) {
                    self.kty = Some(d.kernel().i32(&type_info)?);
                } else {
                    return Err(CoseError::InvalidCoseStructure());
                }
                self.used.push(label);
            } else if label == ALG {
                let type_info = d.kernel().typeinfo()?;
                if type_info.0 == Type::Text {
                    self.alg = Some(common::get_alg_id(
                        from_utf8(&d.kernel().raw_data(type_info.1, common::MAX_BYTES)?)
                            .unwrap()
                            .to_string(),
                    )?);
                } else if common::CBOR_NUMBER_TYPES.contains(&type_info.0) {
                    self.alg = Some(d.kernel().i32(&type_info)?);
                } else {
                    return Err(CoseError::InvalidCoseStructure());
                }
                self.used.push(label);
            } else if label == KID {
                self.kid = Some(d.bytes()?);
                self.used.push(label);
            } else if label == KEY_OPS {
                let mut key_ops = Vec::new();
                for _i in 0..d.array()? {
                    let type_info = d.kernel().typeinfo()?;
                    if type_info.0 == Type::Text {
                        key_ops.push(common::get_key_op_id(
                            from_utf8(&d.kernel().raw_data(type_info.1, common::MAX_BYTES)?)
                                .unwrap()
                                .to_string(),
                        )?);
                    } else if common::CBOR_NUMBER_TYPES.contains(&type_info.0) {
                        key_ops.push(d.kernel().i32(&type_info)?);
                    } else {
                        return Err(CoseError::InvalidCoseStructure());
                    }
                }
                self.key_ops = key_ops;
                self.used.push(label);
            } else if label == BASE_IV {
                self.base_iv = Some(d.bytes()?);
                self.used.push(label);
            } else if label == CRV_K {
                let type_info = d.kernel().typeinfo()?;
                if type_info.0 == Type::Text {
                    self.crv = Some(common::get_crv_id(
                        from_utf8(&d.kernel().raw_data(type_info.1, common::MAX_BYTES)?)
                            .unwrap()
                            .to_string(),
                    )?);
                } else if common::CBOR_NUMBER_TYPES.contains(&type_info.0) {
                    self.crv = Some(d.kernel().i32(&type_info)?);
                } else if type_info.0 == Type::Bytes {
                    self.k = Some(d.kernel().raw_data(type_info.1, common::MAX_BYTES)?);
                } else {
                    return Err(CoseError::InvalidCoseStructure());
                }
                self.used.push(label);
            } else if label == X {
                self.x = Some(d.bytes()?);
                self.used.push(label);
            } else if label == Y {
                let type_info = d.kernel().typeinfo()?;
                if type_info.0 == Type::Bytes {
                    self.y = Some(d.kernel().raw_data(type_info.1, common::MAX_BYTES)?);
                } else if type_info.0 == Type::Bool {
                    self.y_parity = Some(d.kernel().bool(&type_info)?);
                } else {
                    return Err(CoseError::InvalidCoseStructure());
                }
                self.used.push(label);
            } else if label == D {
                self.d = Some(d.bytes()?);
                self.used.push(label);
            } else if label == Q {
                self.q = Some(d.bytes()?);
                self.used.push(label);
            } else if label == DP {
                self.dp = Some(d.bytes()?);
                self.used.push(label);
            } else if label == DQ {
                self.dq = Some(d.bytes()?);
                self.used.push(label);
            } else if label == QINV {
                self.qinv = Some(d.bytes()?);
                self.used.push(label);
            } else if label == OTHER {
                let mut other = Vec::new();
                for _ in 0..d.array()? {
                    if d.object()? != 3 {
                        return Err(CoseError::InvalidOther());
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
                            return Err(CoseError::InvalidOther());
                        }
                    }
                    other.push([ri, di, ti].to_vec());
                }
                self.other = Some(other);
                self.used.push(label);
            } else {
                return Err(CoseError::InvalidLabel(label));
            }
        }
        if self.kty.ok_or(CoseError::MissingKTY())? == RSA {
            if self.k.is_some() {
                self.n = std::mem::take(&mut self.k);
            }
            if self.x.is_some() {
                self.e = std::mem::take(&mut self.x);
            }
            if self.y.is_some() {
                self.rsa_d = std::mem::take(&mut self.y);
            }
            if self.d.is_some() {
                self.p = std::mem::take(&mut self.d);
            }
        }
        self.verify_key_ops()?;
        Ok(())
    }

    pub(crate) fn get_s_key(&self) -> CoseResultWithRet<Vec<u8>> {
        let kty = self.kty.ok_or(CoseError::MissingKTY())?;
        if kty == EC2 || kty == OKP {
            let d = self.d.as_ref().ok_or(CoseError::MissingD())?.to_vec();
            if d.len() <= 0 {
                return Err(CoseError::MissingD());
            }
            Ok(d)
        } else if kty == RSA {
            Ok(Rsa::from_private_components(
                BigNum::from_slice(self.n.as_ref().ok_or(CoseError::MissingN())?)?,
                BigNum::from_slice(self.e.as_ref().ok_or(CoseError::MissingE())?)?,
                BigNum::from_slice(self.rsa_d.as_ref().ok_or(CoseError::MissingRsaD())?)?,
                BigNum::from_slice(self.p.as_ref().ok_or(CoseError::MissingP())?)?,
                BigNum::from_slice(self.q.as_ref().ok_or(CoseError::MissingQ())?)?,
                BigNum::from_slice(self.dp.as_ref().ok_or(CoseError::MissingDP())?)?,
                BigNum::from_slice(self.dq.as_ref().ok_or(CoseError::MissingDQ())?)?,
                BigNum::from_slice(self.qinv.as_ref().ok_or(CoseError::MissingQINV())?)?,
            )?
            .private_key_to_der()?)
        } else if kty == SYMMETRIC {
            let k = self.k.as_ref().ok_or(CoseError::MissingK())?.to_vec();
            if k.len() <= 0 {
                return Err(CoseError::MissingK());
            }
            Ok(k)
        } else {
            Err(CoseError::InvalidKTY())
        }
    }
    pub(crate) fn get_pub_key(&self) -> CoseResultWithRet<Vec<u8>> {
        let kty = self.kty.ok_or(CoseError::MissingKTY())?;
        if kty == EC2 || kty == OKP {
            let mut x = self.x.as_ref().ok_or(CoseError::MissingX())?.to_vec();
            if x.len() <= 0 {
                return Err(CoseError::MissingX());
            }
            let mut pub_key;
            if kty == EC2 {
                if self.y != None && self.y.as_ref().unwrap().len() > 0 {
                    let mut y = self.y.as_ref().unwrap().to_vec();
                    pub_key = vec![4];
                    pub_key.append(&mut x);
                    pub_key.append(&mut y);
                } else {
                    if self.y_parity.is_some() {
                        if self.y_parity.unwrap() {
                            pub_key = vec![3];
                        } else {
                            pub_key = vec![2];
                        }
                    } else {
                        return Err(CoseError::MissingY());
                    }
                    pub_key.append(&mut x);
                }
            } else {
                pub_key = x;
            }
            Ok(pub_key)
        } else if kty == RSA {
            Ok(Rsa::from_public_components(
                BigNum::from_slice(self.n.as_ref().ok_or(CoseError::MissingN())?)?,
                BigNum::from_slice(self.e.as_ref().ok_or(CoseError::MissingE())?)?,
            )?
            .public_key_to_der()?)
        } else {
            Err(CoseError::InvalidKTY())
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
    pub fn add_key(&mut self, key: CoseKey) {
        self.cose_keys.push(key);
    }

    /// Encodes the cose-keySet.
    pub fn encode(&mut self) -> CoseResult {
        let mut e = Encoder::new(Vec::new());
        let len = self.cose_keys.len();
        if len > 0 {
            e.array(len)?;
            for i in 0..len {
                self.cose_keys[i].encode_key(&mut e)?;
            }
            self.bytes = e.into_writer().to_vec();
            Ok(())
        } else {
            Err(CoseError::MissingKey())
        }
    }

    /// Decodes an encoded cose-keySet.
    ///
    /// The COSE encoded bytes of the cose-keySet must be set with the structure attribute bytes beforehand.
    pub fn decode(&mut self) -> CoseResult {
        let input = Cursor::new(self.bytes.clone());
        let mut d = Decoder::new(Config::default(), input);
        let len = d.array()?;
        if len > 0 {
            for _ in 0..len {
                let mut cose_key = CoseKey::new();
                match cose_key.decode_key(&mut d) {
                    Ok(_v) => self.cose_keys.push(cose_key),
                    Err(_e) => (),
                }
            }
            Ok(())
        } else {
            Err(CoseError::MissingKey())
        }
    }

    /// Function that returns a cose-key from the cose-keySet with a given Key ID.
    pub fn get_key(&self, kid: &Vec<u8>) -> CoseResultWithRet<CoseKey> {
        for i in 0..self.cose_keys.len() {
            if self.cose_keys[i]
                .kid
                .as_ref()
                .ok_or(CoseError::MissingKID())?
                == kid
            {
                return Ok(self.cose_keys[i].clone());
            }
        }
        Err(CoseError::MissingKey())
    }
}
