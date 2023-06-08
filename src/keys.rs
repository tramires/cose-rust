//! Module to encode/decode cose-keys/cose-keySet.
use crate::algs;
use crate::common;
use crate::errors::{CoseError, CoseResult, CoseResultWithRet};
use cbor::{decoder::DecodeError, types::Type, Config, Decoder, Encoder};
use std::io::Cursor;
use std::str::from_utf8;

const DER_S: [u8; 16] = [48, 46, 2, 1, 0, 48, 5, 6, 3, 43, 101, 112, 4, 34, 4, 32];
const DER_P: [u8; 12] = [48, 42, 48, 5, 6, 3, 43, 101, 112, 3, 33, 0];
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

//KEY TYPES
pub const OKP: i32 = 1;
pub const EC2: i32 = 2;
pub const SYMMETRIC: i32 = 4;
pub const RESERVED: i32 = 0;
pub(crate) const KTY_ALL: [i32; 4] = [RESERVED, OKP, EC2, SYMMETRIC];
pub(crate) const KTY_NAMES: [&str; 4] = ["Reserved", "OKP", "EC2", "Symmetric"];

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
pub const P_384: i32 = 2;
pub const P_521: i32 = 3;
pub const X25519: i32 = 4;
pub const X448: i32 = 5;
pub const ED25519: i32 = 6;
pub const ED448: i32 = 7;
pub(crate) const CURVES_ALL: [i32; 7] = [P_256, P_384, P_521, X25519, X448, ED25519, ED448];
pub(crate) const EC2_CRVS: [i32; 3] = [P_256, P_384, P_521];
pub(crate) const CURVES_NAMES: [&str; 7] = [
    "P-256", "P-384", "P-521", "X25519", "X448", "Ed25519", "Ed448",
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
    /// Private Key D parameter for OKP/EC2 Keys.
    pub d: Option<Vec<u8>>,
    /// Key value for Symmetric Keys.
    pub k: Option<Vec<u8>>,
    /// Key ID.
    pub kid: Option<Vec<u8>>,
    /// COSE curve for OKP/EC2 keys.
    pub crv: Option<i32>,
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
            d: None,
            k: None,
            kid: None,
            crv: None,
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
        self.reg_label(Y);
        self.y = Some(y);
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

    pub(crate) fn verify_curve(&self) -> CoseResult {
        let kty = self.kty.ok_or(CoseError::MissingKTY())?;
        if kty == SYMMETRIC {
            return Ok(());
        }
        let crv = self.crv.ok_or(CoseError::MissingCRV())?;

        if kty == OKP && crv == ED25519 {
            Ok(())
        } else if kty == EC2 && EC2_CRVS.contains(&crv) {
            Ok(())
        } else {
            Err(CoseError::InvalidCRV())
        }
    }

    pub(crate) fn verify_kty(&self) -> CoseResult {
        self.verify_curve()?;
        let kty = self.kty.ok_or(CoseError::MissingKTY())?;
        let alg = self.alg.ok_or(CoseError::MissingAlg())?;

        if kty == OKP && algs::OKP_ALGS.contains(&alg) {
            Ok(())
        } else if kty == EC2 && algs::EC2_ALGS.contains(&alg) {
            Ok(())
        } else if kty == SYMMETRIC && algs::SYMMETRIC_ALGS.contains(&alg) {
            Ok(())
        } else {
            Err(CoseError::InvalidKTY())
        }
    }

    /// Method to encode the cose-Key.
    pub fn encode(&mut self) -> CoseResult {
        let mut e = Encoder::new(Vec::new());
        self.verify_kty()?;
        self.encode_key(&mut e)?;
        self.bytes = e.into_writer().to_vec();
        Ok(())
    }

    pub(crate) fn encode_key(&self, e: &mut Encoder<Vec<u8>>) -> CoseResult {
        let kty = self.kty.ok_or(CoseError::MissingKTY())?;
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
                } else {
                    e.bytes(&self.k.as_ref().ok_or(CoseError::MissingK())?)?;
                }
            } else if *i == KID {
                e.bytes(&self.kid.as_ref().ok_or(CoseError::MissingKID())?)?;
            } else if *i == ALG {
                e.i32(self.alg.ok_or(CoseError::MissingAlg())?)?
            } else if *i == BASE_IV {
                e.bytes(&self.base_iv.as_ref().ok_or(CoseError::MissingBaseIV())?)?
            } else if *i == X {
                e.bytes(&self.x.as_ref().ok_or(CoseError::MissingX())?)?
            } else if *i == Y {
                e.bytes(&self.y.as_ref().ok_or(CoseError::MissingY())?)?
            } else if *i == D {
                e.bytes(&self.d.as_ref().ok_or(CoseError::MissingD())?)?
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
        self.verify_kty()?;
        self.decode_key(&mut d)?;
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
                if self.kty.ok_or(CoseError::MissingKTY())? == SYMMETRIC {
                    self.k = Some(d.bytes()?);
                } else {
                    let type_info = d.kernel().typeinfo()?;
                    if type_info.0 == Type::Text {
                        self.crv = Some(common::get_crv_id(
                            from_utf8(&d.kernel().raw_data(type_info.1, common::MAX_BYTES)?)
                                .unwrap()
                                .to_string(),
                        )?);
                    } else if common::CBOR_NUMBER_TYPES.contains(&type_info.0) {
                        self.crv = Some(d.kernel().i32(&type_info)?);
                    } else {
                        return Err(CoseError::InvalidCoseStructure());
                    }
                }
                self.used.push(label);
            } else if label == X {
                self.x = Some(d.bytes()?);
                self.used.push(label);
            } else if label == Y {
                self.y = match d.bytes() {
                    Ok(value) => {
                        self.used.push(label);
                        Some(value)
                    }
                    Err(ref err) => match err {
                        DecodeError::UnexpectedType { datatype, info: _ } => {
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
            } else if label == D {
                self.d = Some(d.bytes()?);
                self.used.push(label);
            } else {
                return Err(CoseError::InvalidLabel(label));
            }
        }
        Ok(())
    }

    pub(crate) fn get_s_key(&self) -> CoseResultWithRet<Vec<u8>> {
        let mut s_key = Vec::new();
        let alg = self.alg.ok_or(CoseError::MissingAlg())?;
        if algs::SIGNING_ALGS.contains(&alg) || algs::ECDH_ALGS.contains(&alg) {
            let mut d = self.d.as_ref().ok_or(CoseError::MissingD())?.to_vec();
            if d.len() <= 0 {
                return Err(CoseError::MissingD());
            }
            if algs::EDDSA == alg {
                s_key = DER_S.to_vec();
                s_key.append(&mut d);
            } else {
                s_key = d;
            }
        } else if algs::MAC_ALGS.contains(&alg)
            || algs::ENCRYPT_ALGS.contains(&alg)
            || algs::KEY_DISTRIBUTION_ALGS.contains(&alg)
        {
            let k = self.k.as_ref().ok_or(CoseError::MissingK())?.to_vec();
            if k.len() <= 0 {
                return Err(CoseError::MissingK());
            }
            s_key = k;
        }
        Ok(s_key)
    }
    pub(crate) fn get_pub_key(&self, alg: i32) -> CoseResultWithRet<Vec<u8>> {
        let mut pub_key: Vec<u8>;
        if algs::SIGNING_ALGS.contains(&alg) || algs::ECDH_ALGS.contains(&alg) {
            let mut x = self.x.as_ref().ok_or(CoseError::MissingX())?.to_vec();
            if x.len() <= 0 {
                return Err(CoseError::MissingX());
            }
            if algs::EDDSA == alg {
                pub_key = DER_P.to_vec();
                pub_key.append(&mut x);
            } else {
                if self.y == None {
                    pub_key = vec![3];
                    pub_key.append(&mut x);
                } else {
                    let mut y = self.y.as_ref().ok_or(CoseError::MissingY())?.to_vec();
                    pub_key = vec![4];
                    pub_key.append(&mut x);
                    pub_key.append(&mut y);
                }
            }
        } else {
            return Err(CoseError::InvalidAlg());
        }
        Ok(pub_key)
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
