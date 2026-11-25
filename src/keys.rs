#![doc = include_str!("../docs/keys.md")]
use crate::common::{get_alg_id, get_crv_id, get_key_op_id, get_kty_id, text_int_to_id, MAX_BYTES};
use crate::errors::{CoseError, CoseField, CoseResult, CoseResultWithRet};
use cbor::{types::Type, Config, Decoder, Encoder};
use openssl::bn::BigNum;
use openssl::rsa::Rsa;
use std::io::Cursor;

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
pub(crate) const KTY_NAMES: &[(&str, i32)] = &[
    ("Reserved", RESERVED),
    ("OKP", OKP),
    ("EC2", EC2),
    ("RSA", RSA),
    ("Symmetric", SYMMETRIC),
];

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
pub(crate) const KEY_OP_NAMES: &[(&str, i32)] = &[
    ("sign", KEY_OPS_SIGN),
    ("verify", KEY_OPS_VERIFY),
    ("encrypt", KEY_OPS_ENCRYPT),
    ("decrypt", KEY_OPS_DECRYPT),
    ("wrap key", KEY_OPS_WRAP),
    ("unwrap key", KEY_OPS_UNWRAP),
    ("derive key", KEY_OPS_DERIVE),
    ("derive bits", KEY_OPS_DERIVE_BITS),
    ("MAC create", KEY_OPS_MAC),
    ("MAC verify", KEY_OPS_MAC_VERIFY),
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
pub(crate) const EC2_CRVS: [i32; 4] = [P_256, P_384, P_521, SECP256K1];
pub(crate) const CURVE_NAMES: &[(&str, i32)] = &[
    ("P-256", P_256),
    ("P-384", P_384),
    ("P-521", P_521),
    ("X25519", X25519),
    ("X448", X448),
    ("Ed25519", ED25519),
    ("Ed448", ED448),
    ("secp256k1", SECP256K1),
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
#[doc = include_str!("../docs/CoseKey.md")]
pub struct CoseKey {
    /// cose-key encoded bytes.
    pub bytes: Vec<u8>,
    used: Vec<i32>,
    pub(crate) kty: Option<i32>,
    pub(crate) base_iv: Option<Vec<u8>>,
    pub(crate) key_ops: Vec<i32>,
    pub(crate) alg: Option<i32>,
    pub(crate) x: Option<Vec<u8>>,
    pub(crate) y: Option<Vec<u8>>,
    pub(crate) y_parity: Option<bool>,
    pub(crate) d: Option<Vec<u8>>,
    pub(crate) k: Option<Vec<u8>>,
    pub(crate) kid: Option<Vec<u8>>,
    pub(crate) crv: Option<i32>,
    pub(crate) n: Option<Vec<u8>>,
    pub(crate) e: Option<Vec<u8>>,
    pub(crate) rsa_d: Option<Vec<u8>>,
    pub(crate) p: Option<Vec<u8>>,
    pub(crate) q: Option<Vec<u8>>,
    pub(crate) dp: Option<Vec<u8>>,
    pub(crate) dq: Option<Vec<u8>>,
    pub(crate) qinv: Option<Vec<u8>>,
    pub(crate) other: Option<Vec<Vec<Vec<u8>>>>,
}

impl CoseKey {
    /// Creates an empty CoseKey structure
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    getters! { copy:
        /// Key type.
        kty -> Option<i32>,
        /// Algorithm the key is restricted to.
        alg -> Option<i32>,
        /// EC2/OKP curve
        crv -> Option<i32>,
        /// Sign bit of the y-coordinate for compressed EC2 points.
        y_parity-> Option<bool>,
    }

    getters! { by_ref:
        /// Permitted key operations
        key_ops -> &[i32],
    }

    getters! { deref:
        /// Key Identifier.
        kid -> Option<&[u8]>,
        /// Base initialization vector.
        base_iv -> Option<&[u8]>,
        /// EC2/OKP x-coordinate.
        x -> Option<&[u8]>,
        /// EC2 y-coordinate.
        y -> Option<&[u8]>,
        /// EC2/OKP private key.
        d -> Option<&[u8]>,
        /// Symmetric key.
        k -> Option<&[u8]>,
        /// RSA modulus.
        n -> Option<&[u8]>,
        /// RSA public exponent.
        e -> Option<&[u8]>,
        /// RSA private exponent.
        rsa_d -> Option<&[u8]>,
        /// RSA first prime factor.
        p -> Option<&[u8]>,
        /// RSA second prime factor.
        q -> Option<&[u8]>,
        /// RSA first factor CRT exponent.
        dp -> Option<&[u8]>,
        /// RSA second factor CRT exponent.
        dq -> Option<&[u8]>,
        /// RSA first CRT coefficient.
        qinv -> Option<&[u8]>,
        /// RSA other primes information, (r_i, d_i, t_i).
        other -> Option<&[Vec<Vec<u8>>]>,
    }

    fn reg_label(&mut self, label: i32) {
        self.used.retain(|&x| x != label);
        self.used.push(label);
    }

    pub(crate) fn remove_label(&mut self, label: i32) {
        self.used.retain(|&x| x != label);
    }

    /// Adds the algorithm identifier
    pub fn set_alg(&mut self, alg: i32) {
        self.reg_label(ALG);
        self.alg = Some(alg);
    }

    /// Adds the Key Type
    pub fn set_kty(&mut self, kty: i32) {
        self.reg_label(KTY);
        self.kty = Some(kty);
    }
    /// Removes the algorithm identifier
    pub fn unset_alg(&mut self) {
        self.remove_label(ALG);
        self.alg = None;
    }

    /// Adds the key ID
    pub fn set_kid(&mut self, kid: Vec<u8>) {
        self.reg_label(KID);
        self.kid = Some(kid);
    }

    /// Adds the key operations
    pub fn set_key_ops(&mut self, key_ops: Vec<i32>) {
        self.reg_label(KEY_OPS);
        self.key_ops = key_ops;
    }

    /// Adds the base IV
    pub fn set_base_iv(&mut self, base_iv: Vec<u8>) {
        self.reg_label(BASE_IV);
        self.base_iv = Some(base_iv);
    }

    /// Adds the EC2/OKP curve
    pub fn set_crv(&mut self, crv: i32) {
        self.reg_label(CRV_K);
        self.crv = Some(crv);
    }

    /// Adds the EC2/OKP X-coordinate
    pub fn set_x(&mut self, x: Vec<u8>) {
        self.reg_label(X);
        self.x = Some(x);
    }

    /// Adds the EC2 Y-coordinate
    pub fn set_y(&mut self, y: Vec<u8>) {
        self.y_parity = None;
        self.reg_label(Y);
        self.y = Some(y);
    }

    /// Adds the sign bit of the y-coordinate for compressed EC2 points.
    pub fn set_y_parity(&mut self, parity: bool) {
        self.y = None;
        self.reg_label(Y);
        self.y_parity = Some(parity);
    }

    /// Adds the EC2/OKP private key.
    pub fn set_d(&mut self, d: Vec<u8>) {
        self.reg_label(D);
        self.d = Some(d);
    }

    /// Adds the symmetric key
    pub fn set_k(&mut self, k: Vec<u8>) {
        self.reg_label(CRV_K);
        self.k = Some(k);
    }

    /// Adds RSA modulus
    pub fn set_n(&mut self, n: Vec<u8>) {
        self.reg_label(N);
        self.n = Some(n);
    }

    /// Adds RSA public exponent
    pub fn set_e(&mut self, e: Vec<u8>) {
        self.reg_label(E);
        self.e = Some(e);
    }

    /// Adds RSA private exponent
    pub fn set_rsa_d(&mut self, rsa_d: Vec<u8>) {
        self.reg_label(RSA_D);
        self.rsa_d = Some(rsa_d);
    }

    /// Adds RSA first prime factor.
    pub fn set_p(&mut self, p: Vec<u8>) {
        self.reg_label(P);
        self.p = Some(p);
    }

    /// Adds RSA second prime factor.
    pub fn set_q(&mut self, q: Vec<u8>) {
        self.reg_label(Q);
        self.q = Some(q);
    }

    /// Adds RSA first factor CRT exponent.
    pub fn set_dp(&mut self, dp: Vec<u8>) {
        self.reg_label(DP);
        self.dp = Some(dp);
    }

    /// Adds RSA second factor CRT exponent.
    pub fn set_dq(&mut self, dq: Vec<u8>) {
        self.reg_label(DQ);
        self.dq = Some(dq);
    }

    /// Adds RSA first CRT coefficient.
    pub fn set_qinv(&mut self, qinv: Vec<u8>) {
        self.reg_label(QINV);
        self.qinv = Some(qinv);
    }

    /// RSA other primes information, (r_i, d_i, t_i).
    pub fn set_other(&mut self, other: Vec<Vec<Vec<u8>>>) {
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

    /// Encodes the cose-Key.
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
                        return Err(CoseError::Invalid(CoseField::OtherPrimes));
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
                        return Err(CoseError::Invalid(CoseField::OtherPrimes));
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
                        .ok_or(CoseError::Missing(CoseField::OtherPrimes))?;
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

    /// Decodes the cose-Key.
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
                        return Err(CoseError::InvalidCoseStructure);
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
                            return Err(CoseError::Invalid(CoseField::OtherPrimes));
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
                                return Err(CoseError::Invalid(CoseField::OtherPrimes));
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
            RSA if self.other.is_some() => {
                return Err(CoseError::Invalid(CoseField::OtherPrimes));
            }
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
                let x = self
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
#[doc = include_str!("../docs/CoseKeySet.md")]
pub struct CoseKeySet {
    /// List of the cose-keys.
    pub keys: Vec<CoseKey>,
    /// COSE encoded key set.
    pub bytes: Vec<u8>,
}

impl CoseKeySet {
    /// Creates a new empty structure.
    pub fn new() -> CoseKeySet {
        CoseKeySet {
            keys: Vec::new(),
            bytes: Vec::new(),
        }
    }

    /// Adds a cose-key to the cose-keySet.
    pub fn add_key(&mut self, key: &CoseKey) {
        self.keys.push(key.clone());
    }

    /// Encodes the cose-keySet.
    pub fn encode(&mut self) -> CoseResult {
        if self.keys.is_empty() {
            return Err(CoseError::MissingKey);
        }
        let mut e = Encoder::new(Vec::new());
        e.array(self.keys.len())?;
        for key in &self.keys {
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
            return Err(CoseError::MissingKey);
        }
        self.keys = (0..len)
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
        self.keys
            .iter()
            .find(|key| key.kid.as_deref() == Some(kid))
            .cloned()
            .ok_or(CoseError::MissingKey)
    }
}
