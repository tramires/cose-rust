use crate::algs;
use crate::errors::{CoseError, CoseField, CoseResultWithRet};
use crate::keys;
use cbor::decoder::DecodeError;
use cbor::{types::Type, Config, Decoder, Encoder};
use std::io::Cursor;

pub(crate) const MAX_BYTES: usize = 0x500000;
pub(crate) const CBOR_NUMBER_TYPES: [Type; 8] = [
    Type::UInt16,
    Type::UInt32,
    Type::UInt64,
    Type::UInt8,
    Type::Int16,
    Type::Int32,
    Type::Int64,
    Type::Int8,
];

pub(crate) fn allows(key_ops: &[i32], op: i32) -> bool {
    key_ops.is_empty() || key_ops.contains(&op)
}

pub(crate) fn text_int_to_id(
    d: &mut Decoder<Cursor<Vec<u8>>>,
    type_info: Option<(Type, u8)>,
    to_id: fn(String) -> CoseResultWithRet<i32>,
) -> CoseResultWithRet<i32> {
    let t = match type_info {
        Some(v) => v,
        None => d.kernel().typeinfo()?,
    };
    if t.0 == Type::Text {
        let bytes = d.kernel().raw_data(t.1, MAX_BYTES)?;
        to_id(String::from_utf8(bytes).map_err(|_| CoseError::InvalidCoseStructure())?)
    } else if CBOR_NUMBER_TYPES.contains(&t.0) {
        Ok(d.kernel().i32(&t)?)
    } else {
        Err(CoseError::InvalidCoseStructure())
    }
}

pub(crate) fn required<T>(field: &Option<T>, name: CoseField) -> Result<&T, CoseError> {
    field.as_ref().ok_or(CoseError::Missing(name))
}

pub(crate) fn get_alg_id(alg: String) -> CoseResultWithRet<i32> {
    algs::SIGNING_ALGS_NAMES
        .iter()
        .zip(algs::SIGNING_ALGS.iter())
        .chain(
            algs::ENCRYPT_ALGS_NAMES
                .iter()
                .zip(algs::ENCRYPT_ALGS.iter()),
        )
        .chain(algs::MAC_ALGS_NAMES.iter().zip(algs::MAC_ALGS.iter()))
        .chain(algs::HASH_ALGS_NAMES.iter().zip(algs::HASH_ALGS.iter()))
        .chain(
            algs::KEY_DISTRIBUTION_NAMES
                .iter()
                .zip(algs::KEY_DISTRIBUTION_ALGS.iter()),
        )
        .find(|(name, _)| **name == alg)
        .map(|(_, &val)| val)
        .ok_or_else(|| CoseError::Invalid(CoseField::Alg))
}

pub(crate) fn get_kty_id(kty: String) -> CoseResultWithRet<i32> {
    keys::KTY_NAMES
        .iter()
        .zip(keys::KTY_ALL.iter())
        .find(|(name, _)| **name == kty)
        .map(|(_, &val)| val)
        .ok_or_else(|| CoseError::Invalid(CoseField::Kty))
}

pub(crate) fn get_crv_id(crv: String) -> CoseResultWithRet<i32> {
    keys::CURVES_NAMES
        .iter()
        .zip(keys::CURVES_ALL.iter())
        .find(|(name, _)| **name == crv)
        .map(|(_, &val)| val)
        .ok_or_else(|| CoseError::Invalid(CoseField::Crv))
}
pub(crate) fn get_key_op_id(key_op: String) -> CoseResultWithRet<i32> {
    keys::KEY_OPS_NAMES
        .iter()
        .zip(keys::KEY_OPS_ALL.iter())
        .find(|(name, _)| **name == key_op)
        .map(|(_, &val)| val)
        .ok_or_else(|| CoseError::Invalid(CoseField::KeyOp))
}

pub(crate) fn ph_bstr(bytes: Result<Vec<u8>, DecodeError>) -> CoseResultWithRet<Vec<u8>> {
    match bytes {
        Ok(value) => {
            if value.len() == 1 && value[0] == 160 {
                Ok(Vec::new())
            } else {
                Ok(value)
            }
        }
        Err(_) => Err(CoseError::InvalidCoseStructure()),
    }
}
