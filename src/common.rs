use crate::algs;
use crate::errors::{CoseError, CoseField, CoseResultWithRet};
use crate::keys;
use cbor::{decoder::DecodeError, types::Type};

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
        Ok(value) => Ok(value),
        Err(ref err) => match err {
            DecodeError::UnexpectedType { datatype, info } => {
                if *datatype == Type::Object && *info == 0 {
                    Ok(Vec::new())
                } else {
                    Err(CoseError::InvalidCoseStructure())
                }
            }
            _ => Err(CoseError::InvalidCoseStructure()),
        },
    }
}
