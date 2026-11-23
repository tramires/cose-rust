use crate::algs;
use crate::errors::{CoseError, CoseField, CoseResultWithRet};
use crate::keys;
use cbor::decoder::DecodeError;
use cbor::{types::Type, Decoder};
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
    to_id: fn(&str) -> CoseResultWithRet<i32>,
) -> CoseResultWithRet<i32> {
    let t = match type_info {
        Some(v) => v,
        None => d.kernel().typeinfo()?,
    };
    if t.0 == Type::Text {
        let bytes = d.kernel().raw_data(t.1, MAX_BYTES)?;
        to_id(std::str::from_utf8(&bytes).map_err(|_| CoseError::InvalidCoseStructure)?)
    } else if CBOR_NUMBER_TYPES.contains(&t.0) {
        Ok(d.kernel().i32(&t)?)
    } else {
        Err(CoseError::InvalidCoseStructure)
    }
}

pub(crate) fn required<T>(field: &Option<T>, name: CoseField) -> Result<&T, CoseError> {
    field.as_ref().ok_or(CoseError::Missing(name))
}

fn id_of(names: &[&str], ids: &[i32], name: &str) -> Option<i32> {
    names
        .iter()
        .zip(ids)
        .find(|(n, _)| **n == name)
        .map(|(_, &id)| id)
}

pub(crate) fn get_alg_id(alg: &str) -> CoseResultWithRet<i32> {
    [
        (&algs::SIGNING_ALGS_NAMES[..], &algs::SIGNING_ALGS[..]),
        (&algs::ENCRYPT_ALGS_NAMES[..], &algs::ENCRYPT_ALGS[..]),
        (&algs::MAC_ALGS_NAMES[..], &algs::MAC_ALGS[..]),
        (&algs::HASH_ALGS_NAMES[..], &algs::HASH_ALGS[..]),
        (
            &algs::KEY_DISTRIBUTION_NAMES[..],
            &algs::KEY_DISTRIBUTION_ALGS[..],
        ),
    ]
    .iter()
    .find_map(|(names, ids)| id_of(names, ids, &alg))
    .ok_or(CoseError::Invalid(CoseField::Alg))
}

pub(crate) fn get_kty_id(kty: &str) -> CoseResultWithRet<i32> {
    id_of(&keys::KTY_NAMES, &keys::KTY_ALL, &kty).ok_or_else(|| CoseError::Invalid(CoseField::Kty))
}

pub(crate) fn get_crv_id(crv: &str) -> CoseResultWithRet<i32> {
    id_of(&keys::CURVES_NAMES, &keys::CURVES_ALL, &crv)
        .ok_or_else(|| CoseError::Invalid(CoseField::Crv))
}
pub(crate) fn get_key_op_id(key_op: &str) -> CoseResultWithRet<i32> {
    id_of(&keys::KEY_OPS_NAMES, &keys::KEY_OPS_ALL, &key_op)
        .ok_or_else(|| CoseError::Invalid(CoseField::KeyOp))
}

pub(crate) fn ph_bstr(bytes: Result<Vec<u8>, DecodeError>) -> CoseResultWithRet<Vec<u8>> {
    let value = bytes.map_err(|_| CoseError::InvalidCoseStructure)?;
    Ok(if value == [0xA0] { Vec::new() } else { value })
}
