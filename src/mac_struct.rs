use crate::algs;
use crate::errors::{CoseError, CoseResultWithRet};
use cbor::Encoder;

const MAC: &str = "MAC";
const MAC0: &str = "MAC0";
const MAC_ALL: [&str; 2] = [MAC, MAC0];
const MAC_STRUCT_LEN: usize = 4;

pub(in crate) fn gen_mac(
    key: &Vec<u8>,
    alg: &i32,
    aead: &Vec<u8>,
    context: &str,
    body_protected: &Vec<u8>,
    payload: &Vec<u8>,
) -> CoseResultWithRet<Vec<u8>> {
    let mut e = Encoder::new(Vec::new());
    if MAC_ALL.contains(&context) {
        e.array(MAC_STRUCT_LEN)?;
        e.text(context)?;
        e.bytes(body_protected.as_slice())?;
        e.bytes(aead.as_slice())?;
        e.bytes(payload.as_slice())?;
        algs::mac(*alg, &key, &e.into_writer().to_vec())
    } else {
        Err(CoseError::InvalidContext())
    }
}

pub(in crate) fn verify_mac(
    key: &Vec<u8>,
    alg: &i32,
    aead: &Vec<u8>,
    context: &str,
    body_protected: &Vec<u8>,
    tag: &Vec<u8>,
    payload: &Vec<u8>,
) -> CoseResultWithRet<bool> {
    let mut e = Encoder::new(Vec::new());
    if MAC_ALL.contains(&context) {
        e.array(MAC_STRUCT_LEN)?;
        e.text(context)?;
        e.bytes(body_protected.as_slice())?;
        e.bytes(aead.as_slice())?;
        e.bytes(payload.as_slice())?;
        algs::mac_verify(*alg, &key, &e.into_writer().to_vec(), &tag)
    } else {
        Err(CoseError::InvalidContext())
    }
}
