use crate::algs;
use crate::errors::{CoseError, CoseResultWithRet};
use cbor::Encoder;

const ENCRYPT: &str = "Encrypt";
const ENCRYPT0: &str = "Encrypt0";
const ENCRYPT_RECIPIENT: &str = "Enc_Recipient";
const MAC_RECIPIENT: &str = "Mac_Recipient";
const REC_RECIPIENT: &str = "Rec_Recipient";
const ENC_ALL: [&str; 5] = [
    ENCRYPT,
    ENCRYPT0,
    ENCRYPT_RECIPIENT,
    MAC_RECIPIENT,
    REC_RECIPIENT,
];
const ENC_STRUCT_LEN: usize = 3;

pub fn gen_cipher(
    key: &Vec<u8>,
    alg: &i32,
    iv: &Vec<u8>,
    aead: &Vec<u8>,
    context: &str,
    body_protected: &Vec<u8>,
    payload: &Vec<u8>,
) -> CoseResultWithRet<Vec<u8>> {
    let mut e = Encoder::new(Vec::new());
    if ENC_ALL.contains(&context) {
        e.array(ENC_STRUCT_LEN)?;
        e.text(context)?;
        e.bytes(body_protected.as_slice())?;
        e.bytes(aead.as_slice())?;
        algs::encrypt(*alg, &key, &iv, &payload, &e.into_writer().to_vec())
    } else {
        Err(CoseError::InvalidContext())
    }
}

pub fn dec_cipher(
    key: &Vec<u8>,
    alg: &i32,
    iv: &Vec<u8>,
    aead: &Vec<u8>,
    context: &str,
    body_protected: &Vec<u8>,
    ciphertext: &Vec<u8>,
) -> CoseResultWithRet<Vec<u8>> {
    let mut e = Encoder::new(Vec::new());
    if ENC_ALL.contains(&context) {
        e.array(ENC_STRUCT_LEN)?;
        e.text(context)?;
        e.bytes(body_protected.as_slice())?;
        e.bytes(aead.as_slice())?;
        algs::decrypt(*alg, &key, &iv, &ciphertext, &e.into_writer().to_vec())
    } else {
        Err(CoseError::InvalidContext())
    }
}
