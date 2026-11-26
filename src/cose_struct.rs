use crate::errors::{CoseError, CoseResult, CoseResultWithRet};
use crate::headers::CoseHeader;
use cbor::Encoder;

pub(crate) const SIGNATURE: &str = "Signature";
pub(crate) const SIGNATURE1: &str = "Signature1";
pub(crate) const COUNTER_SIGNATURE: &str = "CounterSignature";
pub(crate) const COUNTER_SIGNATUREV2: &str = "CounterSignatureV2";
const SIGNATURE1_LEN: usize = 4;
const SIGNATURE_LEN: usize = 5;

pub(crate) const MAC: &str = "MAC";
pub(crate) const MAC0: &str = "MAC0";
const MAC_ALL: [&str; 3] = [MAC, MAC0, MAC_RECIPIENT];
const MAC_STRUCT_LEN: usize = 4;

pub(crate) const ENCRYPT: &str = "Encrypt";
pub(crate) const ENCRYPT0: &str = "Encrypt0";
pub(crate) const ENCRYPT_RECIPIENT: &str = "Enc_Recipient";
pub(crate) const MAC_RECIPIENT: &str = "Mac_Recipient";
pub(crate) const REC_RECIPIENT: &str = "Rec_Recipient";
const ENC_ALL: [&str; 4] = [ENCRYPT, ENCRYPT0, ENCRYPT_RECIPIENT, REC_RECIPIENT];
const ENC_STRUCT_LEN: usize = 3;

const STRUCT_LEN: usize = 5;
const PARTY_STRUCT_LEN: usize = 3;
const SUPP_PUB_STRUCT_LEN: usize = 3;

pub(crate) fn sign_structure(
    context: &str,
    body_protected: &[u8],
    sign_protected: &[u8],
    external_aad: &[u8],
    payload: &[u8],
    other: Option<&[u8]>,
) -> CoseResultWithRet<Vec<u8>> {
    let mut e = Encoder::new(Vec::new());
    match context {
        SIGNATURE | COUNTER_SIGNATURE => {
            let context = match (context, other) {
                (COUNTER_SIGNATURE, Some(_)) => COUNTER_SIGNATUREV2,
                _ => context,
            };
            e.array(SIGNATURE_LEN + usize::from(other.is_some()))?;
            e.text(context)?;
            e.bytes(body_protected)?;
            e.bytes(sign_protected)?;
        }
        SIGNATURE1 => {
            e.array(SIGNATURE1_LEN)?;
            e.text(SIGNATURE1)?;
            e.bytes(body_protected)?;
        }
        _ => return Err(CoseError::InvalidContext(context.into())),
    }
    e.bytes(external_aad)?;
    e.bytes(payload)?;
    if let Some(other) = other {
        e.array(1)?;
        e.bytes(other)?;
    }
    Ok(e.into_writer())
}

pub(crate) fn mac_structure(
    context: &str,
    body_protected: &[u8],
    aad: &[u8],
    payload: &[u8],
) -> CoseResultWithRet<Vec<u8>> {
    if !MAC_ALL.contains(&context) {
        return Err(CoseError::InvalidContext(context.into()));
    }
    let mut e = Encoder::new(Vec::new());
    e.array(MAC_STRUCT_LEN)?;
    e.text(context)?;
    e.bytes(body_protected)?;
    e.bytes(aad)?;
    e.bytes(payload)?;
    Ok(e.into_writer())
}

pub(crate) fn encrypt_structure(
    context: &str,
    body_protected: &[u8],
    aad: &[u8],
) -> CoseResultWithRet<Vec<u8>> {
    if !ENC_ALL.contains(&context) {
        return Err(CoseError::InvalidContext(context.into()));
    }
    let mut e = Encoder::new(Vec::new());
    e.array(ENC_STRUCT_LEN)?;
    e.text(context)?;
    e.bytes(body_protected)?;
    e.bytes(aad)?;
    Ok(e.into_writer())
}

fn bytes_or_null(e: &mut Encoder<Vec<u8>>, value: &Option<Vec<u8>>) -> CoseResult {
    match value {
        Some(v) => e.bytes(v)?,
        None => e.null()?,
    }
    Ok(())
}

pub(crate) fn kdf_structure(
    alg: &i32,
    header: &CoseHeader,
    key_data_len: u16,
    protected: &[u8],
) -> CoseResultWithRet<Vec<u8>> {
    let mut e = Encoder::new(Vec::new());
    e.array(if header.priv_info.is_some() {
        STRUCT_LEN
    } else {
        STRUCT_LEN - 1
    })?;
    e.i32(*alg)?;
    let parties = [
        [
            &header.party_u_identity,
            &header.party_u_nonce,
            &header.party_u_other,
        ],
        [
            &header.party_v_identity,
            &header.party_v_nonce,
            &header.party_v_other,
        ],
    ];
    for party in &parties {
        e.array(PARTY_STRUCT_LEN)?;
        for field in party {
            bytes_or_null(&mut e, field)?;
        }
    }
    e.array(if header.pub_other.is_some() {
        SUPP_PUB_STRUCT_LEN
    } else {
        SUPP_PUB_STRUCT_LEN - 1
    })?;
    e.u16(key_data_len)?;
    e.bytes(&protected)?;
    if let Some(other) = &header.pub_other {
        e.bytes(other)?;
    }
    if let Some(info) = &header.priv_info {
        e.bytes(info)?;
    }
    Ok(e.into_writer())
}
