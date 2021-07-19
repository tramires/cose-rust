use crate::errors::CoseResultWithRet;
use cbor::Encoder;

const STRUCT_LEN: usize = 5;
const PARTY_STRUCT_LEN: usize = 3;
const SUPP_PUB_STRUCT_LEN: usize = 3;

pub fn gen_kdf(
    alg: &i32,
    party_u_identity: Option<Vec<u8>>,
    party_u_nonce: Option<Vec<u8>>,
    party_u_other: Option<Vec<u8>>,
    party_v_identity: Option<Vec<u8>>,
    party_v_nonce: Option<Vec<u8>>,
    party_v_other: Option<Vec<u8>>,
    key_data_len: u16,
    protected: Vec<u8>,
    other: Option<Vec<u8>>,
    supp_priv_info: Option<Vec<u8>>,
) -> CoseResultWithRet<Vec<u8>> {
    let mut e = Encoder::new(Vec::new());
    if supp_priv_info == None {
        e.array(STRUCT_LEN - 1)?;
    } else {
        e.array(STRUCT_LEN)?;
    }
    e.i32(*alg)?;
    e.array(PARTY_STRUCT_LEN)?;
    if party_u_identity == None {
        e.null()?;
    } else {
        e.bytes(&party_u_identity.unwrap())?;
    }
    if party_u_nonce == None {
        e.null()?;
    } else {
        e.bytes(&party_u_nonce.unwrap())?;
    }
    if party_u_other == None {
        e.null()?;
    } else {
        e.bytes(&party_u_other.unwrap())?;
    }
    e.array(PARTY_STRUCT_LEN)?;
    if party_v_identity == None {
        e.null()?;
    } else {
        e.bytes(&party_v_identity.unwrap())?;
    }
    if party_v_nonce == None {
        e.null()?;
    } else {
        e.bytes(&party_v_nonce.unwrap())?;
    }
    if party_v_other == None {
        e.null()?;
    } else {
        e.bytes(&party_v_other.unwrap())?;
    }
    if other == None {
        e.array(SUPP_PUB_STRUCT_LEN - 1)?;
    } else {
        e.array(SUPP_PUB_STRUCT_LEN)?;
    }
    e.u16(key_data_len)?;
    e.bytes(&protected)?;
    if other != None {
        e.bytes(&other.unwrap())?;
    }
    if supp_priv_info != None {
        e.bytes(&supp_priv_info.unwrap())?;
    }
    Ok(e.into_writer().to_vec())
}
