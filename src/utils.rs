//! Utilities to help the process of encoding/decoding a COSE message.
//!
//! # Examples
//!
//! Examples on how to encode a COSE message by providing the respective
//! parameters and cose-key in JSON format.
//!
//! The functions `decode_json_key` and `decode_json` used in this examples are from the optional feature `json` of this crate.
//!
//! ## cose-sign1
//! ```
//! use cose::utils;
//! use cose::message::{CoseMessage, SIG1_TAG};
//!
//! fn main() {
//!
//!     // cose-sign1 message in JSON format
//!     let data: &str = r#"
//!     {
//!             "protected": {"alg": "EDDSA" },
//!             "unprotected": {"kid": "11" },
//!             "payload": "signed message"
//!     }"#;
//!
//!     // cose-key in JSON format
//!     let key_json: &str = r#"
//!     {
//!             "kty": "OKP",
//!             "alg": "EDDSA",
//!             "crv": "Ed25519",
//!             "x": "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
//!             "d": "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
//!             "key ops": ["sign", "verify"]
//!     }"#;
//!
//!     // Decode the cose-key JSON to CoseKey structure
//!     let key = utils::decode_json_key(key_json).unwrap();
//!     // Encode the cose-sign1 with the decoded cose-key and cose-sign1 JSON
//!     let res = utils::decode_json(data, &key, SIG1_TAG).unwrap();
//!
//!     // Verify the signature
//!     let mut verify = CoseMessage::new_sign();
//!     verify.bytes = res;
//!     verify.init_decoder(None).unwrap();
//!     verify.key(&key).unwrap();
//!     verify.decode(None, None).unwrap();
//! }
//!
//! ```
//! ## cose-encrypt0
//!
//! ```
//! use cose::utils;
//! use cose::message::{CoseMessage, ENC0_TAG};
//!
//! fn main() {
//!     // cose-encrypt0 message in JSON format
//!     let data: &str = r#"
//!     {
//!             "protected": {"alg": 24 },
//!             "unprotected": {"kid": "11", "iv": "000102030405060700010203" },
//!             "payload": "This is the content."
//!     }"#;
//!     // cose-key in JSON format
//!     let key_json: &str = r#"
//!     {
//!             "kty": 4,
//!             "alg": 24,
//!             "k": "849b57219dae48de646d07dbb533566e976686457c1491be3a76dcea6c427188",
//!             "key ops": [3, 4]
//!     }"#;
//!
//!     // Decode the cose-key JSON to CoseKey structure
//!     let key = utils::decode_json_key(key_json).unwrap();
//!     // Encode the cose-encrypt0 with the decoded cose-key and cose-encrypt0 JSON
//!     let res = utils::decode_json(data, &key, ENC0_TAG).unwrap();
//!
//!     // Decrypt and verify
//!     let mut dec0 = CoseMessage::new_encrypt();
//!     dec0.bytes = res;
//!     dec0.init_decoder(None).unwrap();
//!
//!     dec0.key(&key).unwrap();
//!     let resp = dec0.decode(None, None).unwrap();
//!     assert_eq!(resp, b"This is the content.".to_vec());
//! }
//! ```
//! ## cose-mac0
//!
//! ```
//! use cose::utils;
//! use cose::message::{CoseMessage, MAC0_TAG};
//!
//! pub fn mac0_json() {
//!     // cose-mac0 message in JSON format
//!     let data: &str = r#"
//!     {
//!         "protected": {"crit": [1, 2], "alg": 26 },
//!         "unprotected": {"kid": "11"},
//!         "payload": "This is the content."
//!     }"#;
//!
//!     // cose-key in JSON format
//!     let key_json: &str = r#"
//!     {
//!         "kty": 4,
//!         "alg": 26,
//!         "k": "849b57219dae48de646d07dbb533566e976686457c1491be3a76dcea6c427188",
//!         "key ops": [9, 10]
//!     }"#;
//!
//!     // Decode the cose-key JSON to CoseKey structure
//!     let key = utils::decode_json_key(key_json).unwrap();
//!     // Encode the cose-mac0 with the decoded cose-key and cose-mac0 JSON
//!     let res = utils::decode_json(data, &key, MAC0_TAG).unwrap();
//!
//!     // Verify the MAC tag
//!     let mut verify = CoseMessage::new_mac();
//!     verify.bytes = res;
//!     verify.init_decoder(None).unwrap();
//!
//!     verify.key(&key).unwrap();
//!     verify.decode(None, None).unwrap();
//! }
//!
//! ```

use crate::common;
#[cfg(feature = "json")]
use crate::errors::CoseResult;
use crate::errors::{CoseError, CoseResultWithRet};
use crate::headers;
#[cfg(feature = "json")]
use crate::keys;
use crate::message;
#[cfg(feature = "json")]
use crate::message::CoseMessage;
use cbor::{types::Tag, Config, Decoder};
#[cfg(feature = "json")]
use hex;
#[cfg(feature = "json")]
use serde_json::Value;
use std::io::Cursor;

/// Function that with a given COSE message bytes, identifies the corresponding message type.
///
/// This only works if the message is properly tagged.
pub fn cose_type_finder(bytes: &Vec<u8>) -> CoseResultWithRet<String> {
    let input = Cursor::new(bytes);
    let mut decoder = Decoder::new(Config::default(), input);
    let tag = decoder.tag()?;
    match tag {
        Tag::Unassigned(message::ENC0_TAG) => Ok(message::ENC0_TYPE.to_string()),
        Tag::Unassigned(message::MAC0_TAG) => Ok(message::MAC0_TYPE.to_string()),
        Tag::Unassigned(message::SIG1_TAG) => Ok(message::SIG1_TYPE.to_string()),
        Tag::Unassigned(message::ENC_TAG) => Ok(message::ENC_TYPE.to_string()),
        Tag::Unassigned(message::MAC_TAG) => Ok(message::MAC_TYPE.to_string()),
        Tag::Unassigned(message::SIG_TAG) => Ok(message::SIG_TYPE.to_string()),
        _ => Err(CoseError::InvalidCoseStructure()),
    }
}

/// Function that encodes a json object to a COSE message and applies the respective cryptographic
/// operations with the given cose-key.
///
/// `tag` parameter is the COSE message type identifier.
#[cfg(feature = "json")]
pub fn decode_json(
    message_json: &str,
    key: &keys::CoseKey,
    tag: u64,
) -> CoseResultWithRet<Vec<u8>> {
    let message_value: Value = serde_json::from_str(message_json)?;
    let mut header = headers::CoseHeader::new();
    decode_json_header(&mut header, &message_value["protected"].to_string(), true)?;
    decode_json_header(
        &mut header,
        &message_value["unprotected"].to_string(),
        false,
    )?;
    let payload = match &message_value["payload"] {
        Value::String(r) => r.as_bytes().to_vec(),
        _ => Vec::new(),
    };

    if tag == message::SIG1_TAG {
        let mut sign = CoseMessage::new_sign();
        sign.payload(payload);
        sign.add_header(header);
        sign.key(&key)?;
        sign.secure_content(None)?;
        sign.encode(true)?;
        Ok(sign.bytes)
    } else if tag == message::ENC0_TAG {
        let mut enc = CoseMessage::new_encrypt();
        enc.payload(payload);
        enc.add_header(header);
        enc.key(&key)?;
        enc.secure_content(None)?;
        enc.encode(true)?;
        Ok(enc.bytes)
    } else if tag == message::MAC0_TAG {
        let mut mac = CoseMessage::new_mac();
        mac.payload(payload);
        mac.add_header(header);
        mac.key(&key)?;
        mac.secure_content(None)?;
        mac.encode(true)?;
        Ok(mac.bytes)
    } else {
        Ok(Vec::new())
    }
}

#[cfg(feature = "json")]
fn decode_json_header(
    header: &mut headers::CoseHeader,
    json_header: &str,
    prot: bool,
) -> CoseResult {
    let json_value: Value = serde_json::from_str(json_header)?;
    if json_value.get("crit").is_some() {
        for i in json_value["crit"].as_array().unwrap().to_vec() {
            header.crit.push(i.as_i64().unwrap() as i32);
        }
    }
    if json_value.get("alg").is_some() {
        let alg = match &json_value["alg"] {
            Value::String(r) => common::get_alg_id(r.to_string())?,
            Value::Number(v) => v.as_i64().unwrap() as i32,
            _ => 0,
        };
        header.alg(alg, prot, false);
    }
    if json_value.get("kid").is_some() {
        header.kid(
            json_value["kid"].as_str().unwrap().as_bytes().to_vec(),
            prot,
            false,
        );
    }
    if json_value.get("iv").is_some() {
        header.iv(
            hex::decode(json_value["iv"].as_str().unwrap().to_string())?,
            prot,
            false,
        );
    }
    if json_value.get("partial iv").is_some() {
        header.partial_iv(
            hex::decode(json_value["partial iv"].as_str().unwrap().to_string())?,
            prot,
            false,
        );
    }
    if json_value.get("content type").is_some() {
        match &json_value["content_type"] {
            Value::String(r) => {
                header.content_type(
                    headers::ContentTypeTypes::Tstr(r.as_str().to_string()),
                    prot,
                    false,
                );
            }
            Value::Number(v) => {
                header.content_type(
                    headers::ContentTypeTypes::Uint(v.as_u64().unwrap() as u32),
                    prot,
                    false,
                );
            }
            _ => (),
        };
    }
    Ok(())
}

/// Function to decode a json object to a cose-key structure.
#[cfg(feature = "json")]
pub fn decode_json_key(json_key: &str) -> CoseResultWithRet<keys::CoseKey> {
    let json_value: Value = serde_json::from_str(json_key)?;
    let mut key = keys::CoseKey::new();
    if json_value.get("alg").is_some() {
        let alg = match &json_value["alg"] {
            Value::String(r) => common::get_alg_id(r.to_string())?,
            Value::Number(v) => v.as_i64().unwrap() as i32,
            _ => 0,
        };
        key.alg(alg);
    }
    if json_value.get("kty").is_some() {
        let kty = match &json_value["kty"] {
            Value::String(r) => common::get_kty_id(r.to_string())?,
            Value::Number(v) => v.as_i64().unwrap() as i32,
            _ => 0,
        };
        key.kty(kty);
    }
    if json_value.get("crv").is_some() {
        let crv = match &json_value["crv"] {
            Value::String(r) => common::get_crv_id(r.to_string())?,
            Value::Number(v) => v.as_i64().unwrap() as i32,
            _ => 0,
        };
        key.crv(crv);
    }
    if json_value.get("key ops").is_some() {
        let mut key_ops = Vec::new();
        for i in json_value["key ops"].as_array().unwrap().to_vec() {
            key_ops.push(match i {
                Value::String(r) => common::get_key_op_id(r.to_string())?,
                Value::Number(v) => v.as_i64().unwrap() as i32,
                _ => 0,
            });
        }
        key.key_ops(key_ops);
    }
    if json_value.get("x").is_some() {
        key.x(hex::decode(json_value["x"].as_str().unwrap().to_string())?);
    }
    if json_value.get("y").is_some() {
        match &json_value["y"] {
            Value::String(r) => {
                key.y(hex::decode(r.as_str().to_string())?);
            }
            _ => {}
        };
    }
    if json_value.get("d").is_some() {
        key.d(hex::decode(json_value["d"].as_str().unwrap().to_string())?);
    }
    if json_value.get("k").is_some() {
        key.k(hex::decode(json_value["k"].as_str().unwrap().to_string())?);
    }
    Ok(key)
}
