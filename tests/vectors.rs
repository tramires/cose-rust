// Run the crate against the COSE Working Group test vectors (https://github.com/cose-wg/Examples)
// EXAMPLES_DIR=Examples
//
// Results meaning:
//   - decode:
//      - pass: decoded and verified
//      - rejected: vector marked as failing, and decoding rejected it as expected
//   - encode:
//      - exact: output equals the vector's bytes
//      - length: same length as the vector and output decodes and verifies; the bytes differ due
//      to randomness or v1 counter signatures
//      - tolerated: vectors marked with fail/failures that are encoded, decoded and verified.
//      - tolerated error: vectors marked with fail/failures that failed encoding, should stay 0.
//   - skip: either not implemented or something missing on the test vector

use base64::{
    alphabet,
    engine::{GeneralPurpose, GeneralPurposeConfig},
    Engine,
};
use cose::agent::CoseAgent;
use cose::algs;
use cose::errors::{CoseError, CoseResultWithRet};
use cose::headers::{
    self,
    Bucket::{self, Protected, Unprotected},
    ContentTypeTypes, CoseHeader,
    Party::{U, V},
};
use cose::keys::{self, CoseKey};
use cose::message::CoseMessage;
use hex;
use openssl::bn::{BigNum, BigNumContext};
use openssl::ec::{EcGroup, EcPoint};
use openssl::error::ErrorStack;
use openssl::nid::Nid;
use openssl::pkey::{Id, PKey};
use serde_json::Value;
use std::collections::BTreeMap;
use std::{
    fs,
    path::{Path, PathBuf},
};

const MESSAGE_TYPES: [&str; 6] = ["sign0", "sign", "mac0", "mac", "encrypted", "enveloped"];

const ECDH_ES: [i32; 5] = [
    algs::ECDH_ES_HKDF_256,
    algs::ECDH_ES_HKDF_512,
    algs::ECDH_ES_A128KW,
    algs::ECDH_ES_A192KW,
    algs::ECDH_ES_A256KW,
];

const ECDH_SS: [i32; 5] = [
    algs::ECDH_SS_HKDF_256,
    algs::ECDH_SS_HKDF_512,
    algs::ECDH_SS_A128KW,
    algs::ECDH_SS_A192KW,
    algs::ECDH_SS_A256KW,
];

#[derive(Debug)]
enum Outcome {
    Pass,
    Rejected,
    Exact,
    Length,
    Tolerated,
    ToleratedError,
    Skip(String),
    Fail(String),
}

impl Outcome {
    fn describe(self) -> (&'static str, String) {
        match self {
            Outcome::Pass => ("pass", String::new()),
            Outcome::Rejected => ("rejected", String::new()),
            Outcome::Exact => ("exact", String::new()),
            Outcome::Length => ("length", String::new()),
            Outcome::Tolerated => ("tolerated", String::new()),
            Outcome::ToleratedError => ("toleratedError", String::new()),
            Outcome::Skip(reason) => ("skip", reason),
            Outcome::Fail(reason) => ("FAIL", reason),
        }
    }
}

fn skip(reason: impl Into<String>) -> Outcome {
    Outcome::Skip(reason.into())
}

fn fail(error: CoseError) -> Outcome {
    Outcome::Fail(format!("{:?}", error))
}

#[derive(Default)]
struct Keys {
    ephemeral: Option<CoseKey>,
    sender: Option<CoseKey>,
}

#[test]
#[ignore = "(needs EXAMPLE_DIR)"]
fn encode_examples() {
    run_examples(
        encode_vector,
        &[
            ("exact", 154),
            ("length", 88),
            ("skip", 12),
            ("tolerated", 52),
        ],
    );
}

#[test]
#[ignore = "(needs EXAMPLE_DIR)"]
fn decode_examples() {
    run_examples(
        decode_vector,
        &[("pass", 254), ("rejected", 40), ("skip", 12)],
    );
}

// get counter signers keys from the test vectors
fn counter_keys(layer: &Value, decoded: usize) -> Result<Vec<CoseKey>, Outcome> {
    let signers = layer["countersign"]["signers"]
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or_default();
    if decoded != signers.len() {
        return Err(Outcome::Fail(format!(
            "counter signatures decoded {}/{}",
            decoded,
            signers.len()
        )));
    }
    signers.iter().map(|json| cose_key(&json["key"])).collect()
}

fn run_examples(run: fn(&Value) -> Outcome, expected: &[(&str, usize)]) {
    let root = PathBuf::from(std::env::var("EXAMPLES_DIR").expect("EXAMPLES_DIR not set"));

    let mut files = Vec::new();
    collect_json(&root, &mut files);
    files.sort();

    let (mut counts, mut failed) = (BTreeMap::new(), Vec::new());

    for path in &files {
        let name = path
            .strip_prefix(&root)
            .unwrap_or(path)
            .display()
            .to_string();
        let vector: Value = serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap();

        let (label, detail) = run(&vector).describe();
        if label.contains("FAIL") {
            failed.push(name.clone());
        }

        *counts.entry(label).or_insert(0) += 1;
        println!("{} {} {}", label, name, detail);
    }

    println!("{:?} ", counts);

    assert!(failed.is_empty(), "\x1b[91mfailed\x1b[0m: {:?}", failed);

    let expected: BTreeMap<_, _> = expected.iter().copied().filter(|&(_, n)| n > 0).collect();
    assert_eq!(counts, expected);
}

fn collect_json(dir: &Path, files: &mut Vec<PathBuf>) {
    for path in fs::read_dir(dir)
        .unwrap()
        .filter_map(Result::ok)
        .map(|entry| entry.path())
    {
        if path.is_dir() {
            collect_json(&path, files);
        } else if path.extension().map_or(false, |ext| ext == "json") {
            files.push(path);
        }
    }
}

fn encode_vector(vector: &Value) -> Outcome {
    let expected = match expected_output(vector) {
        Ok(bytes) => bytes,
        Err(outcome) => return outcome,
    };

    let input = &vector["input"];
    let to_fail = vector["fail"] == true || has_failures(input);

    let bytes = match encode(input) {
        Ok(bytes) => bytes,
        Err(skip @ Outcome::Skip(_)) => return skip,
        Err(_) if to_fail => return Outcome::ToleratedError,
        Err(outcome) => return outcome,
    };

    if bytes == expected {
        return if to_fail {
            Outcome::Fail("corrupt output reproduced".into())
        } else {
            Outcome::Exact
        };
    }

    if !to_fail && bytes.len() != expected.len() {
        return Outcome::Fail(format!("{}\n{}", hex::encode(bytes), hex::encode(expected)));
    }

    match decode(input, bytes) {
        Ok(()) if to_fail => Outcome::Tolerated,
        Ok(()) => Outcome::Length,
        Err(e) => Outcome::Fail(format!("fail to decode own output: {:?}", e)),
    }
}

fn has_failures(v: &Value) -> bool {
    match v {
        Value::Object(m) => m.contains_key("failures") || m.values().any(has_failures),
        Value::Array(a) => a.iter().any(has_failures),
        _ => false,
    }
}

fn new_message(m_type: &str) -> CoseMessage {
    match m_type {
        "sign0" | "sign" => CoseMessage::new_sign(),
        "mac0" | "mac" => CoseMessage::new_mac(),
        _ => CoseMessage::new_encrypt(),
    }
}

fn payload(input: &Value) -> Result<Vec<u8>, Outcome> {
    Ok(match hex_field(input, "plaintext_hex")? {
        Some(v) => v,
        None => text(&input["plaintext"]),
    })
}

fn external_aad(layer: &Value) -> Result<Option<Vec<u8>>, Outcome> {
    match hex_field(layer, "external")? {
        Some(external) => Ok(Some(external)),
        None => hex_field(&layer["signers"][0], "external"),
    }
}

fn decode_vector(vector: &Value) -> Outcome {
    let bytes = match expected_output(vector) {
        Ok(bytes) => bytes,
        Err(outcome) => return outcome,
    };
    let fail = vector["fail"] == true;
    match decode(&vector["input"], bytes) {
        Ok(()) if fail => Outcome::Fail(format!("Should fail")),
        Ok(()) => Outcome::Pass,
        Err(Outcome::Fail(_)) if fail => Outcome::Rejected,
        Err(outcome) => outcome,
    }
}

fn get_json_key<'a>(layer: &'a Value, m_type: &str) -> &'a Value {
    if m_type == "sign0" {
        &layer["key"]
    } else {
        &layer["recipients"][0]["key"]
    }
}

fn decode(input: &Value, bytes: Vec<u8>) -> Result<(), Outcome> {
    let m_type = *MESSAGE_TYPES
        .iter()
        .find(|&&m_type| input.get(m_type).is_some())
        .ok_or_else(|| skip("COSE identifier missing"))?;
    let layer = &input[m_type];

    // check if countersign0
    let layers = std::iter::once(layer).chain(agents_json(m_type, layer));
    if layers.into_iter().any(|l| l.get("countersign0").is_some()) {
        return Err(skip("countersign0 not implemented"));
    }

    // check if crit has text label
    let crit = layer["protected"]["crit"]
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or_default();
    if crit.iter().any(Value::is_string) {
        return Err(skip("Text label crit not implemented"));
    }

    let payload = payload(input)?;
    let external = external_aad(layer)?;

    let mut msg = new_message(m_type);
    msg.bytes = bytes;
    msg.init_decoder(None).map_err(fail)?;

    // get the counter keys and verify each counter on the message
    let keys = counter_keys(layer, msg.header.counters().len())?;
    for (index, key) in keys.iter().enumerate() {
        msg.verify_counter(index, key, None).map_err(fail)?;
    }

    let base_iv = base_iv(layer, &msg.header)?;
    let agents = agents_json(m_type, layer);

    // if single agent message type
    if agents.is_empty() {
        let key_json = get_json_key(&layer, m_type);

        let mut key = cose_key(key_json)?;
        if let Some(base_iv) = base_iv {
            key.set_base_iv(base_iv);
        }
        msg.key(&key).map_err(fail)?;
        return expect_payload(msg.decode(external, None), &payload);
    }

    // if agents decoded dont match the test vector agents
    if agents.len() != msg.agents().len() {
        return Err(Outcome::Fail(format!(
            "signers/recipients decoded {}/{}",
            msg.agents().len(),
            agents.len()
        )));
    }

    for (i, json) in agents.iter().enumerate() {
        // if recipients inside the recipient
        if json.get("recipients").is_some() {
            return Err(skip("Triple layer not implemented"));
        }

        let mut key = cose_key(&json["key"])?;
        if let Some(iv) = &base_iv {
            key.set_base_iv(iv.clone());
        }

        let agent = msg
            .agent_mut(i)
            .ok_or_else(|| Outcome::Fail(format!("no agent at index {}", i)))?;

        // unsent headers
        apply_unsent(&mut agent.header, json)?;

        // static kid
        if agent.header.static_kid().is_some() {
            agent.header.set_ecdh_key(cose_key(&json["sender_key"])?);
        }

        agent.key(&key).map_err(fail)?;

        // get the counter keys of the recipient and verify each counter
        let keys = counter_keys(json, agent.header.counters().len())?;
        for (index, key) in keys.iter().enumerate() {
            agent.verify_counter(index, key, None).map_err(fail)?;
        }
        expect_payload(msg.decode(external.clone(), Some(i)), &payload)?;
    }
    Ok(())
}

fn agents_json<'a>(m_type: &str, layer: &'a Value) -> &'a [Value] {
    let list = match m_type {
        "sign" => &layer["signers"],
        "mac" | "enveloped" => &layer["recipients"],
        _ => return &[],
    };
    list.as_array().map(Vec::as_slice).unwrap_or_default()
}

fn encode(input: &Value) -> Result<Vec<u8>, Outcome> {
    let m_type = *MESSAGE_TYPES
        .iter()
        .find(|&&m_type| input.get(m_type).is_some())
        .ok_or_else(|| skip("COSE identifier missing"))?;
    let layer = &input[m_type];
    let agents_j = agents_json(m_type, layer);

    // check if countersign0
    let layers = std::iter::once(layer).chain(agents_j);
    if layers.into_iter().any(|l| l.get("countersign0").is_some()) {
        return Err(skip("countersign0 not supported"));
    }

    let rng = rng_stream(input);
    let payload = payload(input)?;
    let external = external_aad(layer)?;

    let mut msg = new_message(m_type);
    msg.payload = payload.clone();
    apply_headers(&mut msg.header, layer, &Keys::default(), true)?;

    // if no alg is set from the apply_headers
    if msg.header.alg().is_none() {
        if let Some(name) = layer["alg"].as_str() {
            msg.header.set_alg(alg_id(name)?, Protected);
        }
    }

    let base_iv = base_iv(layer, &msg.header)?;

    // if encryption types w/o any IV info get the IV from rng_stream
    if matches!(m_type, "encrypted" | "enveloped") && msg.header.iv().is_none() && base_iv.is_none()
    {
        let iv = rng
            .get(1)
            .or_else(|| rng.first())
            .ok_or_else(|| skip("No IV in rng_stream"))?;
        msg.header.set_iv(iv.clone(), Unprotected);
    }

    // hold the set_kid to match the test vectors order for exact assert
    let mut pending = Vec::new();

    if agents_j.is_empty() {
        // if single agent message type
        let key_json = get_json_key(&layer, m_type);
        let mut key = cose_key(key_json)?;
        if let Some(base_iv) = base_iv {
            key.set_base_iv(base_iv);
        }
        msg.key(&key).map_err(fail)?;
    } else {
        // if multi-agent message type
        for json in agents_j {
            // build the agent and get the pending kid
            let (mut agent, kid) = build_agent(json, &rng, base_iv.clone())?;
            msg.add_agent(&mut agent).map_err(fail)?;
            pending.push(kid);
        }
    };

    msg.secure_content(external.clone()).map_err(fail)?;

    // counter signs on the message layer
    for counter in counter_signers(layer)? {
        msg.sign_counter(counter, None).map_err(fail)?;
    }

    // counter signatures on each agent
    for (i, json) in agents_j.iter().enumerate() {
        let agent = msg.agent_mut(i).unwrap();
        for counter in counter_signers(json)? {
            agent.sign_counter(counter, None).map_err(fail)?;
        }
    }

    // set the pending kid on each agent
    for (i, kid) in pending.into_iter().enumerate() {
        if let Some(kid) = kid {
            msg.agent_mut(i).unwrap().header.set_kid(kid, Unprotected);
        }
    }

    // if the kid was skipped by the same condition
    if let Some(kid) = lone_kid(layer)? {
        msg.header.set_kid(kid, Unprotected);
    }

    msg.encode(true).map_err(fail)?;

    Ok(msg.bytes)
}

fn lone_kid(layer: &Value) -> Result<Option<Vec<u8>>, Outcome> {
    let bucket = match layer["unprotected"].as_object() {
        Some(bucket) if bucket.len() == 1 => bucket,
        _ => return Ok(None),
    };
    match bucket.iter().next() {
        Some((name, value)) if name == "kid" => Ok(Some(text(value))),
        Some((name, value)) if name == "kid_hex" => hex_value(value).map(Some),
        _ => Ok(None),
    }
}

fn build_agent(
    json: &Value,
    rng: &[Vec<u8>],
    base_iv: Option<Vec<u8>>,
) -> Result<(CoseAgent, Option<Vec<u8>>), Outcome> {
    if json.get("recipients").is_some() {
        return Err(skip("Triple layer not implemented"));
    }

    let mut key = cose_key(&json["key"])?;
    if let Some(base_iv) = base_iv {
        key.set_base_iv(base_iv);
    }

    let alg_name = json["protected"]["alg"]
        .as_str()
        .or_else(|| json["unprotected"]["alg"].as_str());
    let alg = alg_id(alg_name.unwrap_or_default())?;

    let mut keys = Keys::default();

    // get the ECDH key
    if ECDH_ES.contains(&alg) {
        keys.ephemeral = Some(ephemeral_key(&key, rng, json["unsent"]["compressed"] == 1)?);
    }
    if ECDH_SS.contains(&alg) {
        let mut sender = cose_key(&json["sender_key"])?;
        if let Some(kty) = sender.kty() {
            sender.set_kty(kty);
        }
        keys.sender = Some(sender);
    }

    // Check if kid will be skipped to ensure it goes after the sender key and the counter
    // signatures
    let ecdh = ECDH_ES.contains(&alg) || ECDH_SS.contains(&alg);
    let defer = ecdh || json.get("countersign").is_some();
    let defered_kid = if defer { lone_kid(json)? } else { None };

    let mut agent = CoseAgent::new();
    apply_headers(&mut agent.header, json, &keys, defer)?;

    let header = &mut agent.header;

    // if ephemeral
    if let Some(ephemeral) = keys.ephemeral {
        // set ephemeral key
        if !header.unprotected().contains(&headers::EPHEMERAL_KEY) {
            header.set_ephemeral_key(ephemeral, Unprotected);
        }
        // set the kid after the ephemeral
        if let Some(kid) = &defered_kid {
            header.set_kid(kid.clone(), Unprotected);
        }
        // if kid not in the test vector headers
        if header.kid().is_none() {
            if let Some(kid) = &key.kid() {
                header.set_kid(*kid, Unprotected);
            }
        }
    }

    // if static key/kid
    if let Some(sender) = &keys.sender {
        // set static kid
        if !header.unprotected().contains(&headers::STATIC_KEY_ID) {
            match &sender.kid() {
                Some(kid) => header.set_static_key_id(kid.to_vec(), sender.clone(), Unprotected),
                None => header.set_static_key(sender.clone(), Unprotected),
            }
        }
        // set the kid after the static key
        if let Some(kid) = &defered_kid {
            header.set_kid(kid.clone(), Unprotected);
        }
        let direct = alg == algs::ECDH_SS_HKDF_256 || alg == algs::ECDH_SS_HKDF_512;
        // if direct ECDH and no party nonce get it from the rng_stream
        if direct && header.party_u_nonce().is_none() {
            let nonce = rng
                .first()
                .cloned()
                .ok_or_else(|| skip("No nonce in rng_stream"))?;
            header.set_party_nonce(nonce, Unprotected, U);
        }
    }
    agent.key(&key).map_err(fail)?;
    // update pending kid for counter signatures case
    let pending_kid = if ecdh { None } else { defered_kid };
    Ok((agent, pending_kid))
}

fn ephemeral_key(
    recipient: &CoseKey,
    rng: &[Vec<u8>],
    compressed: bool,
) -> Result<CoseKey, Outcome> {
    let crv = recipient.crv().ok_or_else(|| skip("No curve"))?;
    let size = match crv {
        keys::P_256 | keys::X25519 => 32,
        keys::P_384 => 48,
        keys::P_521 => 66,
        keys::X448 => 56,
        _ => return Err(skip("Invalid curve")),
    };

    // get the private key from rng_stream
    let mut d = rng
        .iter()
        .rev()
        .find(|entry| entry.len() == size)
        .cloned()
        .ok_or_else(|| skip("No ephemeral key in rng_stream"))?;

    // Mask on the first byte for the extra 7 bits generated (66 bytes - 7 bits)
    if crv == keys::P_521 {
        d[0] &= 0x01;
    }

    let (x, y) = public_key(crv, &d).map_err(|e| skip(format!("ephemeral pub key: {}", e)))?;
    let mut key = CoseKey::new();
    key.set_kty(recipient.kty().unwrap_or_default());
    key.set_crv(crv);
    key.set_x(x);
    match y {
        Some(y) if compressed => key.set_y_parity(y.last().map_or(false, |b| b & 1 == 1)),
        Some(y) => key.set_y(y),
        None => {}
    }
    key.set_d(d);
    Ok(key)
}

// Public key from the private key
fn public_key(crv: i32, d: &[u8]) -> Result<(Vec<u8>, Option<Vec<u8>>), ErrorStack> {
    let nid = match crv {
        keys::X25519 | keys::X448 => {
            let id = if crv == keys::X25519 {
                Id::X25519
            } else {
                Id::X448
            };
            return Ok((
                PKey::private_key_from_raw_bytes(d, id)?.raw_public_key()?,
                None,
            ));
        }
        keys::P_384 => Nid::SECP384R1,
        keys::P_521 => Nid::SECP521R1,
        _ => Nid::X9_62_PRIME256V1,
    };

    let group = EcGroup::from_curve_name(nid)?;
    let mut ctx = BigNumContext::new()?;
    let mut point = EcPoint::new(&group)?;
    let scalar = BigNum::from_slice(d)?;
    point.mul_generator2(&group, &scalar, &mut ctx)?;
    let (mut x, mut y) = (BigNum::new()?, BigNum::new()?);
    point.affine_coordinates(&group, &mut x, &mut y, &mut ctx)?;
    let size = d.len() as i32;
    Ok((x.to_vec_padded(size)?, Some(y.to_vec_padded(size)?)))
}

fn base_iv(layer: &Value, header: &CoseHeader) -> Result<Option<Vec<u8>>, Outcome> {
    let (mut iv, partial) = match (hex_field(&layer["unsent"], "IV_hex")?, header.partial_iv()) {
        (Some(iv), Some(partial)) => (iv, partial),
        _ => return Ok(None),
    };

    let offset = iv.len().saturating_sub(partial.len());
    for (byte, p) in iv[offset..].iter_mut().zip(partial) {
        *byte ^= p;
    }

    Ok(Some(iv))
}

fn counter_signers(layer: &Value) -> Result<Vec<CoseAgent>, Outcome> {
    if layer.get("countersign0").is_some() {
        return Err(skip("countersign0 not supported"));
    }
    let signers = layer["countersign"]["signers"]
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or_default();

    // build counter signers w/ key
    signers
        .iter()
        .map(|json| -> Result<CoseAgent, Outcome> {
            let mut counter = CoseAgent::new_counter_sig();
            apply_headers(&mut counter.header, json, &Keys::default(), false)?;
            counter.key(&cose_key(&json["key"])?).map_err(fail)?;
            Ok(counter)
        })
        .collect()
}

fn apply_unsent(header: &mut CoseHeader, layer: &Value) -> Result<(), Outcome> {
    for (name, value) in layer["unsent"].as_object().into_iter().flatten() {
        match name.as_str() {
            "apu_id" => header.set_party_identity(text(value), None, U),
            "apv_id" => header.set_party_identity(text(value), None, V),
            "pub_other" => header.set_pub_other(text(value)),
            "priv_other" => header.set_priv_info(text(value)),
            "IV_hex" | "compressed" => {}
            other => return Err(skip(format!("unsent {}", other))),
        }
    }
    Ok(())
}
fn apply_headers(
    header: &mut CoseHeader,
    layer: &Value,
    keys: &Keys,
    defer_kid: bool,
) -> Result<(), Outcome> {
    for &(bucket, protected) in [("protected", true), ("unprotected", false)].iter() {
        // for the unprotected headers when the kid is the only one present and defer_kid is set to
        // true, skip
        if !protected && defer_kid && lone_kid(layer)?.is_some() {
            continue;
        }
        let mut entries: Vec<_> = layer[bucket].as_object().into_iter().flatten().collect();
        // Ensure kid goes second with the other non ECDH/countersignature labels
        if !protected && entries.len() > 1 && entries[0].0.trim_end_matches("_hex") == "kid" {
            entries.swap(0, 1);
        }
        for (name, value) in entries {
            apply_params(header, name, value, protected, keys)?;
        }
    }
    apply_unsent(header, layer)?;
    Ok(())
}

fn expect_payload(decoded: CoseResultWithRet<Vec<u8>>, payload: &[u8]) -> Result<(), Outcome> {
    if decoded.map_err(fail)? != payload {
        return Err(Outcome::Fail(format!("Invalid decoded content")));
    }
    Ok(())
}

fn expected_output(vector: &Value) -> Result<Vec<u8>, Outcome> {
    hex_field(&vector["output"], "cbor")?.ok_or_else(|| skip("No CBOR"))
}

fn bucket(protected: bool) -> Bucket {
    if protected {
        Protected
    } else {
        Unprotected
    }
}

fn cert_for_thumbprint(thumbprint: &[u8]) -> Result<Vec<u8>, Outcome> {
    let dir = PathBuf::from(std::env::var("EXAMPLES_DIR").unwrap()).join("x509-examples");
    ["alice.der", "ca.der"]
        .iter()
        .filter_map(|name| fs::read(dir.join(name)).ok())
        .find(|cert| openssl::sha::sha256(cert) == thumbprint)
        .ok_or_else(|| skip("x5t: no cert found with thumbprint"))
}

fn apply_params(
    header: &mut CoseHeader,
    name: &str,
    value: &Value,
    protected: bool,
    keys: &Keys,
) -> Result<(), Outcome> {
    let (name, bytes) = match name.strip_suffix("_hex") {
        Some(base) => (base, hex_value(value)?),
        None => (name, text(value)),
    };

    let no_key = || skip(format!("{} no matching key", name));

    match name {
        "alg" => header.set_alg(
            alg_id(value.as_str().unwrap_or_default())?,
            bucket(protected),
        ),
        "kid" => header.set_kid(bytes, bucket(protected)),
        "ctyp" => {
            let ctyp = match value.as_u64() {
                Some(n) => ContentTypeTypes::Uint(n as u32),
                None => ContentTypeTypes::Tstr(value.as_str().unwrap_or_default().to_string()),
            };
            header.set_content_type(ctyp, bucket(protected));
        }
        "IV" => header.set_iv(bytes, bucket(protected)),
        "partialIV" => header.set_partial_iv(bytes, bucket(protected)),
        "salt" => header.set_salt(bytes, bucket(protected)),
        "apu_id" => header.set_party_identity(bytes, Some(bucket(protected)), U),
        "apv_id" => header.set_party_identity(bytes, Some(bucket(protected)), V),
        "apu_nonce" => header.set_party_nonce(bytes, bucket(protected), U),
        "apv_nonce" => header.set_party_nonce(bytes, bucket(protected), V),
        "apu_other" => header.set_party_other(bytes, bucket(protected), U),
        "apv_other" => header.set_party_other(bytes, bucket(protected), V),
        "x5bag" => header.set_x5bag(certs(value)?, bucket(protected)),
        "x5chain" => header.set_x5chain(certs(value)?, bucket(protected)),
        "x5t" => match value.as_array().map(Vec::as_slice) {
            Some([hash, thumbprint]) if hash == "SHA-256" => {
                let cert = cert_for_thumbprint(&hex_value(thumbprint)?)?;
                header
                    .set_x5t(cert, algs::SHA_256, bucket(protected))
                    .map_err(fail)?;
            }
            _ => return Err(skip("x5t hash")),
        },
        "epk" => header.set_ephemeral_key(
            keys.ephemeral.clone().ok_or_else(no_key)?,
            bucket(protected),
        ),
        "spk_kid" => header.set_static_key_id(
            bytes,
            keys.sender.clone().ok_or_else(no_key)?,
            bucket(protected),
        ),
        other => return Err(skip(format!("header {}", other))),
    }
    Ok(())
}

fn alg_id(name: &str) -> Result<i32, Outcome> {
    Ok(match name {
        "ES256" => algs::ES256,
        "ES384" => algs::ES384,
        "ES512" => algs::ES512,
        "ES256K" => algs::ES256K,
        "EdDSA" => algs::EDDSA,
        "RSA-PSS-256" => algs::PS256,
        "RSA-PSS-384" => algs::PS384,
        "RSA-PSS-512" => algs::PS512,
        "HS256/64" => algs::HMAC_256_64,
        "HS256" => algs::HMAC_256_256,
        "HS384" => algs::HMAC_384_384,
        "HS512" => algs::HMAC_512_512,
        "AES-MAC-128/64" => algs::AES_MAC_128_64,
        "AES-MAC-256/64" => algs::AES_MAC_256_64,
        "AES-MAC-128/128" => algs::AES_MAC_128_128,
        "AES-MAC-256/128" => algs::AES_MAC_256_128,
        "A128GCM" => algs::A128GCM,
        "A192GCM" => algs::A192GCM,
        "A256GCM" => algs::A256GCM,
        "ChaCha-Poly1305" => algs::CHACHA20,
        "AES-CCM-16-128/64" => algs::AES_CCM_16_64_128,
        "AES-CCM-16-256/64" => algs::AES_CCM_16_64_256,
        "AES-CCM-64-128/64" => algs::AES_CCM_64_64_128,
        "AES-CCM-64-256/64" => algs::AES_CCM_64_64_256,
        "AES-CCM-16-128/128" => algs::AES_CCM_16_128_128,
        "AES-CCM-16-256/128" => algs::AES_CCM_16_128_256,
        "AES-CCM-64-128/128" => algs::AES_CCM_64_128_128,
        "AES-CCM-64-256/128" => algs::AES_CCM_64_128_256,
        "direct" => algs::DIRECT,
        "HKDF-HMAC-SHA-256" => algs::DIRECT_HKDF_SHA_256,
        "HKDF-HMAC-SHA-512" => algs::DIRECT_HKDF_SHA_512,
        "HKDF-AES-128" => algs::DIRECT_HKDF_AES_128,
        "HKDF-AES-256" => algs::DIRECT_HKDF_AES_256,
        "A128KW" => algs::A128KW,
        "A192KW" => algs::A192KW,
        "A256KW" => algs::A256KW,
        "RSA-OAEP" => algs::RSA_OAEP_1,
        "RSA-OAEP-256" => algs::RSA_OAEP_256,
        "RSA-OAEP-512" => algs::RSA_OAEP_512,
        "ECDH-ES" => algs::ECDH_ES_HKDF_256,
        "ECDH-ES-512" => algs::ECDH_ES_HKDF_512,
        "ECDH-SS" | "ECDH-SS-256" => algs::ECDH_SS_HKDF_256,
        "ECDH-SS-512" => algs::ECDH_SS_HKDF_512,
        "ECDH-ES-A128KW" | "ECDH-ES+A128KW" => algs::ECDH_ES_A128KW,
        "ECDH-ES-A192KW" => algs::ECDH_ES_A192KW,
        "ECDH-ES-A256KW" => algs::ECDH_ES_A256KW,
        "ECDH-SS-A128KW" | "ECDH-SS+A128KW" => algs::ECDH_SS_A128KW,
        "ECDH-SS-A192KW" => algs::ECDH_SS_A192KW,
        "ECDH-SS-A256KW" => algs::ECDH_SS_A256KW,
        other => return Err(skip(format!("alg {}", other))),
    })
}

// key.set_x(v) is compiled to CoseKey::set_x(&mut key, v)
type Setter = fn(&mut CoseKey, Vec<u8>);

static KEY_FIELDS: [(&str, Setter); 4] = [
    ("x", CoseKey::set_x),
    ("y", CoseKey::set_y),
    ("d", CoseKey::set_d),
    ("k", CoseKey::set_k),
];

static RSA_FIELDS: [(&str, Setter); 8] = [
    ("n", CoseKey::set_n),
    ("e", CoseKey::set_e),
    ("d", CoseKey::set_rsa_d),
    ("p", CoseKey::set_p),
    ("q", CoseKey::set_q),
    ("dP", CoseKey::set_dp),
    ("dQ", CoseKey::set_dq),
    ("qi", CoseKey::set_qinv),
];

fn cose_key(json: &Value) -> Result<CoseKey, Outcome> {
    let (kty, fields) = match json["kty"].as_str() {
        Some("EC") | Some("EC2") => (keys::EC2, &KEY_FIELDS[..]),
        Some("OKP") => (keys::OKP, &KEY_FIELDS[..]),
        Some("oct") => (keys::SYMMETRIC, &KEY_FIELDS[..]),
        Some("RSA") => (keys::RSA, &RSA_FIELDS[..]),
        other => return Err(skip(format!("kty {:?}", other))),
    };

    let mut key = CoseKey::new();
    key.set_kty(kty);
    if let Some(kid) = json["kid"].as_str() {
        key.set_kid(kid.as_bytes().to_vec());
    }

    if let Some(crv) = json["crv"].as_str() {
        key.set_crv(match crv {
            "P-256" => keys::P_256,
            "P-384" => keys::P_384,
            "P-521" => keys::P_521,
            "secp256k1" => keys::SECP256K1,
            "X25519" => keys::X25519,
            "X448" => keys::X448,
            "Ed25519" => keys::ED25519,
            "Ed448" => keys::ED448,
            other => return Err(skip(format!("crv {:?}", other))),
        });
    }

    for &(name, set) in fields {
        let bytes = match json[name].as_str() {
            Some(text) => Some(base64url(text)?),
            None => hex_field(json, &format!("{}_hex", name))?,
        };
        if let Some(bytes) = bytes {
            set(&mut key, bytes);
        }
    }
    Ok(key)
}

fn text(value: &Value) -> Vec<u8> {
    value.as_str().unwrap_or_default().as_bytes().to_vec()
}
fn hex_value(value: &Value) -> Result<Vec<u8>, Outcome> {
    hex::decode(value.as_str().unwrap_or_default()).map_err(|e| skip(e.to_string()))
}

fn hex_field(json: &Value, name: &str) -> Result<Option<Vec<u8>>, Outcome> {
    json[name]
        .as_str()
        .map(|text| hex::decode(text).map_err(|e| skip(e.to_string())))
        .transpose()
}

fn certs(value: &Value) -> Result<Vec<Vec<u8>>, Outcome> {
    match value.as_array() {
        Some(list) => list.iter().map(hex_value).collect(),
        None => Ok(vec![hex_value(value)?]),
    }
}

fn rng_stream(input: &Value) -> Vec<Vec<u8>> {
    input["rng_stream"]
        .as_array()
        .map(|entries| {
            entries
                .iter()
                .filter_map(|e| hex::decode(e.as_str()?).ok())
                .collect()
        })
        .unwrap_or_default()
}

fn base64url(v: &str) -> Result<Vec<u8>, Outcome> {
    let mut out = v.to_string();
    out = out.replace("-", "+");
    out = out.replace("_", "/");
    let pad = out.len() % 4;
    if pad == 2 {
        out += "==";
    } else if pad == 3 {
        out += "=";
    }
    let config = GeneralPurposeConfig::new().with_decode_allow_trailing_bits(true);
    let engine = GeneralPurpose::new(&alphabet::STANDARD, config);
    engine.decode(out).map_err(|e| skip(e.to_string()))
}
