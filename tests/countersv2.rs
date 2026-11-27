use cose::agent::CoseAgent;
use cose::algs;
use cose::errors::{CoseResult, CoseResultWithRet};
use cose::headers::{
    Bucket::{Protected, Unprotected},
    ContentTypeTypes,
};
use cose::keys::CoseKey;
use cose::message::CoseMessage;

const A_1_1: &str = "d8628440a10b8343a10126a10442313158405ac05e289d5d0e1b0a7f048a5d2b643813ded50bc9e49220f4f7278f85f19d4a77d655c9d3b51e805a74b099e1e085aacd97fc29d72f887e8802bb6650cceb2c54546869732069732074686520636f6e74656e742e818343a10126a1044231315840e2aeafd40d69d19dfe6e52077c5d7ff4e408282cbefb5d06cbf414af2e19d982ac45ac98b8544c908b4507de1e90b717c3d34816fe926a2b98f53afd2fa0f30a";
const A_2_1: &str = "d28445a201260300a2044231310b8344a1013823a104581e62696c626f2e62616767696e7340686f626269746f6e2e6578616d706c65588401b1291b0e60a79c459a4a9184a0d393e034b34af069a1cca34f5a913affff698002295fa9f8fcbfb6fdff59132fc0c406e98754a98f1fbfe81c03095f481856bc470170227206fa5bee3c0431c56a66824e7aaf692985952e31271434b2ba2e47a335c658b5e995aeb5d63cf2d0ced367d3e4cc8fffd53b70d115baa9e86961fbd1a5cf54546869732069732074686520636f6e74656e742e5840bb587d6b15f47bfd54d2cbfcecef75451e92b08a514bd439fa3aa65c6ac92df0d7328c4a47529b32add3dd1b4e940071c021e9a8f2641f1d8e3b053ddd65ae52";
const A_3_1: &str = "d8608443a10101a2054cc9cf4df2fe6c632bf78864130b8344a1013823a104581e62696c626f2e62616767696e7340686f626269746f6e2e6578616d706c65588400929663c8789bb28177ae28467e66377da12302d7f9594d2999afa5dfa531294f8896f2b6cdf1740014f4c7f1a358e3a6cf57f4ed6fb02fcf8f7aa989f5dfd07f0700a3a7d8f3c604ba70fa9411bd10c2591b483e1d2c31de003183e434d8fba18f17a4c7e3dfa003ac1cf3d30d44d2533c4989d3ac38c38b71481cc3430c9d65e7ddff58247adbe2709ca818fb415f1e5df66f4e1a51053ba6d65a1a0c52a357da7a644b8070a151b0818344a1013818a220a40102200121582098f50a4ff6c05861c8860d13a638ea56c3f5ad7590bbfbf054e1c7b4d91d628022f50458246d65726961646f632e6272616e64796275636b406275636b6c616e642e6578616d706c6540";
const A_5_1: &str = "d8618543a10105a10b8343a10127a1044231315840602566f4a311dc860740d2df54d4864555e85bc036ea5a6cf7905b96e499c5f66b01c4997f6a20c37c37543adea1d705347d38a5b13594b29583dd741f45510154546869732069732074686520636f6e74656e742e58202bdcc89f058216b8a208ddc6d8b54aa91f48bd63484986565105c9ad5a6682f6818340a20125044a6f75722d73656372657440";
const COUNTERSIGN_SIGNED_01: &str = "d8628443a10300a054546869732069732074686520636f6e74656e742e818343a10127a2078343a10127a10442313158408e1be2f9453d264812e590499132bef3fbf9ee9db27c2c168788e3b7ebe506c04fd3d19faa9f51232af5c959e4ef47928834647f56dfbe939112884d08ef250504423131584077f3eacd11852c4bf9cb1d72fabe6b26fba1d76092b2b5b7ec83b83557652264e69690dbc1172ddc0bf88411c0d25a507fdb247a20c40d5e245fabd3fc9ec106";
const COUNTERSIGN_SIGNED1_01: &str = "d28445a201270300a2078343a10127a10442313158406daed158afe4032e8dd477d3d2b7f667e7957aa8302bb5e568b4dcbcce3cf0ed5a90f831351c85d6155a42a17ca1f25f501cc13f67108ae53bda92db88272e000442313154546869732069732074686520636f6e74656e742e58407142fd2ff96d56db85bee905a76ba1d0b7321a95c8c4d3607c5781932b7afb8711497dfa751bf40b58b3bcc32300b1487f3db34085eef013bf08f4a44d6fef0d";
const V1_V2_MESSAGE: &str = "d28445a201270300a3078343a10127a10442313158406daed158afe4032e8dd477d3d2b7f667e7957aa8302bb5e568b4dcbcce3cf0ed5a90f831351c85d6155a42a17ca1f25f501cc13f67108ae53bda92db88272e00044231310b8343a10127a10441005840adb7b6a59e6dd7456ce72585d7f4d271805ae97ec6af6aa9ff85dc68e29ffb434db08b6c7e6ab6059955f85ffcc6397b9dbb3411e6e5041408910a2ef695b90c54546869732069732074686520636f6e74656e742e58407142fd2ff96d56db85bee905a76ba1d0b7321a95c8c4d3607c5781932b7afb8711497dfa751bf40b58b3bcc32300b1487f3db34085eef013bf08f4a44d6fef0d";

fn get_key(kid: &[u8]) -> CoseResultWithRet<CoseKey> {
    let hex = match kid {
            b"11" => "a501022001215820bac5b11cad8f99f9c72b05cf4b9e26d244dc189f745228255a219a86d6a09eff22582020138bf82dc1b6d562be0fa54ab7804a3a64b6d72ccfed6b6fb6ed28bbfc117e23582057c92077664146e876760c9520d054aa93c3afb04e306705db6090308507b4d3",
            b"bilbo.baggins@hobbiton.example" => "a5010220032158420072992cb3ac08ecf3e5c63dedec0d51a8c1f79ef2f82f94f3c737bf5de7986671eac625fe8257bbd0394644caaa3aaf8f27a4585fbbcad0f2457620085e5c8f42ad22584201dca6947bce88bc5790485ac97427342bc35f887d86d65a089377e247e60baa55e4e8501e2ada5724ac51d6909008033ebc10ac999b9d7f5cc2519f3fe1ea1d947523584200085138ddabf5ca975f5860f91a08e91d6d5f9a76ad4018766a476680b55cd339e8ab6c72b5facdb2a2a50ac25bd086647dd3e2e6e99e84ca2c3609fdf177feb26d",
            b"meriadoc.brandybuck@buckland.example" => "a50102200121582065eda5a12577c2bae829437fe338701a10aaa375e1bb5b5de108de439c08551d2258201e52ed75701163f7f9e40ddf9f341b3dc9ba860af7e0ca7ca7e9eecd0084d19c235820aff907c99f9ad3aae6c4cdf21122bce2bd68b5283e6907154ad911840fa208cf",
            b"ephemeral" => "a50102200121582098f50a4ff6c05861c8860d13a638ea56c3f5ad7590bbfbf054e1c7b4d91d628022f523582002d1f7e6f26c43d4868d87ceb2353161740aacf1f7163647984b522a848df1c3",
            b"11eddsa" => "a401012006215820d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a2358209d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
            b"our-secret" =>"a20104205820849b57219dae48de646d07dbb533566e976686457c1491be3a76dcea6c427188",
            _ => panic!("unknown kid: {:?}", kid),
        };
    let mut key = CoseKey::new();
    key.bytes = hex::decode(hex).unwrap();
    key.decode()?;
    Ok(key)
}

#[test]
fn decode_a_1_1() -> CoseResult {
    let kid = b"11";
    let vector = hex::decode(A_1_1).unwrap();
    let mut verify = CoseMessage::new_from_bytes(vector.clone())?;
    verify.init_decoder(None)?;
    let key = get_key(kid)?;

    let i = verify.agent_indices(kid)[0];
    verify.agent_mut(i).unwrap().key(&key)?;
    verify.decode(None, Some(i))?;

    let counter = verify.header.counter_indices(kid)[0];
    verify.verify_counter(counter, &key, None)?;
    assert_eq!(verify.payload, b"This is the content.");

    // check if decoded as v2, re-encoding to assert with v2 label
    verify.encode(true)?;
    assert_eq!(verify.bytes, vector);

    Ok(())
}

#[test]
fn encode_a_1_1() -> CoseResult {
    let kid = b"11";
    let payload = b"This is the content.".to_vec();

    let mut sign = CoseMessage::new_sign();
    sign.payload = payload;

    let key = get_key(kid)?;

    let mut agent = CoseAgent::new();
    agent.header.set_kid(kid, Unprotected);
    agent.header.set_alg(algs::ES256, Protected);
    agent.key(&key)?;

    sign.add_agent(&mut agent)?;
    sign.secure_content(None)?;

    let mut counter = CoseAgent::new_counter_sig();
    counter.header.set_kid(kid, Unprotected);
    counter.header.set_alg(algs::ES256, Protected);
    counter.key(&key)?;
    sign.sign_counter(counter, None)?;

    sign.encode(true)?;

    assert_eq!(sign.bytes, hex::decode(A_1_1).unwrap());
    Ok(())
}

#[test]
fn decode_a_2_1() -> CoseResult {
    let kid = b"11";
    let kid_counter = b"bilbo.baggins@hobbiton.example";
    let mut verify = CoseMessage::new_from_bytes(hex::decode(A_2_1).unwrap())?;
    verify.init_decoder(None)?;
    let key = get_key(kid)?;

    verify.key(&key)?;
    verify.decode(None, None)?;

    let key_counter = get_key(kid_counter)?;

    let counter = verify.header.counter_indices(kid_counter)[0];
    verify.verify_counter(counter, &key_counter, None)?;

    assert_eq!(verify.payload, b"This is the content.");
    Ok(())
}

#[test]
fn encode_a_2_1() -> CoseResult {
    let kid = b"11";
    let kid_counter = b"bilbo.baggins@hobbiton.example";
    let payload = b"This is the content.".to_vec();

    let mut sign = CoseMessage::new_sign();
    sign.payload = payload;
    sign.header.set_kid(kid, Unprotected);
    sign.header.set_alg(algs::ES256, Protected);
    sign.header
        .set_content_type(ContentTypeTypes::Uint(0), Protected);

    let key = get_key(kid)?;

    sign.key(&key)?;
    sign.secure_content(None)?;

    let key_counter = get_key(kid_counter)?;

    let mut counter = CoseAgent::new_counter_sig();
    counter.header.set_kid(kid_counter, Unprotected);
    counter.header.set_alg(algs::ES512, Protected);
    counter.key(&key_counter)?;
    sign.sign_counter(counter, None)?;

    sign.encode(true)?;

    // Probabilistic
    assert_eq!(sign.bytes.len(), hex::decode(A_2_1).unwrap().len());

    // Round trip
    let mut verify = CoseMessage::new_from_bytes(sign.bytes)?;
    verify.init_decoder(None)?;
    verify.key(&key)?;
    verify.decode(None, None)?;

    verify.verify_counter(0, &key_counter, None)?;

    Ok(())
}

#[test]
fn decode_a_3_1() -> CoseResult {
    let kid = b"meriadoc.brandybuck@buckland.example";
    let kid_counter = b"bilbo.baggins@hobbiton.example";
    let vector = hex::decode(A_3_1).unwrap();
    let mut dec = CoseMessage::new_from_bytes(vector.clone())?;
    dec.init_decoder(None)?;

    let key = get_key(kid)?;

    let i = dec.agent_indices(kid)[0];
    dec.agent_mut(i).unwrap().key(&key)?;
    let payload = dec.decode(None, Some(i))?;

    let key_counter = get_key(kid_counter)?;

    let counter = dec.header.counter_indices(kid_counter)[0];
    dec.verify_counter(counter, &key_counter, None)?;

    assert_eq!(payload, b"This is the content.");

    // check if decoded as v2, re-encoding to assert with v2 label
    dec.encode(true)?;
    assert_eq!(dec.bytes, vector);

    Ok(())
}

#[test]
fn encode_a_3_1_1() -> CoseResult {
    let kid = b"meriadoc.brandybuck@buckland.example";
    let kid_counter = b"bilbo.baggins@hobbiton.example";
    let payload = b"This is the content.".to_vec();

    let mut enc = CoseMessage::new_encrypt();
    enc.header.set_alg(algs::A128GCM, Protected);
    enc.header.set_iv(
        hex::decode("c9cf4df2fe6c632bf7886413").unwrap(),
        Unprotected,
    );
    enc.payload = payload;

    let key = get_key(kid)?;

    let mut agent = CoseAgent::new();
    agent.header.set_alg(algs::ECDH_ES_HKDF_256, Protected);
    agent.key(&key)?;

    let key_ephemeral = get_key(b"ephemeral")?;

    agent.header.set_ephemeral_key(key_ephemeral, Unprotected);

    // kid second to match vector
    agent.header.set_kid(kid, Unprotected);

    enc.add_agent(&mut agent)?;

    enc.secure_content(None)?;

    let key_counter = get_key(kid_counter)?;

    let mut counter = CoseAgent::new_counter_sig();
    counter.header.set_kid(kid_counter, Unprotected);
    counter.header.set_alg(algs::ES512, Protected);
    counter.key(&key_counter)?;
    enc.sign_counter(counter, None)?;

    enc.encode(true)?;

    // probabilistic
    assert_eq!(enc.bytes.len(), hex::decode(A_3_1).unwrap().len());

    // Round trip
    let mut dec = CoseMessage::new_from_bytes(enc.bytes)?;
    dec.init_decoder(None)?;

    dec.agent_mut(0).unwrap().key(&key)?;
    dec.decode(None, Some(0))?;

    dec.verify_counter(0, &key_counter, None)?;

    Ok(())
}
#[test]
fn decode_a_5_1() -> CoseResult {
    let kid = b"our-secret";
    let kid_counter = b"11";
    let mut ver = CoseMessage::new_from_bytes(hex::decode(A_5_1).unwrap())?;
    ver.init_decoder(None)?;

    let key = get_key(kid)?;

    let i = ver.agent_indices(kid)[0];
    ver.agent_mut(i).unwrap().key(&key)?;
    let payload = ver.decode(None, Some(i))?;

    let key_counter = get_key(b"11eddsa")?;

    let counter = ver.header.counter_indices(kid_counter)[0];
    ver.verify_counter(counter, &key_counter, None)?;

    assert_eq!(payload, b"This is the content.");
    Ok(())
}

#[test]
fn encode_a_5_1() -> CoseResult {
    let kid = b"our-secret";
    let kid_counter = b"11";
    let payload = b"This is the content.".to_vec();

    let mut mac = CoseMessage::new_mac();
    mac.header.set_alg(algs::HMAC_256_256, Protected);
    mac.payload = payload;

    let key = get_key(kid)?;

    let mut agent = CoseAgent::new();
    agent.header.set_alg(algs::DIRECT, Unprotected);
    agent.header.set_kid(kid, Unprotected);
    agent.key(&key)?;

    mac.add_agent(&mut agent)?;

    mac.secure_content(None)?;

    let key_counter = get_key(b"11eddsa")?;

    let mut counter = CoseAgent::new_counter_sig();
    counter.header.set_kid(kid_counter, Unprotected);
    counter.header.set_alg(algs::EDDSA, Protected);
    counter.key(&key_counter)?;
    mac.sign_counter(counter, None)?;

    mac.encode(true)?;

    assert_eq!(mac.bytes, hex::decode(A_5_1).unwrap());
    Ok(())
}

#[test]
fn encode_v2_on_signer() -> CoseResult {
    let kid = b"11";
    let payload = b"This is the content.".to_vec();

    let mut sign = CoseMessage::new_sign();
    sign.header
        .set_content_type(ContentTypeTypes::Uint(0), Protected);
    sign.payload = payload;

    let key = get_key(b"11eddsa")?;

    let mut agent = CoseAgent::new();
    agent.header.set_alg(algs::EDDSA, Protected);
    agent.key(&key)?;

    sign.add_agent(&mut agent)?;
    sign.secure_content(None)?;

    let mut counter = CoseAgent::new_counter_sig();
    counter.header.set_kid(kid, Unprotected);
    counter.header.set_alg(algs::EDDSA, Protected);
    counter.key(&key)?;

    let agent_mut = sign.agent_mut(0).unwrap();
    agent_mut.sign_counter(counter, None)?;

    // kid second
    agent_mut.header.set_kid(kid, Unprotected);

    sign.encode(true)?;

    let encoded = sign.bytes;
    let mut expected = hex::decode(COUNTERSIGN_SIGNED_01).unwrap();

    assert_eq!(expected[35], 0xa2); // signer's unprotected map
    assert_eq!(expected[36], 0x07); // v1 counter label

    // switch to v2 label, since the counter signature structure remains for cose-sign signers
    expected[36] = 0x0b;

    assert_eq!(encoded, expected);
    Ok(())
}

#[test]
fn reencode_keeps_v1() -> CoseResult {
    let kid = b"11";
    let mut verify = CoseMessage::new_from_bytes(hex::decode(COUNTERSIGN_SIGNED1_01).unwrap())?;
    verify.init_decoder(None)?;

    let key = get_key(b"11eddsa")?;

    verify.key(&key)?;
    verify.decode(None, None)?;

    let counter = verify.header.counter_indices(kid)[0];
    verify.verify_counter(counter, &key, None)?;
    assert_eq!(verify.payload, b"This is the content.");

    verify.encode(true)?;

    // Check if it keeps the v1 when encoding back
    assert_eq!(verify.bytes, hex::decode(COUNTERSIGN_SIGNED1_01).unwrap());
    Ok(())
}

#[test]
fn v1_and_v2_on_sign1() -> CoseResult {
    let kid = b"11";
    let mut verify = CoseMessage::new_from_bytes(hex::decode(COUNTERSIGN_SIGNED1_01).unwrap())?;
    verify.init_decoder(None)?;

    let key = get_key(b"11eddsa")?;
    verify.key(&key)?;
    verify.decode(None, None)?;

    // v1 counter
    let counter = verify.header.counter_indices(kid)[0];
    verify.verify_counter(counter, &key, None)?;
    assert_eq!(verify.payload, b"This is the content.");

    // add new counter w/ v2
    let mut agent = CoseAgent::new_counter_sig();
    agent.header.set_kid([0], Unprotected);
    agent.header.set_alg(algs::EDDSA, Protected);
    agent.key(&key)?;
    verify.sign_counter(agent, None)?;

    verify.encode(true)?;

    // check if re-decoding into the same struct replaces its state
    verify.init_decoder(None)?;
    assert_eq!(verify.header.counter_indices(kid).len(), 1);
    assert_eq!(verify.header.counter_indices(&[0]).len(), 1);

    let encoded = verify.bytes;

    assert_eq!(encoded, hex::decode(V1_V2_MESSAGE).unwrap());

    let mut check = CoseMessage::new_from_bytes(encoded)?;
    check.init_decoder(None)?;

    let mut counter = check.header.counter_indices(kid)[0];
    check.verify_counter(counter, &key, None)?;

    counter = check.header.counter_indices(&[0])[0];
    check.verify_counter(counter, &key, None)?;

    Ok(())
}

fn external_sign(tbs: &[u8]) -> Vec<u8> {
    use openssl::pkey::{Id, PKey};
    let d =
        hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60").unwrap();
    let key = PKey::private_key_from_raw_bytes(&d, Id::ED25519).unwrap();
    openssl::sign::Signer::new_without_digest(&key)
        .unwrap()
        .sign_oneshot_to_vec(tbs)
        .unwrap()
}

#[test]
fn external_counter_sign() -> CoseResult {
    let kid = b"our-secret";
    let kid_counter = b"11";
    let payload = b"This is the content.".to_vec();

    let mut mac = CoseMessage::new_mac();
    mac.header.set_alg(algs::HMAC_256_256, Protected);
    mac.payload = payload;

    let key = get_key(kid)?;

    let mut agent = CoseAgent::new();
    agent.header.set_alg(algs::DIRECT, Unprotected);
    agent.header.set_kid(kid, Unprotected);
    agent.key(&key)?;

    mac.add_agent(&mut agent)?;

    mac.secure_content(None)?;

    agent = CoseAgent::new_counter_sig();
    agent.header.set_kid(kid_counter, Unprotected);
    agent.header.set_alg(algs::EDDSA, Protected);

    // counter sign externally
    let tbs = mac.get_to_sign(None, &mut agent)?;
    let signature = external_sign(&tbs);
    agent.add_signature(signature)?;
    mac.add_counter_sig(agent)?;

    mac.encode(true)?;

    let bytes = mac.bytes;

    assert_eq!(bytes, hex::decode(A_5_1).unwrap());

    let mut check = CoseMessage::new_from_bytes(bytes)?;
    check.init_decoder(None)?;
    let i = check.header.counter_indices(kid_counter)[0];

    // Check if counter signature v2 context is provided correctly
    assert_eq!(check.get_to_verify(None, i)?, tbs);
    Ok(())
}

#[test]
fn decode_tagged() -> CoseResult {
    let kid = b"11";
    // add a counter signature v2 tag to A.1.1 example
    let vector = hex::decode(A_1_1.replacen("a10b83", "a10bd383", 1)).unwrap();
    let mut verify = CoseMessage::new_from_bytes(vector)?;
    verify.init_decoder(None)?;
    let key = get_key(kid)?;

    let i = verify.agent_indices(kid)[0];
    verify.agent_mut(i).unwrap().key(&key)?;
    verify.decode(None, Some(i))?;

    let counter = verify.header.counter_indices(kid)[0];
    verify.verify_counter(counter, &key, None)?;
    assert_eq!(verify.payload, b"This is the content.");

    Ok(())
}
