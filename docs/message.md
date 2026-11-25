COSE message [`CoseAgent`](crate::message::CoseMessage).


# Cose-encrypt0 encode and decode

```
use cose::message::CoseMessage;
use cose::keys;
use cose::algs;
use hex;

let msg = b"This is the content.".to_vec();
let kid = b"example".to_vec();

let mut enc = CoseMessage::new_encrypt();

// Prepare the cose-key
let mut key = keys::CoseKey::new();
key.set_kty(keys::SYMMETRIC);
key.set_k(hex::decode("849b57219dae48de646d07dbb533566e976686457c1491be3a76dcea6c427188").unwrap());

// Prepare cose-encrypt0 parameters
enc.header.set_alg(algs::CHACHA20, true, false);
enc.header.set_iv(hex::decode("89f52f65a1c580933b5261a7").unwrap(), true, false);
enc.payload = msg.clone();
enc.key(&key)?;

// Generate the ciphertext
enc.secure_content(None)?;

// Encode the cose-encrypt0 message
enc.encode(true)?;

// Prepare decoder
let mut dec = CoseMessage::new_from_bytes(enc.bytes)?;

// Init decoding
dec.init_decoder(None)?;

// Add cose-key
dec.key(&key)?;

// Decrypt the cose-encrypt0 message
let payload = dec.decode(None, None)?;
assert_eq!(payload, msg);

# Ok::<(), cose::errors::CoseError>(())
```

# cose-sign (2 signers)

Encode and decode cose-sign message with 2 signers, using ECDSA w/ SHA-256 and EdDSA

## Encode
```
use cose::message::CoseMessage;
use cose::keys;
use cose::algs;
use cose::agent::CoseAgent;
use hex;

let msg = b"This is the content.".to_vec();
let s1_kid = vec![0];
let s2_kid = vec![1];

// Prepare cose-sign message
let mut sign = CoseMessage::new_sign();
sign.payload = msg;

// Prepare first signer headers
let mut signer1 = CoseAgent::new();
signer1.header.set_alg(algs::ES256, true, false);
signer1.header.set_kid(s1_kid, false, false);

// First signer key
let mut key = keys::CoseKey::new();
key.set_kty(keys::EC2);
key.set_crv(keys::P_256);
key.set_d(hex::decode(
    "57c92077664146e876760c9520d054aa93c3afb04e306705db6090308507b4d3"
).unwrap());

signer1.key(&key)?;

// Add first signer to the cose-sgin message
sign.add_agent(&mut signer1)?;

// Prepare second signer headers
let mut signer2 = CoseAgent::new();
signer2.header.set_alg(algs::EDDSA, true, false);
signer2.header.set_kid(s2_kid, true, false);

// Second signer key
key = keys::CoseKey::new();
key.set_kty(keys::OKP);
key.set_crv(keys::ED25519);
key.set_d(hex::decode(
    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
).unwrap());

signer2.key(&key).unwrap();

// Add second signer to the cose-sign message
sign.add_agent(&mut signer2).unwrap();

// Generate signature and encode cose-sign message
sign.secure_content(None).unwrap();
sign.encode(true).unwrap();

let encoded = sign.bytes;

# Ok::<(), cose::errors::CoseError>(())
```

## Decode
```
use cose::message::CoseMessage;
use cose::keys;
use cose::algs;
use cose::agent::CoseAgent;
use hex;

# let encoded = hex::decode("d8628440a054546869732069732074686520636f6e74656e742e828343a10126a10441005840e2aeafd40d69d19dfe6e52077c5d7ff4e408282cbefb5d06cbf414af2e19d982ac45ac98b8544c908b4507de1e90b717c3d34816fe926a2b98f53afd2fa0f30a8346a20127044101a05840c3bfb1ae4b9a2d0809d0bf3a9636b9121b66808676cede81bff7f3146162c409b4791c3e01b834cd6a15ee82c2bb4eb76d43b982553e3b652e64a60f800f6106").unwrap();
let s1_kid = vec![0];
let s2_kid = vec![1];
// Prepare CoseSign with the cose-sign bytes
let mut verify = CoseMessage::new_from_bytes(encoded)?;

// Init decoding
verify.init_decoder(None).unwrap();

// Prepare first signer key
let mut key = keys::CoseKey::new();
key.set_kty(keys::EC2);
key.set_crv(keys::P_256);
key.set_x(hex::decode(
    "bac5b11cad8f99f9c72b05cf4b9e26d244dc189f745228255a219a86d6a09eff"
).unwrap());
key.set_y(hex::decode(
    "20138bf82dc1b6d562be0fa54ab7804a3a64b6d72ccfed6b6fb6ed28bbfc117e"
).unwrap());

// Get first signer and verify
let mut i = verify.agent_indices(&s1_kid)?[0];
verify.agent_mut(i).unwrap().key(&key)?;
verify.decode(None, Some(i))?;

// Prepare second signer key
key = keys::CoseKey::new();
key.set_kty(keys::OKP);
key.set_crv(keys::ED25519);
key.set_x(hex::decode(
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
).unwrap());

// Get second signer and verify
i = verify.agent_indices(&s2_kid)?[0];
verify.agent_mut(i).unwrap().key(&key)?;
verify.decode(None, Some(i))?;

# Ok::<(), cose::errors::CoseError>(())
```

# cose-encrypt

Encode and decode cose-encrypt message with AES-GCM algorithm with one recipients using ECDH-ES + A128KW as the key distribution.

## Encode
```
use cose::message::CoseMessage;
use cose::keys;
use cose::headers;
use cose::algs;
use cose::agent::CoseAgent;
use hex;

let msg = b"This is the content.".to_vec();
let kid = vec![0];

// Prepare cose-encrypt message
let mut enc = CoseMessage::new_encrypt();
enc.header.set_alg(algs::A128GCM, true, false);
enc.header.set_iv(hex::decode("89f52f65a1c580933b5261a7").unwrap(), true, false);
enc.payload = msg;

// Prepare recipient headers
let mut rec = CoseAgent::new();
rec.header.set_alg(algs::ECDH_ES_A128KW, true, false);
rec.header.set_kid(kid, false, false);

// Prepare receiver key
let mut key = keys::CoseKey::new();
key.set_kty(keys::EC2);
key.set_crv(keys::P_256);
key.set_x(hex::decode(
    "bac5b11cad8f99f9c72b05cf4b9e26d244dc189f745228255a219a86d6a09eff"
).unwrap());
key.set_y(hex::decode(
    "20138bf82dc1b6d562be0fa54ab7804a3a64b6d72ccfed6b6fb6ed28bbfc117e"
).unwrap());

rec.key(&key)?;

// Prepare sender ephemeral key
key = keys::CoseKey::new();
key.set_kty(keys::EC2);
key.set_crv(keys::P_256);
key.set_x(hex::decode(
    "65eda5a12577c2bae829437fe338701a10aaa375e1bb5b5de108de439c08551d"
).unwrap());
key.set_y_parity(true);
key.set_d(hex::decode(
    "aff907c99f9ad3aae6c4cdf21122bce2bd68b5283e6907154ad911840fa208cf"
).unwrap());

rec.header.set_ephemeral_key(key, true, false);

enc.add_agent(&mut rec)?;

// Generate ciphertext and encode cose-encrypt message
enc.secure_content(None)?;
enc.encode(true)?;

let encoded = enc.bytes;

# Ok::<(), cose::errors::CoseError>(())
```

## Decode
```
use cose::message::CoseMessage;
use cose::keys;
use cose::headers;
use cose::algs;
use cose::agent::CoseAgent;
use hex;

# let encoded = hex::decode("d8608451a20101054c89f52f65a1c580933b5261a7a0582429f8734ff9a26888ffca9fa4e0d92e1d09d238ec3e9278a873cac8cc1e7bcc78408d83068183582fa201381c20a40102200121582065eda5a12577c2bae829437fe338701a10aaa375e1bb5b5de108de439c08551d22f5a10441005818f2d0cdda8afb7c51f7cdbd0e0cbc1333d30d21ef9912d490").unwrap();
let expected = b"This is the content.".to_vec();
let kid = vec![0];

// Initial message decoding
let mut dec = CoseMessage::new_from_bytes(encoded)?;
dec.init_decoder(None)?;

// Prepare recipient ECDH key
let mut key = keys::CoseKey::new();
key.set_kty(keys::EC2);
key.set_crv(keys::P_256);
key.set_d(hex::decode(
    "57c92077664146e876760c9520d054aa93c3afb04e306705db6090308507b4d3"
).unwrap());

// Get recipient and decode the message
let mut i = dec.agent_indices(&kid)?[0];
dec.agent_mut(i).unwrap().key(&key)?;
let msg = dec.decode(None, Some(i))?;
assert_eq!(msg, expected);

# Ok::<(), cose::errors::CoseError>(())
```

# Detached payload

```
# use cose::message::CoseMessage;
# use cose::keys;
# use cose::algs;
# use hex;
# let msg = b"This is the content.".to_vec();
# let kid = b"example".to_vec();
# let mut enc = CoseMessage::new_mac();
# let mut key = keys::CoseKey::new();
# key.set_kty(keys::SYMMETRIC);
# key.set_k(hex::decode("849b57219dae48de646d07dbb533566e976686457c1491be3a76dcea6c427188").unwrap());
# enc.header.set_alg(algs::HMAC_256_256, true, false);
# enc.payload = msg.clone();
# enc.key(&key)?;
# enc.secure_content(None)?;
// The payload is left out of the message
enc.encode(false)?;

// Prepare decoder
let mut dec = CoseMessage::new_from_bytes(enc.bytes)?;

// The payload is provided on the initial decoding
dec.init_decoder(Some(msg.clone()))?;

// Add key
dec.key(&key)?;

// Final decode of the message
let payload = dec.decode(None, None)?;
assert_eq!(payload, msg);

# Ok::<(), cose::errors::CoseError>(())
```

# Untagged

```
# use cose::message::CoseMessage;
# use cose::keys;
# use cose::algs;
# let encoded = hex::decode("d28447a2012604423131a054546869732069732074686520636f6e74656e742e58405e84ce5812b0966e6919ff1ac15c030666bae902c0705d1e0a5fbac828437c63b0bb87a95a456835f4d115850adefcf0fd0a5c26027140c10d3e20a890c5eaa7").unwrap();
# let mut key = keys::CoseKey::new();
# key.set_kty(keys::EC2);
# key.set_alg(algs::ES256);
# key.set_crv(keys::P_256);
# key.set_x(hex::decode(
#     "bac5b11cad8f99f9c72b05cf4b9e26d244dc189f745228255a219a86d6a09eff"
# ).unwrap());
# key.set_y(hex::decode(
#     "20138bf82dc1b6d562be0fa54ab7804a3a64b6d72ccfed6b6fb6ed28bbfc117e"
# ).unwrap());
// Type of cose-message must be known
let mut received = CoseMessage::new_sign();

// Provide the encoded COSE message bytes
received.bytes = encoded;

received.init_decoder(None)?;
received.key(&key)?;
received.decode(None, None)?;

# Ok::<(), cose::errors::CoseError>(())
```
