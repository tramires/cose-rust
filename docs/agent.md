Signers, recipients and counter signers ([`CoseAgent`]).


# Adding a counter signature

```
# use cose::message::CoseMessage;
use cose::agent::CoseAgent;
# use cose::keys;
use cose::algs;
# use hex;
# let msg = b"This is the content.".to_vec();
# let mut mkey = keys::CoseKey::new();
# mkey.bytes =
# hex::decode("A601020258246D65726961646F632E6272616E64796275636B406275636B6C616E642E6578616D706C65200121582065EDA5A12577C2BAE829437FE338701A10AAA375E1BB5B5DE108DE439C08551D2258201E52ED75701163F7F9E40DDF9F341B3DC9BA860AF7E0CA7CA7E9EECD0084D19C235820AFF907C99F9AD3AAE6C4CDF21122BCE2BD68B5283E6907154AD911840FA208CF").unwrap();
# mkey.decode()?;
# let mut cose_message = CoseMessage::new_sign();
# cose_message.header.set_alg(algs::ES256, true, false);
# cose_message.header.set_kid(mkey.kid().unwrap(), true, false);
# cose_message.payload = msg;
# cose_message.key(&mkey)?;
# cose_message.secure_content(None).unwrap();
# let mut key = keys::CoseKey::new();
# key.bytes =
# hex::decode("A60102024231312001215820BAC5B11CAD8F99F9C72B05CF4B9E26D244DC189F745228255A219A86D6A09EFF22582020138BF82DC1B6D562BE0FA54AB7804A3A64B6D72CCFED6B6FB6ED28BBFC117E23582057C92077664146E876760C9520D054AA93C3AFB04E306705DB6090308507B4D3").unwrap();
# key.decode()?;

let mut counter = CoseAgent::new_counter_sig();

// Prepare the headers
counter.header.set_alg(algs::ES256, true, false);
counter.header.set_kid(key.kid().unwrap(), true, false);

// Add the cose-key to the counter signer
counter.key(&key)?;

// Counter sign and add the counter signature to the message
cose_message.sign_counter(counter, None)?;

// Encode the final message
cose_message.encode(true)?;

# Ok::<(), cose::errors::CoseError>(())
```

# Verifying

```
use cose::message::CoseMessage;

# use cose::agent::CoseAgent;
# use cose::keys;
# use hex;
# let mut mkey = keys::CoseKey::new();
# mkey.bytes =
# hex::decode("A601020258246D65726961646F632E6272616E64796275636B406275636B6C616E642E6578616D706C65200121582065EDA5A12577C2BAE829437FE338701A10AAA375E1BB5B5DE108DE439C08551D2258201E52ED75701163F7F9E40DDF9F341B3DC9BA860AF7E0CA7CA7E9EECD0084D19C235820AFF907C99F9AD3AAE6C4CDF21122BCE2BD68B5283E6907154AD911840FA208CF").unwrap();
# mkey.decode()?;
# let bytes = hex::decode("d284582aa201260458246d65726961646f632e6272616e64796275636b406275636b6c616e642e6578616d706c65a1078347a2044231310126a0584043e4f6cb352d4fc0942b129e76cdf89690fe2a7a2a5d015abac74968c72b22064126ea3addec92c6ba5257be4295e631f34478f1d7a80be3ac832bd714a39cee54546869732069732074686520636f6e74656e742e58408c6d7a58caa8e23ad509ba291cb17689d61e4ad96a51b4a76d46785655df118cc4137815606d983e0bc55ab45f332aebfef85d4c50965269fc90de5651235ba1").unwrap();
let mut verifier = CoseMessage::new_from_bytes(bytes)?;
verifier.init_decoder(None)?;
# verifier.key(&mkey)?;
# verifier.decode(None, None)?;
# let mut key = keys::CoseKey::new();
# key.bytes =
# hex::decode("A60102024231312001215820BAC5B11CAD8F99F9C72B05CF4B9E26D244DC189F745228255A219A86D6A09EFF22582020138BF82DC1B6D562BE0FA54AB7804A3A64B6D72CCFED6B6FB6ED28BBFC117E23582057C92077664146E876760C9520D054AA93C3AFB04E306705DB6090308507B4D3").unwrap();
# key.decode()?;

// get the counter signature index by the key ID
let i = verifier.header.counter_indices(key.kid().unwrap())[0];

// Add counter key and verify
verifier.verify_counter(i, &key, None)?;

# Ok::<(), cose::errors::CoseError>(())
```

# Adding an externally signed counter signature

When the signing key is held outside this crate (an HSM, a timestamp authority...):

1. [`CoseMessage::get_to_sign`](crate::message::CoseMessage::get_to_sign) to counter sign the message or
   [`CoseAgent::get_to_sign`](CoseAgent::get_to_sign) to counter sign the agent, which returns the bytes
   to be signed externally.
2. The external signer then signs the bytes, and [`add_signatures`](CoseAgent::add_signature) takes
   that signature and stores it back in the counter signer.
3. [`CoseMessage::add_counter_sig`](crate::message::CoseMessage::add_counter_sig) and
   [`CoseAgent::add_counter_sig`](CoseAgent::add_counter_sig) attaches the already signed
   counter signature to the message, agent or signer.

```
use cose::message::CoseMessage;
# use cose::agent::CoseAgent;
# use cose::keys;
# use cose::algs;
# use openssl::pkey::{Id, PKey};
# use hex;
# let msg = b"This is the content.".to_vec();
# let mut mkey = keys::CoseKey::new();
# mkey.bytes =
# hex::decode("A601020258246D65726961646F632E6272616E64796275636B406275636B6C616E642E6578616D706C65200121582065EDA5A12577C2BAE829437FE338701A10AAA375E1BB5B5DE108DE439C08551D2258201E52ED75701163F7F9E40DDF9F341B3DC9BA860AF7E0CA7CA7E9EECD0084D19C235820AFF907C99F9AD3AAE6C4CDF21122BCE2BD68B5283E6907154AD911840FA208CF").unwrap();
# mkey.decode()?;
# let mut cose_message = CoseMessage::new_sign();
# cose_message.header.set_alg(algs::ES256, true, false);
# cose_message.header.set_kid(mkey.kid().unwrap(), true, false);
# cose_message.payload = msg;
# cose_message.key(&mkey)?;
# cose_message.secure_content(None).unwrap();
# let mut counter = CoseAgent::new_counter_sig();
# counter.header.set_alg(algs::ES256, true, false);
# counter.header.set_kid(b"external", true, false);
# fn external_sign(tbs: &[u8]) -> Vec<u8> {
#   let d = hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60").unwrap();  
#   let key = PKey::private_key_from_raw_bytes(&d, Id::ED25519).unwrap();
#   openssl::sign::Signer::new_without_digest(&key).unwrap().sign_oneshot_to_vec(tbs).unwrap()
# }

// get the content to externally sign
let tbs = cose_message.get_to_sign(None, &mut counter)?;

// sign externally
let signature = external_sign(&tbs);

// Add the signature to the counter signer
counter.add_signature(signature)?;

// Add the counter signer to the message
cose_message.add_counter_sig(counter)?;

// Encode the final message
cose_message.encode(true)?;

# Ok::<(), cose::errors::CoseError>(())
```
To verify externally, [`CoseMessage::get_to_verify`](crate::message::CoseMessage::get_to_verify) and
[`CoseAgent::get_to_verify`](CoseAgent::get_to_verify) returns the signature bytes.
