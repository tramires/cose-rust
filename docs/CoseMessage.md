A COSE message of any of the six types.

| Type | Protects with | Key goes to | Constructor |
|------|---------------|-------------|-------------|
| cose-sign1 / cose-sign | signature | message / each signer | [`new_sign`](crate::message::CoseMessage::new_sign) |
| cose-encrypt0 / cose-encrypt | encryption | message / each recipient | [`new_encrypt`](crate::message::CoseMessage::new_encrypt) |
| cose-mac0 / cose-mac | MAC | message / each recipient| [`new_mac`](crate::message::CoseMessage::new_mac) |


A message is encoded as the multi-agent form (cose-sign, cose-encrypt, cose-mac) once agents
are added with [`add_agent`](crate::message::CoseMessage::add_agent), and as the single agent form otherwise.

# External AAD

Data protected by the signature, MAC or encryption, but not carried in the message. Both the
sender and receiver must use the same bytes; use `None` for no external data.

# Detached payload

The payload can be transported separately ("detached content"), making it absent from the COSE
message. It must be then provided in the decoding process, to
[`init_decoder`](crate::message::CoseMessage::init_decoder).

# Tagged and untagged

A tagged message starts with a CBOR tag that identifies its type, so it can be decoded with
`new_from_bytes` which picks the type from the tag. The type-specific constructors (`new_sign`,
`new_encrypt` and `new_mac`) work as well, as long they match the tag.

An untagged message has no identifier present, so the type must be previously known to decode
it properly with the matching constructor (`new_sign`, `new_encrypt`, `new_mac`).

