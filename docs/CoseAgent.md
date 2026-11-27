`CoseAgent` is a party of a COSE message with its own headers and key.

| Role | Used in | Constructor | Algorithms |
|------|---------|-------------|------------|
| Signer | cose-sign | [`CoseAgent::new`] | signature algorithms |
| Recipient | cose-encrypt, cose-mac | [`CoseAgent::new`] | key distribution algorithms |
| Counter signer | any COSE message type, signer or recipient | [`CoseAgent::new_counter_sig`] | signature algorithms |

With the exception of counter signatures, the role of the signers and recipients is decided
when they are added to a `CoseMessage` with [`add_agent`](crate::message::CoseMessage::add_agent).

# Encoding

Create the agent and set its headers and key ([`key`](CoseAgent::key)), and add it to the
message. The message's [`secure_content`](crate::message::CoseMessage::secure_content) then
signs/encrypts for every agent.

# Decoding

After the initial decoding of the message parameters
([`init_decoder`](crate::message::CoseMessage::init_decoder)), find a given agent with the use
of [`agent_indices`](crate::message::CoseMessage::agent_indices) or via the 
[`agents`](crate::message::CoseMessage::agents) getter, set its key through
[`agent_mut`](crate::message::CoseMessage::agent_mut), and decode the message with the agent index.

# Counter signatures

A counter signature is a signature over an already secured message, signer or recipient. It can
be added by another party, at any time, without changing the original, making it suitable for
adding further proof, such as a timestamp.

The counter signatures created by this crate use the format from [RFC 9338](https://www.rfc-editor.org/rfc/rfc9338/)
 (label 11). The older [RFC 8152](https://www.rfc-editor.org/rfc/rfc8152/) format (label 7), which
[RFC 9338](https://www.rfc-editor.org/rfc/rfc9338/) deprecates but still requires verifiers to
accept, is decoded and verified, and keeps its format when the message is re-encoded.
