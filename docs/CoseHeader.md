# Protected and unprotected

Each parameter is placed in one of two buckets when it is set, protected parameters are covered
by the cryptographic operations, while unprotected ones are not and can be changed in transit.
Parameters that affect security, such as `alg`, belong in the protected bucket; a verifier can
then check this with [`protected`](CoseHeader::protected).

Values are read with getters (`alg()`) and written with setters (`set_alg(...)`). The setters
also record the bucket, which is why the fields are not public.

# Supported parameters

- General: algorithm, critical, content type, key ID, counter signature
- Encryption: IV, Partial IV
- Key agreement: ephemeral key, static key, static key ID, salt, PartyU/PartyV information
- X.509 ([RFC 9360](https://www.rfc-editor.org/rfc/rfc9360)): x5bag, x5chain, x5t, x5u and
their `sender` variants

Parameters that cannot appear together are kept exclusive, for example setting the IV removes
the Partial IV and setting one ECDH sender key (ephemeral, static or static key ID) removes the
others.

The header also holds two inputs of the key derivation context that are never sent in the
message, because both parties must already know them prior to the exchange: `SuppPubInfo`
and `SuppPrivInfo`. They are bound into the derived key, so the recipient must set the same
values before decoding.


# Setter parameters

Setters for parameters that are sent in the message take a [`Bucket`]:

- [`Bucket::Protected`]: protected by the cryptographic operations.
- [`Bucket::Unprotected`]: not protected by the cryptographic operations.
- [`Bucket::Critical`]: protected and listed in `crit`, so a recipient that doesn't understand the
  parameter must reject the message.


Calling a setter again repalces the previous value and placement. Key derivation context parameters
also take a [`Party`] (U or V), and `set_party_identity` takes an `Option<Bucket>` where `None` uses
it in the key derivation without including it in the message.
