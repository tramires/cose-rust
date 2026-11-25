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

Most setters take two flags:
- `prot`: `true` places the parameter in the protected bucket, `false` in the unprotected one
- `crit`: `true` also marks the parameter as critical, so a recipient that does not understand
it must reject the message.
