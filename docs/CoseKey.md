# Key types

| `kty` | Always | Public components | Private components |
|-------|--------|-------------------|--------------------|
| EC2 | `crv` | `x`, `y` (or its sign bit, with [`set_y_parity`](CoseKey::set_y_parity)) | `d` |
| OKP | `crv` | `x` | `d` |
| Symmetric | | | `k` |
| RSA ([RFC 8230](https://www.rfc-editor.org/rfc/rfc8230)) | `n`, `e` | | `d`, `p`, `q`, `dp`, `dq`, `qinv` |

A key only needs the components its use requires.

# Key operations

[`set_key_ops`](CoseKey::set_key_ops) restricts what a key may be used for, a key without any
`key_ops` can be used for anything its components allow. For ECDH, the private key `key_ops`, if
present, must include either derive key or derive bits and the public key `key_ops` must be empty.

# Multi-prime RSA keys

RSA keys with more than two primes (the `other` parameter) can be encoded and decoded, but not used
for signing or decryption, as the cryptographic backend does not support them.
