COSE keys ([`CoseKey`]) and key sets ([`CoseKeySet`]).

# Encoding

Both [`CoseKey`] and [`CoseKeySet`] are encoded to and decoded from CBOR with their `encode`
and `decode` methods through their `bytes` field.
