//! Algorithm identifiers, IANA [COSE Algorithms](https://www.iana.org/assignments/cose/cose.xhtml#algorithms)
use crate::errors::{CoseError, CoseField, CoseResult, CoseResultWithRet};
use crate::keys;
use openssl::aes::{unwrap_key, wrap_key, AesKey};
use openssl::bn::{BigNum, BigNumContext};
use openssl::cipher::{self, CipherRef};
use openssl::cipher_ctx::CipherCtx;
use openssl::derive::Deriver;
use openssl::ec::{EcGroup, EcKey, EcPoint};
use openssl::ecdsa::EcdsaSig;
use openssl::hash::{hash, MessageDigest};
use openssl::md::{Md, MdRef};
use openssl::nid::Nid;
use openssl::pkey::{Id, PKey};
use openssl::pkey_ctx::{NonceType, PkeyCtx};
use openssl::rand::rand_bytes;
use openssl::rsa::{Padding, Rsa};
use openssl::sign::{RsaPssSaltlen, Signer, Verifier};
use openssl::stack::Stack;
use openssl::symm::{decrypt_aead, encrypt as encr, encrypt_aead, Cipher};
use openssl::x509::{store::X509StoreBuilder, X509StoreContext, X509};

// Signing algotihtms
pub const ES256: i32 = -7;
pub const ES256K: i32 = -47;
pub const ES384: i32 = -35;
pub const ES512: i32 = -36;
pub const EDDSA: i32 = -8;
pub const PS512: i32 = -39;
pub const PS384: i32 = -38;
pub const PS256: i32 = -37;
pub(crate) const SIGNING_ALGS: [i32; 8] = [ES256, ES384, ES512, EDDSA, PS256, PS384, PS512, ES256K];

// Encryption algorithms
pub const A128GCM: i32 = 1;
pub const A192GCM: i32 = 2;
pub const A256GCM: i32 = 3;
pub const CHACHA20: i32 = 24;
pub const AES_CCM_16_64_128: i32 = 10;
pub const AES_CCM_16_64_256: i32 = 11;
pub const AES_CCM_64_64_128: i32 = 12;
pub const AES_CCM_64_64_256: i32 = 13;
pub const AES_CCM_16_128_128: i32 = 30;
pub const AES_CCM_16_128_256: i32 = 31;
pub const AES_CCM_64_128_128: i32 = 32;
pub const AES_CCM_64_128_256: i32 = 33;
pub(crate) const ENCRYPT_ALGS: [i32; 12] = [
    A128GCM,
    A192GCM,
    A256GCM,
    CHACHA20,
    AES_CCM_16_64_128,
    AES_CCM_16_64_256,
    AES_CCM_64_64_128,
    AES_CCM_64_64_256,
    AES_CCM_16_128_128,
    AES_CCM_16_128_256,
    AES_CCM_64_128_128,
    AES_CCM_64_128_256,
];

// MAC algorithms
pub const HMAC_256_64: i32 = 4;
pub const HMAC_256_256: i32 = 5;
pub const HMAC_384_384: i32 = 6;
pub const HMAC_512_512: i32 = 7;
pub const AES_MAC_128_64: i32 = 14;
pub const AES_MAC_256_64: i32 = 15;
pub const AES_MAC_128_128: i32 = 25;
pub const AES_MAC_256_128: i32 = 26;
pub(crate) const MAC_ALGS: [i32; 8] = [
    HMAC_256_64,
    HMAC_256_256,
    HMAC_384_384,
    HMAC_512_512,
    AES_MAC_128_64,
    AES_MAC_256_64,
    AES_MAC_128_128,
    AES_MAC_256_128,
];

pub(crate) const CONTENT_ALGS: [&[i32]; 3] = [&SIGNING_ALGS, &MAC_ALGS, &ENCRYPT_ALGS];

// HASH Algorithms
pub const SHA_256: i32 = -16;
pub const HASH_ALGS: [i32; 1] = [SHA_256];

// Content Key Distribution

//Direct
pub const DIRECT: i32 = -6;
//KDFs
pub const DIRECT_HKDF_SHA_256: i32 = -10;
pub const DIRECT_HKDF_SHA_512: i32 = -11;
pub const DIRECT_HKDF_AES_128: i32 = -12;
pub const DIRECT_HKDF_AES_256: i32 = -13;
//Key Wrap
pub const A128KW: i32 = -3;
pub const A192KW: i32 = -4;
pub const A256KW: i32 = -5;
//RSA OAEP
pub const RSA_OAEP_1: i32 = -40;
pub const RSA_OAEP_256: i32 = -41;
pub const RSA_OAEP_512: i32 = -42;
//Direct Key Agreement
pub const ECDH_ES_HKDF_256: i32 = -25;
pub const ECDH_ES_HKDF_512: i32 = -26;
pub const ECDH_SS_HKDF_256: i32 = -27;
pub const ECDH_SS_HKDF_512: i32 = -28;
//Key Agreement with Key Wrap
pub const ECDH_ES_A128KW: i32 = -29;
pub const ECDH_ES_A192KW: i32 = -30;
pub const ECDH_ES_A256KW: i32 = -31;
pub const ECDH_SS_A128KW: i32 = -32;
pub const ECDH_SS_A192KW: i32 = -33;
pub const ECDH_SS_A256KW: i32 = -34;
pub(crate) const KEY_DISTRIBUTION_ALGS: [i32; 21] = [
    DIRECT,
    DIRECT_HKDF_SHA_256,
    DIRECT_HKDF_SHA_512,
    DIRECT_HKDF_AES_128,
    DIRECT_HKDF_AES_256,
    A128KW,
    A192KW,
    A256KW,
    RSA_OAEP_1,
    RSA_OAEP_256,
    RSA_OAEP_512,
    ECDH_ES_HKDF_256,
    ECDH_ES_HKDF_512,
    ECDH_SS_HKDF_256,
    ECDH_SS_HKDF_512,
    ECDH_ES_A128KW,
    ECDH_ES_A192KW,
    ECDH_ES_A256KW,
    ECDH_SS_A128KW,
    ECDH_SS_A192KW,
    ECDH_SS_A256KW,
];
pub(crate) const RSA_OAEP: [i32; 3] = [RSA_OAEP_1, RSA_OAEP_256, RSA_OAEP_512];
pub(crate) const A_KW: [i32; 3] = [A128KW, A192KW, A256KW];

pub(crate) const DIRECT_HKDF: [i32; 4] = [
    DIRECT_HKDF_SHA_256,
    DIRECT_HKDF_SHA_512,
    DIRECT_HKDF_AES_128,
    DIRECT_HKDF_AES_256,
];
pub(crate) const ECDH_H: [i32; 4] = [
    ECDH_ES_HKDF_256,
    ECDH_ES_HKDF_512,
    ECDH_SS_HKDF_256,
    ECDH_SS_HKDF_512,
];
pub(crate) const ECDH_A: [i32; 6] = [
    ECDH_ES_A128KW,
    ECDH_ES_A192KW,
    ECDH_ES_A256KW,
    ECDH_SS_A128KW,
    ECDH_SS_A192KW,
    ECDH_SS_A256KW,
];
const AES_BLOCK: usize = 16;
const GCM_TAG: usize = 16;

pub(crate) const ALG_NAMES: &[(&str, i32)] = &[
    ("ES256", ES256),
    ("ES384", ES384),
    ("ES512", ES512),
    ("EDDSA", EDDSA),
    ("PS256", PS256),
    ("PS384", PS384),
    ("PS512", PS512),
    ("ES256K", ES256K),
    ("A128GCM", A128GCM),
    ("A192GCM", A192GCM),
    ("A256GCM", A256GCM),
    ("ChaCha20/Poly1305", CHACHA20),
    ("AES-CCM-16-64-128", AES_CCM_16_64_128),
    ("AES-CCM-16-64-256", AES_CCM_16_64_256),
    ("AES-CCM-64-64-128", AES_CCM_64_64_128),
    ("AES-CCM-64-64-256", AES_CCM_64_64_256),
    ("AES-CCM-16-128-128", AES_CCM_16_128_128),
    ("AES-CCM-16-128-256", AES_CCM_16_128_256),
    ("AES-CCM-64-128-128", AES_CCM_64_128_128),
    ("AES-CCM-64-128-256", AES_CCM_64_128_256),
    ("HMAC 256/64", HMAC_256_64),
    ("HMAC 256/256", HMAC_256_256),
    ("HMAC 384/384", HMAC_384_384),
    ("HMAC 512/512", HMAC_512_512),
    ("AES-MAC 128/64", AES_MAC_128_64),
    ("AES-MAC 256/64", AES_MAC_256_64),
    ("AES-MAC 128/128", AES_MAC_128_128),
    ("AES-MAC 256/128", AES_MAC_256_128),
    ("direct", DIRECT),
    ("direct+HKDF-SHA-256", DIRECT_HKDF_SHA_256),
    ("direct+HKDF-SHA-512", DIRECT_HKDF_SHA_512),
    ("direct+HKDF-AES-128", DIRECT_HKDF_AES_128),
    ("direct+HKDF-AES-256", DIRECT_HKDF_AES_256),
    ("A128KW", A128KW),
    ("A192KW", A192KW),
    ("A256KW", A256KW),
    ("RSAES-OAEP w/ RFC 8017 default parameters", RSA_OAEP_1),
    ("RSAES-OAEP w/ SHA-256", RSA_OAEP_256),
    ("RSAES-OAEP w/ SHA-512", RSA_OAEP_512),
    ("ECDH-ES + HKDF-256", ECDH_ES_HKDF_256),
    ("ECDH-ES + HKDF-512", ECDH_ES_HKDF_512),
    ("ECDH-SS + HKDF-256", ECDH_SS_HKDF_256),
    ("ECDH-SS + HKDF-512", ECDH_SS_HKDF_512),
    ("ECDH-ES + A128KW", ECDH_ES_A128KW),
    ("ECDH-ES + A192KW", ECDH_ES_A192KW),
    ("ECDH-ES + A256KW", ECDH_ES_A256KW),
    ("ECDH-SS + A128KW", ECDH_SS_A128KW),
    ("ECDH-SS + A192KW", ECDH_SS_A192KW),
    ("ECDH-SS + A256KW", ECDH_SS_A256KW),
    ("SHA-256", SHA_256),
];

pub(crate) fn is_ecdh(alg: i32) -> bool {
    ECDH_H.contains(&alg) || ECDH_A.contains(&alg)
}

fn ec_group(crv: i32) -> CoseResultWithRet<EcGroup> {
    let nid = match crv {
        keys::P_256 => Nid::X9_62_PRIME256V1,
        keys::P_384 => Nid::SECP384R1,
        keys::P_521 => Nid::SECP521R1,
        keys::SECP256K1 => Nid::SECP256K1,
        _ => return Err(CoseError::Invalid(CoseField::Crv)),
    };
    Ok(EcGroup::from_curve_name(nid)?)
}

fn okp_id(crv: i32) -> CoseResultWithRet<Id> {
    Ok(match crv {
        keys::ED25519 => Id::ED25519,
        keys::ED448 => Id::ED448,
        keys::X25519 => Id::X25519,
        keys::X448 => Id::X448,
        _ => return Err(CoseError::Invalid(CoseField::Crv)),
    })
}

fn digests(alg: i32) -> CoseResultWithRet<(MessageDigest, &'static MdRef)> {
    Ok(match alg {
        ES256 | ES256K | PS256 => (MessageDigest::sha256(), Md::sha256()),
        ES384 | PS384 => (MessageDigest::sha384(), Md::sha384()),
        ES512 | PS512 => (MessageDigest::sha512(), Md::sha512()),
        _ => return Err(CoseError::Invalid(CoseField::Alg)),
    })
}

pub(crate) fn sign(
    alg: i32,
    crv: Option<i32>,
    key: &Vec<u8>,
    content: &Vec<u8>,
) -> CoseResultWithRet<Vec<u8>> {
    if alg == EDDSA {
        let key = PKey::private_key_from_raw_bytes(
            key,
            okp_id(crv.ok_or(CoseError::Missing(CoseField::Crv))?)?,
        )?;
        return Ok(Signer::new_without_digest(&key)?.sign_oneshot_to_vec(content)?);
    }

    let (message_digest, md) = digests(alg)?;
    if matches!(alg, PS256 | PS384 | PS512) {
        let key = PKey::from_rsa(Rsa::private_key_from_der(key)?)?;
        let mut signer = Signer::new(message_digest, &key)?;
        signer.set_rsa_padding(Padding::PKCS1_PSS)?;
        signer.set_rsa_pss_saltlen(RsaPssSaltlen::DIGEST_LENGTH)?;
        signer.update(&content)?;
        return Ok(signer.sign_to_vec()?);
    }
    let group = ec_group(if alg == ES256K {
        keys::SECP256K1
    } else {
        crv.ok_or(CoseError::Missing(CoseField::Crv))?
    })?;

    let number = BigNum::from_slice(key.as_slice())?;
    let point = EcPoint::new(&group)?;
    let ec_key = EcKey::from_private_components(&group, &number, &point)?;
    let final_key = PKey::from_ec_key(ec_key)?;

    let hashed_input = hash(message_digest, content.as_slice())?;
    let mut ctx = PkeyCtx::new(&final_key)?;
    ctx.sign_init()?;
    ctx.set_signature_md(md)?;
    ctx.set_nonce_type(NonceType::DETERMINISTIC_K)?;
    let mut der = vec![];
    ctx.sign_to_vec(&hashed_input, &mut der)?;

    let sig = EcdsaSig::from_der(&der)?;
    // P-521 -> 66 bytes
    let size = (group.degree() as i32 + 7) / 8;
    Ok([sig.r().to_vec_padded(size)?, sig.s().to_vec_padded(size)?].concat())
}

pub(crate) fn verify(
    alg: i32,
    crv: Option<i32>,
    key: &Vec<u8>,
    content: &Vec<u8>,
    signature: &Vec<u8>,
) -> CoseResultWithRet<bool> {
    if alg == EDDSA {
        let key = PKey::public_key_from_raw_bytes(
            key,
            okp_id(crv.ok_or(CoseError::Missing(CoseField::Crv))?)?,
        )?;
        return Ok(Verifier::new_without_digest(&key)?.verify_oneshot(signature, content)?);
    }

    let (message_digest, _) = digests(alg)?;
    if matches!(alg, PS256 | PS384 | PS512) {
        let key = PKey::from_rsa(Rsa::public_key_from_der(key)?)?;
        let mut verifier = Verifier::new(message_digest, &key)?;
        verifier.set_rsa_padding(Padding::PKCS1_PSS)?;
        verifier.set_rsa_pss_saltlen(RsaPssSaltlen::DIGEST_LENGTH)?;
        verifier.update(&content)?;
        return Ok(verifier.verify(&signature)?);
    }
    let group = ec_group(if alg == ES256K {
        keys::SECP256K1
    } else {
        crv.ok_or(CoseError::Missing(CoseField::Crv))?
    })?;
    let mut ctx = BigNumContext::new()?;
    let point = EcPoint::from_bytes(&group, key, &mut ctx)?;
    let final_key = PKey::from_ec_key(EcKey::from_public_key(&group, &point)?)?;

    // P-521 -> 66 bytes
    let size = (group.degree() as usize + 7) / 8;
    if signature.len() != 2 * size {
        return Ok(false);
    }
    let (r, s) = signature.split_at(size);
    let der = EcdsaSig::from_private_components(BigNum::from_slice(r)?, BigNum::from_slice(s)?)?
        .to_der()?;

    let mut verifier = Verifier::new(message_digest, &final_key)?;
    verifier.update(&content)?;
    Ok(verifier.verify(&der)?)
}

fn verify_mac_key(alg: i32, l: usize) -> CoseResult {
    let size = match alg {
        AES_MAC_128_64 => 16,
        AES_MAC_256_64 => 32,
        AES_MAC_128_128 => 16,
        AES_MAC_256_128 => 32,
        _ => 0,
    };

    if size != 0 && l != size {
        Err(CoseError::Invalid(CoseField::K))
    } else {
        Ok(())
    }
}

fn cbc_mac(cipher: Cipher, key: &[u8], data: &[u8]) -> CoseResultWithRet<Vec<u8>> {
    let blocks = data.len().div_ceil(AES_BLOCK).max(1);
    let mut padded = data.to_vec();
    padded.resize(blocks * AES_BLOCK, 0);
    let encrypted = encr(cipher, key, Some(&[0; AES_BLOCK]), &padded)?;
    let last = padded.len() - AES_BLOCK;
    Ok(encrypted[last..last + AES_BLOCK].to_vec())
}

pub(crate) fn mac(alg: i32, key: &Vec<u8>, content: &Vec<u8>) -> CoseResultWithRet<Vec<u8>> {
    verify_mac_key(alg, key.len())?;
    match alg {
        AES_MAC_128_64 | AES_MAC_256_64 | AES_MAC_128_128 | AES_MAC_256_128 => {
            let (cipher, size) = match alg {
                AES_MAC_128_64 => (Cipher::aes_128_cbc(), 8),
                AES_MAC_256_64 => (Cipher::aes_256_cbc(), 8),
                AES_MAC_128_128 => (Cipher::aes_128_cbc(), 16),
                _ => (Cipher::aes_256_cbc(), 16),
            };
            if key.len() != cipher.key_len() {
                return Err(CoseError::Invalid(CoseField::K));
            }

            let mut tag = cbc_mac(cipher, key, content)?;
            tag.truncate(size);
            Ok(tag)
        }
        HMAC_256_64 | HMAC_256_256 | HMAC_384_384 | HMAC_512_512 => {
            let (message_digest, size) = match alg {
                HMAC_256_64 => (MessageDigest::sha256(), 8),
                HMAC_256_256 => (MessageDigest::sha256(), 32),
                HMAC_384_384 => (MessageDigest::sha384(), 48),
                _ => (MessageDigest::sha512(), 64),
            };
            let hmac_key = PKey::hmac(key)?;
            let mut signer = Signer::new(message_digest, &hmac_key)?;
            signer.update(content)?;

            let mut tag = signer.sign_to_vec()?;
            tag.truncate(size);
            Ok(tag)
        }
        _ => Err(CoseError::Invalid(CoseField::Alg)),
    }
}

pub(crate) fn mac_verify(
    alg: i32,
    key: &Vec<u8>,
    content: &Vec<u8>,
    tag: &[u8],
) -> CoseResultWithRet<bool> {
    let expected = mac(alg, key, content)?;
    Ok(expected.len() == tag.len() && openssl::memcmp::eq(&expected, tag))
}

fn ccm_params(alg: i32) -> Option<(&'static CipherRef, usize)> {
    Some(match alg {
        AES_CCM_16_64_128 | AES_CCM_64_64_128 => (cipher::Cipher::aes_128_ccm(), 8),
        AES_CCM_16_64_256 | AES_CCM_64_64_256 => (cipher::Cipher::aes_256_ccm(), 8),
        AES_CCM_16_128_128 | AES_CCM_64_128_128 => (cipher::Cipher::aes_128_ccm(), 16),
        AES_CCM_16_128_256 | AES_CCM_64_128_256 => (cipher::Cipher::aes_256_ccm(), 16),
        _ => return None,
    })
}

fn gcm_cipher(alg: i32) -> Option<Cipher> {
    Some(match alg {
        A128GCM => Cipher::aes_128_gcm(),
        A192GCM => Cipher::aes_192_gcm(),
        A256GCM => Cipher::aes_256_gcm(),
        CHACHA20 => Cipher::chacha20_poly1305(),
        _ => return None,
    })
}

fn split_tag(ciphertext: &[u8], tag_len: usize) -> CoseResultWithRet<(&[u8], &[u8])> {
    let offset = ciphertext
        .len()
        .checked_sub(tag_len)
        .ok_or(CoseError::Invalid(CoseField::Ciphertext))?;
    Ok(ciphertext.split_at(offset))
}
pub(crate) fn encrypt(
    alg: i32,
    key: &Vec<u8>,
    iv: &Vec<u8>,
    payload: &Vec<u8>,
    aad: &[u8],
) -> CoseResultWithRet<Vec<u8>> {
    if iv.len() != get_iv_size(alg)? {
        return Err(CoseError::Invalid(CoseField::Iv));
    }
    if let Some((cipher, tag_len)) = ccm_params(alg) {
        let mut ctx = CipherCtx::new()?;
        ctx.encrypt_init(Some(cipher), None, None)?;

        ctx.set_tag_length(tag_len)?;
        ctx.set_iv_length(iv.len())?;
        ctx.encrypt_init(None, Some(key), Some(iv))?;
        ctx.set_data_len(payload.len())?;

        ctx.cipher_update(aad, None)?;
        let mut out = vec![];
        ctx.cipher_update_vec(payload, &mut out)?;
        ctx.cipher_final_vec(&mut out)?;

        let mut tag = vec![0u8; tag_len];
        ctx.tag(&mut tag)?;
        out.extend_from_slice(&tag);
        return Ok(out);
    }
    let cipher = gcm_cipher(alg).ok_or(CoseError::Invalid(CoseField::Alg))?;
    let mut tag = [0u8; GCM_TAG];
    let mut out = encrypt_aead(cipher, key, Some(iv), aad, payload, &mut tag)?;
    out.extend_from_slice(&tag);

    Ok(out)
}

pub(crate) fn decrypt(
    alg: i32,
    key: &Vec<u8>,
    iv: &Vec<u8>,
    ciphertext: &Vec<u8>,
    aad: &[u8],
) -> CoseResultWithRet<Vec<u8>> {
    if iv.len() != get_iv_size(alg)? {
        return Err(CoseError::Invalid(CoseField::Iv));
    }
    if let Some((cipher, tag_len)) = ccm_params(alg) {
        let (data, tag) = split_tag(ciphertext, tag_len)?;
        let mut ctx = CipherCtx::new()?;
        ctx.decrypt_init(Some(cipher), None, None)?;

        ctx.set_tag_length(tag_len)?;
        ctx.set_key_length(key.len())?;
        ctx.set_iv_length(iv.len())?;
        ctx.decrypt_init(None, Some(key), Some(iv))?;
        ctx.set_tag(tag)?;
        ctx.set_data_len(data.len())?;

        ctx.cipher_update(aad, None)?;
        let mut out = vec![0u8; data.len() + cipher.block_size()];
        let count = ctx.cipher_update(data, Some(&mut out))?;
        out.truncate(count);
        return Ok(out);
    }
    let cipher = gcm_cipher(alg).ok_or(CoseError::Invalid(CoseField::Alg))?;
    let (data, tag) = split_tag(ciphertext, GCM_TAG)?;
    Ok(decrypt_aead(cipher, key, Some(iv), aad, data, tag)?)
}

pub(crate) fn aes_key_wrap(
    key: &Vec<u8>,
    size: usize,
    cek: &Vec<u8>,
) -> CoseResultWithRet<Vec<u8>> {
    let aes_key = AesKey::new_encrypt(&key).map_err(|_| CoseError::KeyWrap)?;
    let mut wrapped = vec![0u8; (size + 8).into()];
    wrap_key(&aes_key, None, &mut wrapped, cek).map_err(|_| CoseError::KeyWrap)?;
    Ok(wrapped)
}

pub(crate) fn aes_key_unwrap(
    key: &Vec<u8>,
    size: usize,
    wrapped: &Vec<u8>,
) -> CoseResultWithRet<Vec<u8>> {
    if wrapped.len() != size + 8 {
        return Err(CoseError::KeyWrap);
    }
    let aes_key = AesKey::new_decrypt(&key).map_err(|_| CoseError::KeyWrap)?;
    let mut cek = vec![0u8; size];
    unwrap_key(&aes_key, None, &mut cek, wrapped).map_err(|_| CoseError::KeyWrap)?;
    Ok(cek)
}

fn oaep_md(alg: i32) -> CoseResultWithRet<&'static MdRef> {
    Ok(match alg {
        RSA_OAEP_1 => Md::sha1(),
        RSA_OAEP_256 => Md::sha256(),
        RSA_OAEP_512 => Md::sha512(),
        _ => return Err(CoseError::Invalid(CoseField::Alg)),
    })
}

pub(crate) fn rsa_oaep_enc(key: &Vec<u8>, cek: &Vec<u8>, alg: i32) -> CoseResultWithRet<Vec<u8>> {
    let rsa_key = PKey::public_key_from_der(key)?;
    let mut enc = PkeyCtx::new(&rsa_key)?;
    enc.encrypt_init()?;
    enc.set_rsa_padding(Padding::PKCS1_OAEP)?;
    enc.set_rsa_oaep_md(oaep_md(alg)?)?;
    let mut out: Vec<u8> = Vec::new();
    enc.encrypt_to_vec(cek, &mut out)?;
    Ok(out.to_vec())
}

pub(crate) fn rsa_oaep_dec(
    key: &Vec<u8>,
    size: usize,
    cek: &Vec<u8>,
    alg: i32,
) -> CoseResultWithRet<Vec<u8>> {
    let rsa_key = PKey::private_key_from_der(key)?;
    let mut enc = PkeyCtx::new(&rsa_key)?;
    enc.decrypt_init()?;
    enc.set_rsa_padding(Padding::PKCS1_OAEP)?;
    enc.set_rsa_oaep_md(oaep_md(alg)?)?;
    let mut out = Vec::new();
    enc.decrypt_to_vec(cek, &mut out)?;
    if out.len() != size {
        return Err(CoseError::Invalid(CoseField::Ciphertext));
    }
    Ok(out)
}

pub(crate) fn thumbprint(cert: &[u8], alg: &i32) -> CoseResultWithRet<Vec<u8>> {
    if *alg == SHA_256 {
        let digest = hash(MessageDigest::sha256(), cert)?;
        Ok(digest.to_vec())
    } else {
        Err(CoseError::Invalid(CoseField::Alg))
    }
}

pub(crate) fn verify_thumbprint(cert: &[u8], expected: &[u8], alg: &i32) -> CoseResult {
    if thumbprint(cert, alg)? != expected {
        return Err(CoseError::Invalid(CoseField::X5T));
    }
    Ok(())
}

pub(crate) fn verify_chain(chain: &[Vec<u8>]) -> CoseResult {
    let stack = Stack::new()?;
    for i in (1..chain.len()).rev() {
        let cert = X509::from_der(&chain[i])?;
        let to_ver = X509::from_der(&chain[i - 1])?;
        let mut store_bldr = X509StoreBuilder::new()?;
        store_bldr.add_cert(cert)?;
        let store = store_bldr.build();
        let mut context = X509StoreContext::new()?;

        if !context.init(&store, &to_ver, &stack, |c| c.verify_cert())? {
            return Err(CoseError::Invalid(CoseField::KeyChain));
        }
    }
    Ok(())
}

pub(crate) fn ecdh_derive_key(
    crv_rec: Option<i32>,
    crv_send: Option<i32>,
    receiver_key: &Vec<u8>,
    sender_key: &Vec<u8>,
) -> CoseResultWithRet<Vec<u8>> {
    let mut ctx = BigNumContext::new()?;
    let public = match crv_rec {
        None => X509::from_der(receiver_key)?.public_key()?,
        Some(crv) if matches!(crv, keys::X25519 | keys::X448) => {
            PKey::public_key_from_raw_bytes(receiver_key, okp_id(crv)?)?
        }
        Some(crv) => {
            let group = ec_group(crv)?;
            let point = EcPoint::from_bytes(&group, receiver_key, &mut ctx)?;
            PKey::from_ec_key(EcKey::from_public_key(&group, &point)?)?
        }
    };
    let private = match crv_send {
        None => PKey::private_key_from_der(sender_key)?,
        Some(crv) if matches!(crv, keys::X25519 | keys::X448) => {
            PKey::private_key_from_raw_bytes(sender_key, okp_id(crv)?)?
        }
        Some(crv) => {
            let group = ec_group(crv)?;
            let scalar = BigNum::from_slice(sender_key)?;
            let point = EcPoint::new(&group)?;
            PKey::from_ec_key(EcKey::from_private_components(&group, &scalar, &point)?)?
        }
    };
    let mut deriver = Deriver::new(&private)?;
    deriver.set_peer(&public)?;
    Ok(deriver.derive_to_vec()?)
}

pub(crate) fn hkdf(
    length: usize,
    ikm: &Vec<u8>,
    salt: Option<&Vec<u8>>,
    info: &[u8],
    alg: i32,
) -> CoseResultWithRet<Vec<u8>> {
    if matches!(alg, DIRECT_HKDF_AES_128 | DIRECT_HKDF_AES_256) {
        let cipher = if alg == DIRECT_HKDF_AES_128 {
            Cipher::aes_128_cbc()
        } else {
            Cipher::aes_256_cbc()
        };
        let mut t = Vec::new();
        let mut okm = Vec::new();
        let mut i = 0;
        while okm.len() < length {
            i += 1;
            t = cbc_mac(cipher, ikm, &[&t[..], info, &[i]].concat())?;
            okm.extend_from_slice(&t);
        }
        okm.truncate(length);
        return Ok(okm);
    }
    let digest = if matches!(
        alg,
        DIRECT_HKDF_SHA_512 | ECDH_ES_HKDF_512 | ECDH_SS_HKDF_512
    ) {
        Md::sha512()
    } else {
        Md::sha256()
    };

    let mut ctx = PkeyCtx::new_id(Id::HKDF)?;
    ctx.derive_init()?;
    ctx.set_hkdf_md(digest)?;
    ctx.set_hkdf_key(ikm)?;
    if let Some(salt) = salt {
        ctx.set_hkdf_salt(salt)?;
    }
    ctx.add_hkdf_info(info)?;
    let mut out = vec![0; length];
    ctx.derive(Some(&mut out))?;
    Ok(out)
}

pub(crate) fn get_cek_size(alg: i32) -> CoseResultWithRet<usize> {
    Ok(match alg {
        A128GCM | AES_CCM_16_64_128 | AES_CCM_64_64_128 | AES_CCM_16_128_128
        | AES_CCM_64_128_128 | AES_MAC_128_64 | AES_MAC_128_128 | A128KW | ECDH_ES_A128KW
        | ECDH_SS_A128KW => 16,
        A192GCM | A192KW | ECDH_ES_A192KW | ECDH_SS_A192KW => 24,
        A256GCM | CHACHA20 | AES_CCM_16_64_256 | AES_CCM_64_64_256 | AES_CCM_16_128_256
        | AES_CCM_64_128_256 | AES_MAC_256_128 | AES_MAC_256_64 | HMAC_256_64 | HMAC_256_256
        | A256KW | ECDH_ES_A256KW | ECDH_SS_A256KW => 32,
        HMAC_384_384 => 48,

        HMAC_512_512 => 64,
        _ => return Err(CoseError::Invalid(CoseField::Alg)),
    })
}
pub(crate) fn gen_random_key(alg: i32) -> CoseResultWithRet<Vec<u8>> {
    let mut key = vec![0u8; get_cek_size(alg)?];
    rand_bytes(&mut key)?;
    Ok(key)
}

pub(crate) fn get_iv_size(alg: i32) -> CoseResultWithRet<usize> {
    match alg {
        A128GCM | A192GCM | A256GCM | CHACHA20 => Ok(12),
        AES_CCM_16_64_128 | AES_CCM_16_64_256 | AES_CCM_16_128_128 | AES_CCM_16_128_256 => Ok(13),
        AES_CCM_64_64_128 | AES_CCM_64_64_256 | AES_CCM_64_128_128 | AES_CCM_64_128_256 => Ok(7),
        _ => Err(CoseError::Invalid(CoseField::Alg)),
    }
}

pub(crate) fn gen_iv(
    partial_iv: &Vec<u8>,
    base_iv: &Vec<u8>,
    alg: &i32,
) -> CoseResultWithRet<Vec<u8>> {
    let size = get_iv_size(*alg)?;
    let padding = size
        .checked_sub(partial_iv.len())
        .ok_or(CoseError::Invalid(CoseField::PartialIv))?;
    let mut iv = vec![0; padding];
    iv.extend_from_slice(partial_iv);
    for (byte, base) in iv.iter_mut().zip(base_iv) {
        *byte ^= base;
    }
    Ok(iv)
}

// Test if malformed messages return error or false instead of panic
#[cfg(test)]
mod tests {
    use super::*;

    const P256_PUB: &str = "04bac5b11cad8f99f9c72b05cf4b9e26d244dc189f745228255a219a86d6a09eff20138bf82dc1b6d562be0fa54ab7804a3a64b6d72ccfed6b6fb6ed28bbfc117e";

    #[test]
    fn short_ecdsa_signature() {
        let key = hex::decode(P256_PUB).unwrap();
        let result = verify(
            ES256,
            Some(keys::P_256),
            &key,
            &b"content".to_vec(),
            &vec![0; 10],
        );
        assert!(matches!(result, Ok(false)));
    }

    #[test]
    fn ciphertext_shorter_than_tag() {
        for (alg, key, iv) in [(A128GCM, 16, 12), (AES_CCM_16_64_128, 16, 13)] {
            assert!(matches!(
                decrypt(alg, &vec![0; key], &vec![0; iv], &vec![0; 5], &vec![]),
                Err(CoseError::Invalid(CoseField::Ciphertext))
            ));
        }
    }

    #[test]
    fn short_wrapped_key() {
        assert!(matches!(
            aes_key_unwrap(&vec![0; 16], 16, &vec![0; 7]),
            Err(CoseError::KeyWrap)
        ));
    }

    #[test]
    fn partial_iv_longer_than_iv() {
        assert!(matches!(
            gen_iv(&vec![0; 20], &vec![0; 12], &A128GCM),
            Err(CoseError::Invalid(CoseField::PartialIv))
        ));
    }

    #[test]
    fn wrong_iv_length() {
        assert!(matches!(
            decrypt(A256GCM, &vec![0; 32], &vec![0; 13], &vec![0; 32], &vec![]),
            Err(CoseError::Invalid(CoseField::Iv))
        ));
    }
}
