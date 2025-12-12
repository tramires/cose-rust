//! A collection of COSE algorithm identifiers.
use crate::errors::{CoseError, CoseField, CoseResult, CoseResultWithRet};
use crate::keys;
use openssl::aes::{unwrap_key, wrap_key, AesKey};
use openssl::bn::{BigNum, BigNumContext};
use openssl::cipher;
use openssl::cipher_ctx::CipherCtx;
use openssl::derive::Deriver;
use openssl::ec::{EcGroup, EcKey, EcPoint};
use openssl::ecdsa::EcdsaSig;
use openssl::hash::{hash, MessageDigest};
use openssl::md::Md;
use openssl::nid::Nid;
use openssl::pkey::{Id, PKey, Private, Public};
use openssl::pkey_ctx::{NonceType, PkeyCtx};
use openssl::rsa::{Padding, Rsa};
use openssl::sign::{RsaPssSaltlen, Signer, Verifier};
use openssl::stack::Stack;
use openssl::symm::{decrypt_aead, encrypt as encr, encrypt_aead, Cipher};
use openssl::x509::{store::X509StoreBuilder, X509StoreContext, X509};
use rand::Rng;

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
pub(crate) const SIGNING_ALGS_NAMES: [&str; 8] = [
    "ES256", "ES384", "ES512", "EDDSA", "PS256", "PS384", "PS512", "ES256K",
];

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
pub(crate) const ENCRYPT_ALGS_NAMES: [&str; 12] = [
    "A128GCM",
    "A192GCM",
    "A256GCM",
    "ChaCha20/Poly1305",
    "AES-CCM-16-64-128",
    "AES-CCM-16-64-256",
    "AES-CCM-64-64-128",
    "AES-CCM-64-64-256",
    "AES-CCM-16-128-128",
    "AES-CCM-16-128-256",
    "AES-CCM-64-128-128",
    "AES-CCM-64-128-256",
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
pub(crate) const MAC_ALGS_NAMES: [&str; 8] = [
    "HMAC 256/64",
    "HMAC 256/256",
    "HMAC 384/384",
    "HMAC 512/512",
    "AES-MAC 128/64",
    "AES-MAC 256/64",
    "AES-MAC 128/128",
    "AES-MAC 256/128",
];
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

// HASH Algorithms
pub const SHA_256: i32 = -16;
pub const HASH_ALGS: [i32; 1] = [SHA_256];
pub const HASH_ALGS_NAMES: [&str; 1] = ["SHA-256"];

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

pub(crate) const KEY_DISTRIBUTION_NAMES: [&str; 21] = [
    "direct",
    "direct+HKDF-SHA-256",
    "direct+HKDF-SHA-512",
    "direct+HKDF-AES-128",
    "direct+HKDF-AES-256",
    "A128KW",
    "A192KW",
    "A256KW",
    "RSAES-OAEP w/ RFC 8017 default parameters",
    "RSAES-OAEP w/ SHA-256",
    "RSAES-OAEP w/ SHA-512",
    "ECDH-ES + HKDF-256",
    "ECDH-ES + HKDF-512",
    "ECDH-SS + HKDF-256",
    "ECDH-SS + HKDF-512",
    "ECDH-ES + A128KW",
    "ECDH-ES + A192KW",
    "ECDH-ES + A256KW",
    "ECDH-SS + A128KW",
    "ECDH-SS + A192KW",
    "ECDH-SS + A256KW",
];
pub(crate) const ECDH_ALGS: [i32; 10] = [
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
pub(crate) const OAEP_ALGS: [i32; 3] = [RSA_OAEP_1, RSA_OAEP_256, RSA_OAEP_512];
const K16_ALGS: [i32; 11] = [
    A128GCM,
    CHACHA20,
    AES_CCM_16_64_128,
    AES_CCM_64_64_128,
    AES_CCM_16_128_128,
    AES_CCM_64_128_128,
    AES_MAC_128_64,
    AES_MAC_128_128,
    ECDH_ES_A128KW,
    ECDH_SS_A128KW,
    A128KW,
];
const K24_ALGS: [i32; 4] = [A192KW, ECDH_ES_A192KW, ECDH_SS_A192KW, A192GCM];
const K32_ALGS: [i32; 12] = [
    A256GCM,
    AES_CCM_16_64_256,
    AES_CCM_64_64_256,
    AES_CCM_16_128_256,
    AES_CCM_64_128_256,
    AES_MAC_256_128,
    AES_MAC_256_64,
    HMAC_256_64,
    HMAC_256_256,
    ECDH_ES_A256KW,
    ECDH_SS_A256KW,
    A256KW,
];

pub(crate) const RSA_OAEP: [i32; 3] = [RSA_OAEP_1, RSA_OAEP_256, RSA_OAEP_512];
pub(crate) const A_KW: [i32; 3] = [A128KW, A192KW, A256KW];
pub(crate) const D_HA: [i32; 2] = [DIRECT_HKDF_AES_128, DIRECT_HKDF_AES_256];
pub(crate) const D_HS: [i32; 2] = [DIRECT_HKDF_SHA_256, DIRECT_HKDF_SHA_512];
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

const DER_S2: [u8; 16] = [48, 46, 2, 1, 0, 48, 5, 6, 3, 43, 101, 112, 4, 34, 4, 32];
const DER_S4: [u8; 16] = [48, 71, 2, 1, 0, 48, 5, 6, 3, 43, 101, 113, 4, 59, 4, 57];
const DER_P2: [u8; 12] = [48, 42, 48, 5, 6, 3, 43, 101, 112, 3, 33, 0];
const DER_P4: [u8; 12] = [48, 67, 48, 5, 6, 3, 43, 101, 113, 3, 58, 0];

/// Function to sign content with a given key and algorithm.
pub fn sign(
    alg: i32,
    crv: Option<i32>,
    key: &Vec<u8>,
    content: &Vec<u8>,
) -> CoseResultWithRet<Vec<u8>> {
    let number = BigNum::from_slice(key.as_slice())?;
    let group;
    let message_digest;
    let md;
    match alg {
        ES256 | ES384 | ES512 => {
            if alg == ES256 {
                message_digest = MessageDigest::sha256();
                md = Md::sha256();
            } else if alg == ES384 {
                message_digest = MessageDigest::sha384();
                md = Md::sha384();
            } else {
                message_digest = MessageDigest::sha512();
                md = Md::sha512();
            }
            let crv = crv.ok_or(CoseError::Invalid(CoseField::Crv))?;
            if crv == keys::P_256 {
                group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
            } else if crv == keys::P_384 {
                group = EcGroup::from_curve_name(Nid::SECP384R1)?;
            } else if crv == keys::P_521 {
                group = EcGroup::from_curve_name(Nid::SECP521R1)?;
            } else {
                return Err(CoseError::Invalid(CoseField::Crv));
            }
        }
        ES256K => {
            group = EcGroup::from_curve_name(Nid::SECP256K1)?;
            message_digest = MessageDigest::sha256();
            md = Md::sha256();
        }
        EDDSA => {
            let mut ed_key;
            let crv = crv.ok_or(CoseError::Invalid(CoseField::Crv))?;
            if crv == keys::ED25519 {
                ed_key = DER_S2.to_vec();
                ed_key.append(&mut key.clone());
            } else if crv == keys::ED448 {
                ed_key = DER_S4.to_vec();
                ed_key.append(&mut key.clone());
            } else {
                return Err(CoseError::Invalid(CoseField::Crv));
            }
            let key = PKey::private_key_from_der(ed_key.as_slice())?;
            let mut signer = Signer::new(MessageDigest::null(), &key)?;
            let size = signer.len()?;
            let mut s = vec![0; size];
            signer.sign_oneshot(&mut s, content.as_slice())?;
            return Ok(s);
        }
        PS256 => {
            let rsa_key = Rsa::private_key_from_der(key)?;
            let key = PKey::from_rsa(rsa_key)?;
            let mut signer = Signer::new(MessageDigest::sha256(), &key)?;
            signer.set_rsa_padding(Padding::PKCS1_PSS)?;
            signer.set_rsa_pss_saltlen(RsaPssSaltlen::DIGEST_LENGTH)?;
            signer.update(&content)?;
            return Ok(signer.sign_to_vec()?);
        }
        PS384 => {
            let rsa_key = Rsa::private_key_from_der(key)?;
            let key = PKey::from_rsa(rsa_key)?;
            let mut signer = Signer::new(MessageDigest::sha384(), &key)?;
            signer.set_rsa_padding(Padding::PKCS1_PSS)?;
            signer.set_rsa_pss_saltlen(RsaPssSaltlen::DIGEST_LENGTH)?;
            signer.update(&content)?;
            return Ok(signer.sign_to_vec()?);
        }
        PS512 => {
            let rsa_key = Rsa::private_key_from_der(key)?;
            let key = PKey::from_rsa(rsa_key)?;
            let mut signer = Signer::new(MessageDigest::sha512(), &key)?;
            signer.set_rsa_padding(Padding::PKCS1_PSS)?;
            signer.set_rsa_pss_saltlen(RsaPssSaltlen::DIGEST_LENGTH)?;
            signer.update(&content)?;
            return Ok(signer.sign_to_vec()?);
        }
        _ => {
            return Err(CoseError::Invalid(CoseField::Alg));
        }
    }

    let size: i32 = key.len() as i32;
    let ec_key = EcKey::from_private_components(&group, &number, &EcPoint::new(&group).unwrap())?;
    let final_key = PKey::from_ec_key(ec_key)?;

    let hashed_input = hash(message_digest, content.as_slice())?;
    let mut ctx = PkeyCtx::new(&final_key)?;
    ctx.sign_init()?;
    ctx.set_signature_md(md)?;
    ctx.set_nonce_type(NonceType::DETERMINISTIC_K)?;

    let mut output = vec![];
    ctx.sign_to_vec(&hashed_input, &mut output)?;
    let priv_comp = EcdsaSig::from_der(&output)?;
    let mut s = priv_comp.r().to_vec_padded(size)?;
    s.append(&mut priv_comp.s().to_vec_padded(size)?);
    Ok(s)
}

/// Function to verify a signature with a given key, algorithm and content that was signed.
pub fn verify(
    alg: i32,
    crv: Option<i32>,
    key: &Vec<u8>,
    content: &Vec<u8>,
    signature: &Vec<u8>,
) -> CoseResultWithRet<bool> {
    let group;
    let message_digest;
    let mut ctx = BigNumContext::new()?;
    let size: usize;
    if key[0] == 3 {
        size = key.len() - 1;
    } else {
        size = (key.len() - 1) / 2;
    }
    match alg {
        ES256 | ES384 | ES512 => {
            if alg == ES256 {
                message_digest = MessageDigest::sha256();
            } else if alg == ES384 {
                message_digest = MessageDigest::sha384();
            } else {
                message_digest = MessageDigest::sha512();
            }
            let crv = crv.ok_or(CoseError::Invalid(CoseField::Crv))?;
            if crv == keys::P_256 {
                group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
            } else if crv == keys::P_384 {
                group = EcGroup::from_curve_name(Nid::SECP384R1)?;
            } else if crv == keys::P_521 {
                group = EcGroup::from_curve_name(Nid::SECP521R1)?;
            } else {
                return Err(CoseError::Invalid(CoseField::Crv));
            }
        }
        ES256K => {
            group = EcGroup::from_curve_name(Nid::SECP256K1)?;
            message_digest = MessageDigest::sha256();
        }
        EDDSA => {
            let mut ed_key;
            let crv = crv.ok_or(CoseError::Invalid(CoseField::Crv))?;
            if crv == keys::ED25519 {
                ed_key = DER_P2.to_vec();
                ed_key.append(&mut key.clone());
            } else if crv == keys::ED448 {
                ed_key = DER_P4.to_vec();
                ed_key.append(&mut key.clone());
            } else {
                return Err(CoseError::Invalid(CoseField::Crv));
            }
            let ec_public_key = PKey::public_key_from_der(ed_key.as_slice())?;
            let mut verifier = Verifier::new(MessageDigest::null(), &ec_public_key)?;
            return Ok(verifier.verify_oneshot(&signature, &content)?);
        }
        PS256 => {
            let rsa_key = Rsa::public_key_from_der(key)?;
            let key = PKey::from_rsa(rsa_key)?;
            let mut verifier = Verifier::new(MessageDigest::sha256(), &key)?;
            verifier.set_rsa_padding(Padding::PKCS1_PSS)?;
            verifier.set_rsa_pss_saltlen(RsaPssSaltlen::DIGEST_LENGTH)?;
            verifier.update(&content)?;
            return Ok(verifier.verify(&signature)?);
        }
        PS384 => {
            let rsa_key = Rsa::public_key_from_der(key)?;
            let key = PKey::from_rsa(rsa_key)?;
            let mut verifier = Verifier::new(MessageDigest::sha384(), &key)?;
            verifier.set_rsa_padding(Padding::PKCS1_PSS)?;
            verifier.set_rsa_pss_saltlen(RsaPssSaltlen::DIGEST_LENGTH)?;
            verifier.update(&content)?;
            return Ok(verifier.verify(&signature)?);
        }
        PS512 => {
            let rsa_key = Rsa::public_key_from_der(key)?;
            let key = PKey::from_rsa(rsa_key)?;
            let mut verifier = Verifier::new(MessageDigest::sha512(), &key)?;
            verifier.set_rsa_padding(Padding::PKCS1_PSS)?;
            verifier.set_rsa_pss_saltlen(RsaPssSaltlen::DIGEST_LENGTH)?;
            verifier.update(&content)?;
            return Ok(verifier.verify(&signature)?);
        }
        _ => {
            return Err(CoseError::Invalid(CoseField::Alg));
        }
    }
    let point = EcPoint::from_bytes(&group, &key, &mut ctx)?;
    let ec_key = EcKey::from_public_key(&group, &point)?;
    let final_key = PKey::from_ec_key(ec_key)?;
    let mut verifier = Verifier::new(message_digest, &final_key)?;
    verifier.update(&content)?;
    let s = EcdsaSig::from_private_components(
        BigNum::from_slice(&signature[..size])?,
        BigNum::from_slice(&signature[size..])?,
    )?;
    Ok(verifier.verify(&s.to_der()?)?)
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
        Err(CoseError::MissingKey())
    } else {
        Ok(())
    }
}

pub(crate) fn mac(alg: i32, key: &Vec<u8>, content: &Vec<u8>) -> CoseResultWithRet<Vec<u8>> {
    let size;
    verify_mac_key(alg, key.len())?;
    match alg {
        AES_MAC_128_64 | AES_MAC_256_64 | AES_MAC_128_128 | AES_MAC_256_128 => {
            let mut padded: Vec<u8> = content.to_vec();
            if padded.len() % 16 != 0 {
                padded.append(&mut vec![0; 16 - (padded.len() % 16)]);
            }
            let cipher;
            let index = padded.len() - 16;
            if alg == AES_MAC_128_64 {
                size = 8;
                cipher = Cipher::aes_128_cbc()
            } else if alg == AES_MAC_256_64 {
                size = 8;
                cipher = Cipher::aes_256_cbc()
            } else if alg == AES_MAC_128_128 {
                size = 16;
                cipher = Cipher::aes_128_cbc()
            } else {
                size = 16;
                cipher = Cipher::aes_256_cbc()
            }
            let s = encr(cipher, key, Some(&[0; 16]), &padded)?;
            Ok(s[index..index + size].to_vec())
        }
        HMAC_256_64 | HMAC_256_256 | HMAC_384_384 | HMAC_512_512 => {
            let k;
            let message_digest;

            if alg == HMAC_256_64 {
                k = PKey::hmac(key.as_slice())?;
                message_digest = MessageDigest::sha256();
                size = 8;
            } else if alg == HMAC_256_256 {
                k = PKey::hmac(key.as_slice())?;
                message_digest = MessageDigest::sha256();
                size = 32;
            } else if alg == HMAC_384_384 {
                k = PKey::hmac(key.as_slice())?;
                message_digest = MessageDigest::sha384();
                size = 48;
            } else {
                k = PKey::hmac(key.as_slice())?;
                message_digest = MessageDigest::sha512();
                size = 64;
            }
            let mut signer = Signer::new(message_digest, &k)?;
            signer.update(content.as_slice())?;
            let mut s = signer.sign_to_vec()?;
            s.truncate(size);
            Ok(s)
        }
        _ => Err(CoseError::Invalid(CoseField::Alg)),
    }
}

pub(crate) fn mac_verify(
    alg: i32,
    key: &Vec<u8>,
    content: &Vec<u8>,
    signature: &Vec<u8>,
) -> CoseResultWithRet<bool> {
    let size;
    verify_mac_key(alg, key.len())?;
    match alg {
        AES_MAC_128_64 | AES_MAC_256_64 | AES_MAC_128_128 | AES_MAC_256_128 => {
            let mut padded: Vec<u8> = content.to_vec();
            if padded.len() % 16 != 0 {
                padded.append(&mut vec![0; 16 - (padded.len() % 16)]);
            }
            let cipher;
            let index = padded.len() - 16;
            if alg == AES_MAC_128_64 {
                size = 8;
                cipher = Cipher::aes_128_cbc()
            } else if alg == AES_MAC_256_64 {
                size = 8;
                cipher = Cipher::aes_256_cbc()
            } else if alg == AES_MAC_128_128 {
                size = 16;
                cipher = Cipher::aes_128_cbc()
            } else {
                size = 16;
                cipher = Cipher::aes_256_cbc()
            }
            let s = encr(cipher, key, Some(&[0; 16]), &padded)?;
            Ok(s[index..index + size].to_vec() == *signature)
        }
        HMAC_256_64 | HMAC_256_256 | HMAC_384_384 | HMAC_512_512 => {
            let k;
            let message_digest;

            if alg == HMAC_256_64 {
                k = PKey::hmac(key.as_slice())?;
                message_digest = MessageDigest::sha256();
                size = 8;
            } else if alg == HMAC_256_256 {
                k = PKey::hmac(key.as_slice())?;
                message_digest = MessageDigest::sha256();
                size = 32;
            } else if alg == HMAC_384_384 {
                k = PKey::hmac(key.as_slice())?;
                message_digest = MessageDigest::sha384();
                size = 48;
            } else {
                k = PKey::hmac(key.as_slice())?;
                message_digest = MessageDigest::sha512();
                size = 64;
            }
            let mut verifier = Signer::new(message_digest, &k)?;
            verifier.update(content.as_slice())?;
            let s = verifier.sign_to_vec()?;
            Ok(s[..size].to_vec() == *signature)
        }
        _ => Err(CoseError::Invalid(CoseField::Alg)),
    }
}
pub(crate) fn encrypt(
    alg: i32,
    key: &Vec<u8>,
    iv: &Vec<u8>,
    payload: &Vec<u8>,
    aead: &Vec<u8>,
) -> CoseResultWithRet<Vec<u8>> {
    match alg {
        AES_CCM_16_64_128 | AES_CCM_16_64_256 | AES_CCM_64_64_128 | AES_CCM_64_64_256
        | AES_CCM_16_128_128 | AES_CCM_16_128_256 | AES_CCM_64_128_128 | AES_CCM_64_128_256 => {
            let cipher;
            let tag_len;
            if alg == AES_CCM_16_64_128 {
                tag_len = 8;
                cipher = cipher::Cipher::aes_128_ccm();
            } else if alg == AES_CCM_16_64_256 {
                tag_len = 8;
                cipher = cipher::Cipher::aes_256_ccm();
            } else if alg == AES_CCM_64_64_128 {
                tag_len = 8;
                cipher = cipher::Cipher::aes_128_ccm();
            } else if alg == AES_CCM_64_64_256 {
                tag_len = 8;
                cipher = cipher::Cipher::aes_256_ccm();
            } else if alg == AES_CCM_16_128_128 {
                tag_len = 16;
                cipher = cipher::Cipher::aes_128_ccm();
            } else if alg == AES_CCM_16_128_256 {
                tag_len = 16;
                cipher = cipher::Cipher::aes_256_ccm();
            } else if alg == AES_CCM_64_128_128 {
                tag_len = 16;
                cipher = cipher::Cipher::aes_128_ccm();
            } else {
                tag_len = 16;
                cipher = cipher::Cipher::aes_256_ccm();
            }
            let mut ctx = CipherCtx::new()?;
            ctx.encrypt_init(Some(cipher), None, None)?;

            ctx.set_tag_length(tag_len)?;
            ctx.set_iv_length(iv.len())?;
            ctx.encrypt_init(None, Some(&key), Some(&iv))?;
            ctx.set_data_len(payload.len())?;

            let mut out = vec![];

            ctx.cipher_update(&aead, None)?;
            ctx.cipher_update_vec(&payload, &mut out)?;
            ctx.cipher_final_vec(&mut out)?;

            let mut out_tag = vec![0u8; tag_len];
            ctx.tag(&mut out_tag)?;
            out.append(&mut out_tag);

            Ok(out)
        }
        A128GCM | A192GCM | A256GCM | CHACHA20 => {
            let mut tag: [u8; 16] = [0; 16];
            let cipher;
            if alg == A128GCM {
                cipher = Cipher::aes_128_gcm();
            } else if alg == A192GCM {
                cipher = Cipher::aes_192_gcm();
            } else if alg == A256GCM {
                cipher = Cipher::aes_256_gcm();
            } else {
                cipher = Cipher::chacha20_poly1305();
            }
            let mut ciphertext = encrypt_aead(cipher, key, Some(iv), aead, payload, &mut tag)?;
            ciphertext.append(&mut tag.to_vec());
            Ok(ciphertext)
        }
        _ => Err(CoseError::Invalid(CoseField::Alg)),
    }
}

pub(crate) fn decrypt(
    alg: i32,
    key: &Vec<u8>,
    iv: &Vec<u8>,
    ciphertext: &Vec<u8>,
    aead: &Vec<u8>,
) -> CoseResultWithRet<Vec<u8>> {
    match alg {
        AES_CCM_16_64_128 | AES_CCM_16_64_256 | AES_CCM_64_64_128 | AES_CCM_64_64_256
        | AES_CCM_16_128_128 | AES_CCM_16_128_256 | AES_CCM_64_128_128 | AES_CCM_64_128_256 => {
            let cipher;
            let tag_len;
            if alg == AES_CCM_16_64_128 {
                tag_len = 8;
                cipher = cipher::Cipher::aes_128_ccm();
            } else if alg == AES_CCM_16_64_256 {
                tag_len = 8;
                cipher = cipher::Cipher::aes_256_ccm();
            } else if alg == AES_CCM_64_64_128 {
                tag_len = 8;
                cipher = cipher::Cipher::aes_128_ccm();
            } else if alg == AES_CCM_64_64_256 {
                tag_len = 8;
                cipher = cipher::Cipher::aes_256_ccm();
            } else if alg == AES_CCM_16_128_128 {
                tag_len = 16;
                cipher = cipher::Cipher::aes_128_ccm();
            } else if alg == AES_CCM_16_128_256 {
                tag_len = 16;
                cipher = cipher::Cipher::aes_256_ccm();
            } else if alg == AES_CCM_64_128_128 {
                tag_len = 16;
                cipher = cipher::Cipher::aes_128_ccm();
            } else {
                tag_len = 16;
                cipher = cipher::Cipher::aes_256_ccm();
            }
            let offset = ciphertext.len() - tag_len;
            let data = ciphertext[..offset].to_vec();
            let tag = ciphertext[offset..].to_vec();
            let mut ctx = CipherCtx::new()?;
            ctx.decrypt_init(Some(cipher), None, None)?;

            ctx.set_tag_length(tag_len)?;
            ctx.set_key_length(key.len())?;
            ctx.set_iv_length(iv.len())?;
            ctx.decrypt_init(None, Some(&key), Some(&iv))?;

            let mut out = vec![0; data.len() + cipher.block_size()];

            ctx.set_tag(&tag)?;
            ctx.set_data_len(data.len())?;

            ctx.cipher_update(&aead, None)?;
            let count = ctx.cipher_update(&data, Some(&mut out))?;
            out.truncate(count);
            Ok(out)
        }
        A128GCM | A192GCM | A256GCM | CHACHA20 => {
            let offset = ciphertext.len() - 16;
            let cipher;
            if alg == A128GCM {
                cipher = Cipher::aes_128_gcm();
            } else if alg == A192GCM {
                cipher = Cipher::aes_192_gcm();
            } else if alg == A256GCM {
                cipher = Cipher::aes_256_gcm();
            } else {
                cipher = Cipher::chacha20_poly1305();
            }
            Ok(decrypt_aead(
                cipher,
                key,
                Some(iv),
                aead,
                &ciphertext[..offset],
                &ciphertext[offset..],
            )?)
        }
        _ => Err(CoseError::Invalid(CoseField::Alg)),
    }
}

pub(crate) fn aes_key_wrap(
    key: &Vec<u8>,
    size: usize,
    cek: &Vec<u8>,
) -> CoseResultWithRet<Vec<u8>> {
    let aes_key = AesKey::new_encrypt(&key)?;
    let mut ciphertext = vec![0u8; (size + 8).into()];
    wrap_key(&aes_key, None, &mut ciphertext, cek)?;
    Ok(ciphertext)
}

pub(crate) fn aes_key_unwrap(
    key: &Vec<u8>,
    size: usize,
    cek: &Vec<u8>,
) -> CoseResultWithRet<Vec<u8>> {
    let aes_key = AesKey::new_decrypt(&key)?;
    let mut orig_key = vec![0u8; size];
    unwrap_key(&aes_key, None, &mut orig_key, cek)?;
    Ok(orig_key)
}
pub(crate) fn rsa_oaep_enc(key: &Vec<u8>, cek: &Vec<u8>, alg: &i32) -> CoseResultWithRet<Vec<u8>> {
    let rsa_key = PKey::public_key_from_der(key)?;
    let mut enc = PkeyCtx::new(&rsa_key)?;
    enc.encrypt_init()?;
    enc.set_rsa_padding(Padding::PKCS1_OAEP)?;
    match *alg {
        RSA_OAEP_1 => {
            enc.set_rsa_oaep_md(Md::sha1())?;
        }
        RSA_OAEP_256 => {
            enc.set_rsa_oaep_md(Md::sha256())?;
        }
        RSA_OAEP_512 => {
            enc.set_rsa_oaep_md(Md::sha512())?;
        }
        _ => return Err(CoseError::Invalid(CoseField::Alg)),
    }
    let mut out: Vec<u8> = Vec::new();
    enc.encrypt_to_vec(cek, &mut out)?;
    Ok(out.to_vec())
}

pub(crate) fn rsa_oaep_dec(
    key: &Vec<u8>,
    size: usize,
    cek: &Vec<u8>,
    alg: &i32,
) -> CoseResultWithRet<Vec<u8>> {
    let rsa_key = PKey::private_key_from_der(key)?;
    let mut enc = PkeyCtx::new(&rsa_key)?;
    enc.decrypt_init()?;
    enc.set_rsa_padding(Padding::PKCS1_OAEP)?;
    match *alg {
        RSA_OAEP_1 => {
            enc.set_rsa_oaep_md(Md::sha1())?;
        }
        RSA_OAEP_256 => {
            enc.set_rsa_oaep_md(Md::sha256())?;
        }
        RSA_OAEP_512 => {
            enc.set_rsa_oaep_md(Md::sha512())?;
        }
        _ => return Err(CoseError::Invalid(CoseField::Alg)),
    }
    let mut out: Vec<u8> = Vec::new();
    enc.decrypt_to_vec(cek, &mut out)?;
    Ok(out[..size].to_vec())
}

pub(crate) fn thumbprint(cert: &Vec<u8>, alg: &i32) -> CoseResultWithRet<Vec<u8>> {
    if *alg == SHA_256 {
        let digest = hash(MessageDigest::sha256(), cert)?;
        Ok(digest.to_vec())
    } else {
        Err(CoseError::Invalid(CoseField::Alg))
    }
}

pub(crate) fn verify_thumbprint(cert: &Vec<u8>, thumbprint: &Vec<u8>, alg: &i32) -> CoseResult {
    if *alg == SHA_256 {
        let digest = hash(MessageDigest::sha256(), &cert)?;
        assert_eq!(digest.to_vec(), *thumbprint);
    } else {
        return Err(CoseError::Invalid(CoseField::Alg));
    }
    Ok(())
}

pub(crate) fn verify_chain(chain: &Vec<Vec<u8>>) -> CoseResult {
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
    let pkey_rec: PKey<Public>;
    let pkey_send: PKey<Private>;
    if crv_rec.is_some() {
        let crv = crv_rec.unwrap();
        match crv {
            keys::X448 | keys::X25519 => {
                let id_pkey;
                if crv == keys::X448 {
                    id_pkey = Id::X448;
                } else {
                    id_pkey = Id::X25519;
                }
                pkey_rec = PKey::public_key_from_raw_bytes(receiver_key, id_pkey)?;
            }
            keys::P_256 | keys::P_384 | keys::P_521 => {
                let group;
                if crv == keys::P_256 {
                    group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
                } else if crv == keys::P_384 {
                    group = EcGroup::from_curve_name(Nid::SECP384R1)?;
                } else {
                    group = EcGroup::from_curve_name(Nid::SECP521R1)?;
                }
                let mut ctx = BigNumContext::new()?;
                let point = EcPoint::from_bytes(&group, receiver_key, &mut ctx)?;
                pkey_rec = PKey::from_ec_key(EcKey::from_public_key(&group, &point)?)?;
            }
            _ => return Err(CoseError::Invalid(CoseField::Crv)),
        }
    } else {
        let x5 = X509::from_der(&receiver_key)?;
        pkey_rec = x5.public_key()?;
    }

    if crv_send.is_some() {
        let crv = crv_send.unwrap();
        match crv {
            keys::X448 | keys::X25519 => {
                let id_pkey;
                if crv == keys::X448 {
                    id_pkey = Id::X448;
                } else {
                    id_pkey = Id::X25519;
                }
                pkey_send = PKey::private_key_from_raw_bytes(sender_key, id_pkey)?;
            }
            keys::P_256 | keys::P_384 | keys::P_521 => {
                let number = BigNum::from_slice(&sender_key)?;
                let group;
                if crv == keys::P_256 {
                    group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
                } else if crv == keys::P_384 {
                    group = EcGroup::from_curve_name(Nid::SECP384R1)?;
                } else {
                    group = EcGroup::from_curve_name(Nid::SECP521R1)?;
                }
                pkey_send = PKey::from_ec_key(EcKey::from_private_components(
                    &group,
                    &number,
                    &EcPoint::new(&group).unwrap(),
                )?)?;
            }
            _ => return Err(CoseError::Invalid(CoseField::Crv)),
        }
    } else {
        pkey_send = PKey::private_key_from_der(sender_key)?;
    }
    let mut deriver = Deriver::new(&pkey_send)?;
    deriver.set_peer(&pkey_rec)?;
    Ok(deriver.derive_to_vec()?)
}

pub(crate) fn hkdf(
    length: usize,
    ikm: &Vec<u8>,
    salt_input: Option<&Vec<u8>>,
    info_input: &mut Vec<u8>,
    alg: i32,
) -> CoseResultWithRet<Vec<u8>> {
    if [DIRECT_HKDF_AES_128, DIRECT_HKDF_AES_256].contains(&alg) {
        let mut t = Vec::new();
        let mut okm = Vec::new();
        let mut i = 0;
        while okm.len() < length {
            i += 1;
            let mut info_tmp = info_input.clone();
            t.append(&mut info_tmp);
            t.append(&mut vec![i]);
            let mut padded: Vec<u8> = t;
            if padded.len() % 16 != 0 {
                padded.append(&mut vec![0; 16 - (padded.len() % 16)]);
            }
            let cipher;
            if alg == DIRECT_HKDF_AES_128 {
                cipher = Cipher::aes_128_cbc();
            } else {
                cipher = Cipher::aes_256_cbc();
            }
            let index = padded.len() - 16;
            let s = encr(cipher, &ikm, None, &padded).unwrap();
            t = s[index..index + 16].to_vec();
            let mut temp = t.clone();
            okm.append(&mut temp);
        }
        return Ok(okm[..length].to_vec());
    }

    let mut digest = Md::sha256();
    if [DIRECT_HKDF_SHA_512, ECDH_ES_HKDF_512, ECDH_SS_HKDF_512].contains(&alg) {
        digest = Md::sha512();
    }
    let salt = match salt_input {
        Some(v) => v.to_vec(),
        None => vec![0; length],
    };
    let mut ctx = PkeyCtx::new_id(Id::HKDF)?;
    ctx.derive_init()?;
    ctx.set_hkdf_md(&digest)?;
    ctx.set_hkdf_key(ikm)?;
    ctx.set_hkdf_salt(&salt)?;
    ctx.add_hkdf_info(info_input)?;
    let mut out = vec![0; length];
    ctx.derive(Some(&mut out))?;
    Ok(out)
}

pub(crate) fn get_cek_size(alg: &i32) -> CoseResultWithRet<usize> {
    if K16_ALGS.contains(alg) {
        Ok(16)
    } else if K32_ALGS.contains(alg) {
        Ok(32)
    } else if K24_ALGS.contains(alg) {
        Ok(24)
    } else if HMAC_384_384 == *alg {
        Ok(48)
    } else if HMAC_512_512 == *alg {
        Ok(64)
    } else {
        Err(CoseError::Invalid(CoseField::Alg))
    }
}
pub(crate) fn gen_random_key(alg: &i32) -> CoseResultWithRet<Vec<u8>> {
    if K16_ALGS.contains(alg) {
        Ok(rand::thread_rng().gen::<[u8; 16]>().to_vec())
    } else if K32_ALGS.contains(alg) {
        Ok(rand::thread_rng().gen::<[u8; 32]>().to_vec())
    } else if K24_ALGS.contains(alg) {
        Ok(rand::thread_rng().gen::<[u8; 24]>().to_vec())
    } else if HMAC_384_384 == *alg {
        let mut out = rand::thread_rng().gen::<[u8; 32]>().to_vec();
        out.append(&mut rand::thread_rng().gen::<[u8; 16]>().to_vec());
        Ok(out)
    } else if HMAC_512_512 == *alg {
        let mut out = rand::thread_rng().gen::<[u8; 32]>().to_vec();
        out.append(&mut rand::thread_rng().gen::<[u8; 32]>().to_vec());
        Ok(out)
    } else {
        Err(CoseError::Invalid(CoseField::Alg))
    }
}

pub(crate) fn get_iv_size(alg: &i32) -> CoseResultWithRet<usize> {
    match *alg {
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
    let size = get_iv_size(alg)?;
    let mut pv = partial_iv.clone();
    let mut padded = vec![0; size - pv.len()];
    padded.append(&mut pv);
    let mut iv = Vec::new();
    for i in 0..padded.len() {
        if i < base_iv.len() {
            iv.push(padded[i] ^ base_iv[i]);
        } else {
            iv.push(padded[i]);
        }
    }
    Ok(iv)
}
