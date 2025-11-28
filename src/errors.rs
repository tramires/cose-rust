//! Errors returned by the module, including
//! [rust-openssl](https://docs.rs/openssl/0.10.35/openssl/index.html) and
//! [cbor-codec](https://twittner.gitlab.io/cbor-codec/cbor/) errors.
use cbor::decoder::DecodeError;
use cbor::encoder::EncodeError;
#[cfg(feature = "json")]
use hex::FromHexError;
use openssl::aes;
use openssl::error;
#[cfg(feature = "json")]
use serde_json::Error;
use std::io;

/// Errors that don't return anything.
pub type CoseResult = Result<(), CoseError>;
/// Results that return something.
pub type CoseResultWithRet<A> = Result<A, CoseError>;

#[derive(Debug)]
pub enum CoseField {
    Alg,
    Crv,
    KeyOp,
    Kid,
    StaticKid,
    Kty,
    Tag,
    ContentType,
    Iv,
    BaseIv,
    PartialIv,
    Salt,
    PartyUIdentity,
    PartyUNonce,
    PartyUOther,
    PartyVIdentity,
    PartyVNonce,
    PartyVOther,
    K,
    X,
    Y,
    D,
    N,
    E,
    RsaD,
    P,
    Q,
    DP,
    DQ,
    QInv,
    RI,
    DI,
    TI,
    Other,
    CounterSignature,
    Payload,
    Signature,
    Ciphertext,
    Mac,
    KeyChain,
    X5Bag,
    X5Chain,
    X5U,
    X5T,
    X5TAlg,
    X5ChainSender,
    X5TSender,
    X5TSenderAlg,
    X5USender,
    Signer,
}

/// Errors returned.
#[derive(Debug)]
pub enum CoseError {
    Invalid(CoseField),
    Missing(CoseField),
    InvalidLabel(i32),
    DuplicateLabel(i32),
    InvalidContext(String),
    MissingKey(),
    AlgMismatch(),
    InvalidCoseStructure(),
    InvalidMethodMultipleAgents(),
    DirectAlgMultipleRecipientsError(),
    CryptoStackError(error::ErrorStack),
    CryptoKeyError(aes::KeyError),
    CryptoError(error::Error),
    IoError(io::Error),
    EncodeError(EncodeError),
    DecodeError(DecodeError),
    #[cfg(feature = "json")]
    HexError(FromHexError),
    #[cfg(feature = "json")]
    SerdeJsonError(Error),
}
impl From<error::ErrorStack> for CoseError {
    fn from(err: error::ErrorStack) -> CoseError {
        CoseError::CryptoStackError(err)
    }
}
impl From<error::Error> for CoseError {
    fn from(err: error::Error) -> CoseError {
        CoseError::CryptoError(err)
    }
}
impl From<aes::KeyError> for CoseError {
    fn from(err: aes::KeyError) -> CoseError {
        CoseError::CryptoKeyError(err)
    }
}
impl From<io::Error> for CoseError {
    fn from(err: io::Error) -> CoseError {
        CoseError::IoError(err)
    }
}

impl From<EncodeError> for CoseError {
    fn from(err: EncodeError) -> CoseError {
        CoseError::EncodeError(err)
    }
}
impl From<DecodeError> for CoseError {
    fn from(err: DecodeError) -> CoseError {
        CoseError::DecodeError(err)
    }
}
#[cfg(feature = "json")]
impl From<FromHexError> for CoseError {
    fn from(err: FromHexError) -> CoseError {
        CoseError::HexError(err)
    }
}
#[cfg(feature = "json")]
impl From<Error> for CoseError {
    fn from(err: Error) -> CoseError {
        CoseError::SerdeJsonError(err)
    }
}
