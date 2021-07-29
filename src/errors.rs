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

/// Errors returned.
#[derive(Debug)]
pub enum CoseError {
    InvalidAlgorithmForContext(String),
    InvalidAlgorithm(),
    KeyDoesntSupportEncryption(),
    KeyDoesntSupportDecryption(),
    KeyUnableToEncryptOrDecrypt(),
    KeyUnableToSignOrVerify(),
    KeyDoesntSupportSigning(),
    KeyDoesntSupportVerification(),
    PrivateKeyNotPresent(),
    PublicKeyNotPresent(),
    DuplicateLabel(i32),
    InvalidLabel(i32),
    InvalidCounterSignature(),
    MissingRecipient(),
    MissingKey(),
    FunctionOnlyAvailableForContext(String),
    InvalidOperationForContext(String),
    InvalidContext(),
    MissingSignature(),
    MissingCiphertext(),
    MissingTag(),
    MissingPayload(),
    InvalidCoseStructure(),
    MissingParameter(String),
    InvalidParameter(String),
    NotImplemented(String),
    InvalidTag(),
    AlgorithmOnlySupportsOneRecipient(String),
    MissingAlgorithm(),
    CryptoStackError(error::ErrorStack),
    CryptoError(error::Error),
    CryptoKeyError(aes::KeyError),
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
