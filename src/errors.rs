//! Errors returned by the module, including
//! [rust-openssl](https://docs.rs/openssl/0.10.35/openssl/index.html) and
//! [cbor-codec](https://twittner.gitlab.io/cbor-codec/cbor/) errors.
use cbor::decoder::DecodeError;
use cbor::encoder::EncodeError;
use getrandom::Error as randError;
use openssl::error;
use std::{error::Error, fmt, io};

/// Errors that don't return anything.
pub type CoseResult = Result<(), CoseError>;
/// Results that return something.
pub type CoseResultWithRet<A> = Result<A, CoseError>;

#[derive(Debug, Copy, Clone)]
#[non_exhaustive]
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
    OtherPrimes,
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
#[non_exhaustive]
pub enum CoseError {
    Invalid(CoseField),
    Missing(CoseField),
    InvalidLabel(i32),
    DuplicateLabel(i32),
    InvalidContext(String),
    MultipleSenderKeys,
    EmptyX5,
    IVandPartialIV,
    MissingKey,
    AlgMismatch,
    InvalidCoseStructure,
    InvalidMethodMultipleAgents,
    DirectAlgMultipleRecipients,
    DirectAlgProtectedHeader,
    NotSecured,
    KeyWrap,
    CryptoStack(error::ErrorStack),
    Crypto(error::Error),
    GetRandom(randError),
    Io(io::Error),
    Encode(EncodeError),
    Decode(DecodeError),
}

macro_rules! wrap_errors {
    ($($variant:ident($source:ty)),* $(,)?) => {
        $(impl From<$source> for CoseError {
            fn from(err: $source) -> Self {
                CoseError::$variant(err)
            }
        })*
    };
}

wrap_errors! {
    CryptoStack(error::ErrorStack),
    Crypto(error::Error),
    GetRandom(randError),
    Io(io::Error),
    Encode(EncodeError),
    Decode(DecodeError),
}

impl fmt::Display for CoseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CoseError::Invalid(field) => write!(f, "invalid {:?}", field),
            CoseError::Missing(field) => write!(f, "missing {:?}", field),
            CoseError::InvalidLabel(label) => write!(f, "invalid label {}", label),
            CoseError::DuplicateLabel(label) => write!(f, "duplicate label {}", label),
            CoseError::InvalidContext(context) => write!(f, "invalid context {}", context),
            CoseError::MissingKey => f.write_str("missing key"),
            CoseError::AlgMismatch => f.write_str("algorithms mismatch"),
            CoseError::InvalidCoseStructure => f.write_str("invalid COSE structure"),
            CoseError::InvalidMethodMultipleAgents => {
                f.write_str("Method not available for message with multiple signers or recipients")
            }
            CoseError::DirectAlgProtectedHeader => {
                f.write_str("direct algortithms require an empty protected header")
            }
            CoseError::MultipleSenderKeys => {
                f.write_str("multiple sender keys for a single recipient found")
            }
            CoseError::EmptyX5 => f.write_str("empty X5 provided"),
            CoseError::IVandPartialIV => f.write_str("no IV or Partial IV"),
            CoseError::DirectAlgMultipleRecipients => {
                f.write_str("direct algortithms allow only one recipient")
            }
            CoseError::KeyWrap => f.write_str("AES key-wrap failed"),
            CoseError::NotSecured => f.write_str("content not secured"),
            CoseError::CryptoStack(_) | CoseError::Crypto(_) => f.write_str("OpenSSL error"),
            CoseError::GetRandom(_) => f.write_str("random number generation failed"),
            CoseError::Io(_) => f.write_str("I/O error"),
            CoseError::Encode(_) => f.write_str("CBOR encoding error"),
            CoseError::Decode(_) => f.write_str("CBOR decoding error"),
        }
    }
}

impl Error for CoseError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            CoseError::CryptoStack(e) => Some(e),
            CoseError::Crypto(e) => Some(e),
            CoseError::GetRandom(e) => Some(e),
            CoseError::Io(e) => Some(e),
            CoseError::Encode(e) => Some(e),
            CoseError::Decode(e) => Some(e),
            _ => None,
        }
    }
}
