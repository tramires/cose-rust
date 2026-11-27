//! Errors returned by the module, including
use cbor::decoder::DecodeError;
use cbor::encoder::EncodeError;
use openssl::error;
use std::{error::Error, fmt, io};

/// Result of an operation that returns nothing on success.
pub type CoseResult = Result<(), CoseError>;
/// Result of an operation that returns a value.
pub type CoseResultWithRet<A> = Result<A, CoseError>;

/// Errors returned by the crate.
#[derive(Debug)]
#[non_exhaustive]
pub enum CoseError {
    /// Field is set, but its value is wrong or not allowed
    Invalid(CoseField),
    /// A required field is not set
    Missing(CoseField),
    /// A map contains a label this crate does not recognize
    InvalidLabel(i32),
    /// Duplicate label found
    DuplicateLabel(i32),
    /// A method was used on a structure with the wrong context (for example, a counter signature
    /// method on a signer
    InvalidContext(String),
    /// A header has more than one sender key parmeter, only one is allowed
    MultipleSenderKeys,
    /// A certificate parmeter has no certificates
    EmptyX5,
    /// No usable key was provided for the operation
    MissingKey,
    /// The key's algorithm differs from the algorithm of the message or agent
    AlgMismatch,
    /// The data does not have the CBOR structure of a COSE message
    InvalidCoseStructure,
    /// The method is only available for messages without signers or recipients
    InvalidMethodMultipleAgents,
    /// A direct key agreement algorithm was used with more than one recipient
    DirectAlgMultipleRecipients,
    /// A recipient with a direct algorithm has a non-empty protected header
    DirectAlgProtectedHeader,
    /// Content is not secured
    NotSecured,
    /// A header has both an IV and a Partial IV
    IvandPartialIv,
    /// AES key wrap or unwrap failed
    KeyWrap,
    /// An OpenSSL operation failed
    CryptoStack(error::ErrorStack),
    /// An OpenSSL operation failed
    Crypto(error::Error),
    /// An I/O error occured during encoding or decoding
    Io(io::Error),
    /// CBOR encoding failed
    Encode(EncodeError),
    /// CBOR decoding failed
    Decode(DecodeError),
}

/// The field named by [`CoseError::Invalid`] and [`CoseError::Missing`]
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
            CoseError::DirectAlgMultipleRecipients => {
                f.write_str("direct algortithms allow only one recipient")
            }
            CoseError::IvandPartialIv => {
                f.write_str("both IV and Partial IV are present in the header")
            }
            CoseError::KeyWrap => f.write_str("AES key-wrap failed"),
            CoseError::NotSecured => f.write_str("content not secured"),
            CoseError::CryptoStack(_) | CoseError::Crypto(_) => f.write_str("OpenSSL error"),
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
            CoseError::Io(e) => Some(e),
            CoseError::Encode(e) => Some(e),
            CoseError::Decode(e) => Some(e),
            _ => None,
        }
    }
}
