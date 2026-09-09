//! Errors returned by BLS HD key derivation.

use core::fmt;
use std::error;

/// Errors that can occur in BLS HD key derivation
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Invalid derivation path string
    InvalidDerivationPath,
    /// Invalid seed length
    InvalidSeed,
    /// Invalid private key
    InvalidPrivateKey,
    /// Invalid public key
    InvalidPublicKey,
    /// Invalid chain code
    InvalidChainCode,
    /// Cannot derive public key from hardened
    CannotDeriveFromHardenedPublic,
    /// BLS error
    BLSError(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::InvalidDerivationPath => write!(f, "Invalid derivation path"),
            Error::InvalidSeed => write!(f, "Invalid seed"),
            Error::InvalidPrivateKey => write!(f, "Invalid private key"),
            Error::InvalidPublicKey => write!(f, "Invalid public key"),
            Error::InvalidChainCode => write!(f, "Invalid chain code"),
            Error::CannotDeriveFromHardenedPublic => {
                write!(f, "Cannot derive public key from hardened")
            }
            Error::BLSError(e) => write!(f, "BLS error: {}", e),
        }
    }
}

impl error::Error for Error {}
