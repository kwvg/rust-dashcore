//! BLS key operations used by HD derivation.
//!
//! The only module that names the BLS library.

use dashcore::blsful::{Bls12381G2Impl, PublicKey, SecretKey, SerializationFormat};
use zeroize::Zeroize;

/// G1 serialization format used as input to BLS HD derivation.
///
/// Non-hardened derivation feeds the parent public key into the HMAC, so the
/// serialization format is part of the derivation itself — dashbls
/// parameterizes it as `fLegacy`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlsDerivationMode {
    /// Modern (IETF/basic-scheme) serialization, like dashbls
    /// `PrivateChild(i)` with the default `fLegacy = false`.
    Modern,
    /// Legacy Dash serialization (`fLegacy = true`). This is what
    /// dashbls/DashSync use for masternode operator keys (DIP-3
    /// `m/9'/coin'/3'/3'`).
    Legacy,
}

impl BlsDerivationMode {
    fn format(self) -> SerializationFormat {
        match self {
            BlsDerivationMode::Modern => SerializationFormat::Modern,
            BlsDerivationMode::Legacy => SerializationFormat::Legacy,
        }
    }
}

/// An opaque BLS secret key.
#[derive(Clone, PartialEq, Eq)]
pub struct BlsSecretKey(SecretKey<Bls12381G2Impl>);

impl BlsSecretKey {
    /// Interprets 32 big-endian bytes as a scalar reduced modulo the group
    /// order, as dashbls does. `None` when the scalar reduces to zero.
    pub fn from_be_bytes_reduce(bytes: &[u8; 32]) -> Option<Self> {
        SecretKey::from_be_bytes(bytes).into_option().map(BlsSecretKey)
    }

    /// As [`Self::from_be_bytes_reduce`], for a little-endian scalar.
    pub fn from_le_bytes_reduce(bytes: &[u8; 32]) -> Option<Self> {
        SecretKey::from_le_bytes(bytes).into_option().map(BlsSecretKey)
    }

    /// Returns the scalar as 32 big-endian bytes.
    pub fn to_be_bytes(&self) -> [u8; 32] {
        self.0.to_be_bytes()
    }

    /// Adds two scalars in the BLS12-381 scalar field.
    pub fn add(&self, tweak: &Self) -> Self {
        BlsSecretKey(SecretKey(self.0.0 + tweak.0.0))
    }

    /// Derives the corresponding public key.
    pub fn public_key(&self) -> BlsPublicKey {
        BlsPublicKey(PublicKey::from(&self.0))
    }
}

impl Zeroize for BlsSecretKey {
    fn zeroize(&mut self) {
        self.0.0.zeroize();
    }
}

/// An opaque BLS public key.
#[derive(Clone, PartialEq, Eq)]
pub struct BlsPublicKey(PublicKey<Bls12381G2Impl>);

impl BlsPublicKey {
    /// Parses a 48-byte G1 point encoded in `mode`.
    pub fn from_bytes_with_mode(bytes: &[u8], mode: BlsDerivationMode) -> Result<Self, String> {
        PublicKey::from_bytes_with_mode(bytes, mode.format())
            .map(BlsPublicKey)
            .map_err(|e| e.to_string())
    }

    /// Returns the modern (IETF) encoding of the point.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes()
    }

    /// Returns the encoding of the point in `mode`.
    pub fn to_bytes_with_mode(&self, mode: BlsDerivationMode) -> Vec<u8> {
        self.0.to_bytes_with_mode(mode.format())
    }

    /// Returns the modern (IETF) encoding as a fixed-width array.
    pub fn to_compressed(&self) -> [u8; 48] {
        self.0.0.to_compressed()
    }

    /// Adds two G1 points.
    pub fn add(&self, other: &Self) -> Self {
        BlsPublicKey(PublicKey(self.0.0 + other.0.0))
    }
}
