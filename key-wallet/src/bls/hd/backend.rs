//! BLS key operations used by HD derivation.
//!
//! The only module that names the BLS library.

use dashcore::blsful::{Bls12381G2Impl, PublicKey, SecretKey, SerializationFormat};
use zeroize::{Zeroize, Zeroizing};

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
    ///
    /// `None` when the sum reduces to zero. In non-hardened derivation the
    /// tweak is computable from the extended public key alone, so a zero
    /// child scalar means the parent scalar is the tweak's negation and any
    /// holder of that key can recover it.
    pub fn add(&self, tweak: &Self) -> Option<Self> {
        let sum = Zeroizing::new(BlsSecretKey(SecretKey(self.0.0 + tweak.0.0)).to_be_bytes());
        Self::from_be_bytes_reduce(&sum)
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
    pub fn from_bytes_with_mode(bytes: &[u8], mode: BlsDerivationMode) -> Option<Self> {
        PublicKey::from_bytes_with_mode(bytes, mode.format()).ok().map(BlsPublicKey)
    }

    /// Returns the modern (IETF) encoding of the point.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes()
    }

    /// Returns the encoding of the point in `mode`.
    ///
    /// `None` when the point cannot be expressed in the target
    /// serialization. The legacy format accepts points the modern one
    /// rejects, so re-encoding between them is a checked operation.
    pub fn to_bytes_with_mode(&self, mode: BlsDerivationMode) -> Option<Vec<u8>> {
        Some(self.0.to_bytes_with_mode(mode.format()))
    }

    /// Returns the modern (IETF) encoding as a fixed-width array.
    pub fn to_compressed(&self) -> [u8; 48] {
        self.0.0.to_compressed()
    }

    /// Adds two G1 points.
    ///
    /// `None` when the sum is the point at infinity, which is the same event
    /// [`BlsSecretKey::add`] rejects seen from the public side, and no usable
    /// key besides. Neither backend rejects it for us: parsing an encoded
    /// identity fails, but aggregating to one succeeds.
    pub fn add(&self, other: &Self) -> Option<Self> {
        let sum = BlsPublicKey(PublicKey(self.0.0 + other.0.0));
        (!sum.is_identity()).then_some(sum)
    }

    /// Whether the point is the identity, per bit 6 of the compressed
    /// encoding, which both serializations spell the same way.
    fn is_identity(&self) -> bool {
        self.to_bytes().first().is_some_and(|byte| byte & 0x40 != 0)
    }
}
