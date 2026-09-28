//
// This file is a part of rust-dashcore.
// Portions written by Andrew Poelstra <apoelstra@wpsoftware.net> for rust-bitcoin.
// SPDX-License-Identifier: CC0-1.0
// See the accompanying file LICENSE or https://creativecommons.org/publicdomain/zero/1.0
//

//! ECDSA Bitcoin signatures.
//!
//! This module provides ECDSA signatures used Bitcoin that can be roundtrip (de)serialized.

use core::str::FromStr;
use core::{fmt, iter};

use hashes::hex::{self, FromHex};
use internals::hex::display::DisplayHex;
use internals::write_err;
use secp256k1;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use thiserror::Error as ThisError;
use zeroize::{Zeroize, Zeroizing};

use crate::sighash::{EcdsaSighashType, NonStandardSighashType};

const MAX_SIG_LEN: usize = 73;

/// An ECDSA signature with the corresponding hash type.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Signature {
    /// The underlying ECDSA Signature
    pub sig: secp256k1::ecdsa::Signature,
    /// The corresponding hash type
    pub hash_ty: EcdsaSighashType,
}

impl Signature {
    /// Constructs an ECDSA dash signature for [`EcdsaSighashType::All`].
    pub fn sighash_all(sig: secp256k1::ecdsa::Signature) -> Signature {
        Signature {
            sig,
            hash_ty: EcdsaSighashType::All,
        }
    }

    /// Deserializes from slice following the standardness rules for [`EcdsaSighashType`].
    pub fn from_slice(sl: &[u8]) -> Result<Self, Error> {
        let (hash_ty, sig) = sl.split_last().ok_or(Error::EmptySignature)?;
        let hash_ty = EcdsaSighashType::from_standard(*hash_ty as u32)
            .map_err(|_| Error::NonStandardSighashType(*hash_ty as u32))?;
        let sig = secp256k1::ecdsa::Signature::from_der(sig).map_err(Error::Secp256k1)?;
        Ok(Signature {
            sig,
            hash_ty,
        })
    }

    /// Serializes an ECDSA signature (inner secp256k1 signature in DER format).
    ///
    /// This does **not** perform extra heap allocation.
    pub fn serialize(&self) -> SerializedSignature {
        let mut buf = [0u8; MAX_SIG_LEN];
        let signature = self.sig.serialize_der();
        buf[..signature.len()].copy_from_slice(&signature);
        buf[signature.len()] = self.hash_ty as u8;
        SerializedSignature {
            data: buf,
            len: signature.len() + 1,
        }
    }

    /// Serializes an ECDSA signature (inner secp256k1 signature in DER format) into `Vec`.
    ///
    /// Note: this performs an extra heap allocation, you might prefer the
    /// [`serialize`](Self::serialize) method instead.
    pub fn to_vec(self) -> Vec<u8> {
        // TODO: add support to serialize to a writer to SerializedSig
        self.sig.serialize_der().iter().copied().chain(iter::once(self.hash_ty as u8)).collect()
    }
}

impl fmt::Display for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::LowerHex::fmt(&self.sig.serialize_der().as_hex(), f)?;
        fmt::LowerHex::fmt(&[self.hash_ty as u8].as_hex(), f)
    }
}

impl FromStr for Signature {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = Vec::from_hex(s)?;
        let (sighash_byte, signature) = bytes.split_last().ok_or(Error::EmptySignature)?;
        Ok(Signature {
            sig: secp256k1::ecdsa::Signature::from_der(signature)?,
            hash_ty: EcdsaSighashType::from_standard(*sighash_byte as u32)?,
        })
    }
}

/// Holds signature serialized in-line (not in `Vec`).
///
/// This avoids allocation and allows proving maximum size of the signature (73 bytes).
/// The type can be used largely as a byte slice. It implements all standard traits one would
/// expect and has familiar methods.
/// However, the usual use case is to push it into a script. This can be done directly passing it
/// into `ScriptBuf::push_slice`.
#[derive(Copy, Clone)]
pub struct SerializedSignature {
    data: [u8; MAX_SIG_LEN],
    len: usize,
}

impl SerializedSignature {
    /// Returns an iterator over bytes of the signature.
    #[inline]
    pub fn iter(&self) -> core::slice::Iter<'_, u8> {
        self.into_iter()
    }
}

impl core::ops::Deref for SerializedSignature {
    type Target = [u8];

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.data[..self.len]
    }
}

impl core::ops::DerefMut for SerializedSignature {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.data[..self.len]
    }
}

impl AsRef<[u8]> for SerializedSignature {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self
    }
}

impl AsMut<[u8]> for SerializedSignature {
    #[inline]
    fn as_mut(&mut self) -> &mut [u8] {
        self
    }
}

impl core::borrow::Borrow<[u8]> for SerializedSignature {
    #[inline]
    fn borrow(&self) -> &[u8] {
        self
    }
}

impl core::borrow::BorrowMut<[u8]> for SerializedSignature {
    #[inline]
    fn borrow_mut(&mut self) -> &mut [u8] {
        self
    }
}

impl fmt::Debug for SerializedSignature {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl fmt::Display for SerializedSignature {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::LowerHex::fmt(self, f)
    }
}

impl fmt::LowerHex for SerializedSignature {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::LowerHex::fmt(&(**self).as_hex(), f)
    }
}

impl fmt::UpperHex for SerializedSignature {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::UpperHex::fmt(&(**self).as_hex(), f)
    }
}

impl PartialEq for SerializedSignature {
    #[inline]
    fn eq(&self, other: &SerializedSignature) -> bool {
        **self == **other
    }
}

impl Eq for SerializedSignature {}

impl core::hash::Hash for SerializedSignature {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        core::hash::Hash::hash(&**self, state)
    }
}

impl<'a> IntoIterator for &'a SerializedSignature {
    type IntoIter = core::slice::Iter<'a, u8>;
    type Item = &'a u8;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        (*self).iter()
    }
}

/// A key-related error.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
#[non_exhaustive]
pub enum Error {
    /// Hex encoding error
    HexEncoding(hex::Error),
    /// Base58 encoding error
    NonStandardSighashType(u32),
    /// Empty Signature
    EmptySignature,
    /// secp256k1-related error
    Secp256k1(secp256k1::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::HexEncoding(ref e) => write_err!(f, "Signature hex encoding error"; e),
            Error::NonStandardSighashType(hash_ty) => {
                write!(f, "Non standard signature hash type {}", hash_ty)
            }
            Error::EmptySignature => write!(f, "Empty ECDSA signature"),
            Error::Secp256k1(ref e) => write_err!(f, "invalid ECDSA signature"; e),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use self::Error::*;

        match self {
            HexEncoding(e) => Some(e),
            Secp256k1(e) => Some(e),
            NonStandardSighashType(_) | EmptySignature => None,
        }
    }
}

impl From<secp256k1::Error> for Error {
    fn from(e: secp256k1::Error) -> Error {
        Error::Secp256k1(e)
    }
}

impl From<NonStandardSighashType> for Error {
    fn from(err: NonStandardSighashType) -> Self {
        Error::NonStandardSighashType(err.0)
    }
}

impl From<hex::Error> for Error {
    fn from(err: hex::Error) -> Self {
        Error::HexEncoding(err)
    }
}

/// Compressed SEC1 public key length.
pub const ECDSA_PK_LEN: usize = 33;

/// Uncompressed SEC1 public key length.
pub const ECDSA_PK_UNCOMPRESSED_LEN: usize = 65;

/// Scalar (secret key or tweak) length.
pub const ECDSA_SK_LEN: usize = 32;

/// Errors produced by secp256k1 operations.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, ThisError)]
#[non_exhaustive]
pub enum EcdsaError {
    /// Public key bytes are not a usable curve point.
    #[error("invalid secp256k1 public key")]
    InvalidPublicKey,
    /// Secret key bytes are zero or not below the curve order.
    #[error("invalid secp256k1 secret key")]
    InvalidSecretKey,
    /// Tweak is out of range or produced the point at infinity.
    #[error("invalid secp256k1 tweak")]
    InvalidTweak,
}

/// A secp256k1 public key (a curve point, without a serialization form).
///
/// The backend's type stays behind this one; convert with [`From`] where a
/// backend-only API (x-only keys, Schnorr) still needs it.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct EcdsaPublicKey(secp256k1::PublicKey);

impl EcdsaPublicKey {
    /// Parses a compressed (33-byte) or uncompressed (65-byte) SEC1 encoding.
    ///
    /// # Errors
    ///
    /// Returns `InvalidPublicKey` when the bytes are not a valid encoding of a
    /// curve point.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, EcdsaError> {
        let inner = if let Ok(bytes) = <[u8; ECDSA_PK_LEN]>::try_from(bytes) {
            secp256k1::PublicKey::from_byte_array_compressed(bytes)
        } else if let Ok(bytes) = <[u8; ECDSA_PK_UNCOMPRESSED_LEN]>::try_from(bytes) {
            secp256k1::PublicKey::from_byte_array_uncompressed(bytes)
        } else {
            return Err(EcdsaError::InvalidPublicKey);
        };
        inner.map(Self).map_err(|_| EcdsaError::InvalidPublicKey)
    }

    /// The compressed SEC1 encoding.
    pub fn to_compressed(&self) -> [u8; ECDSA_PK_LEN] {
        self.0.serialize()
    }

    /// The uncompressed SEC1 encoding.
    pub fn to_uncompressed(&self) -> [u8; ECDSA_PK_UNCOMPRESSED_LEN] {
        self.0.serialize_uncompressed()
    }

    /// Adds `tweak * G` to the point.
    ///
    /// # Errors
    ///
    /// Returns `InvalidTweak` when the tweak is not a valid scalar or the sum
    /// is the point at infinity.
    pub fn add_tweak(&self, tweak: &[u8; ECDSA_SK_LEN]) -> Result<Self, EcdsaError> {
        let tweak =
            secp256k1::Scalar::from_be_bytes(*tweak).map_err(|_| EcdsaError::InvalidTweak)?;
        self.0.add_exp_tweak(&tweak).map(Self).map_err(|_| EcdsaError::InvalidTweak)
    }
}

/// Ordered by compressed encoding, as the backend orders its points.
impl Ord for EcdsaPublicKey {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.to_compressed().cmp(&other.to_compressed())
    }
}

impl PartialOrd for EcdsaPublicKey {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Debug for EcdsaPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EcdsaPublicKey({})", self)
    }
}

/// Hex of the compressed encoding.
impl fmt::Display for EcdsaPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::LowerHex::fmt(&self.to_compressed().as_hex(), f)
    }
}

/// Hex of either SEC1 encoding.
impl FromStr for EcdsaPublicKey {
    type Err = EcdsaError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_bytes(&Vec::from_hex(s).map_err(|_| EcdsaError::InvalidPublicKey)?)
    }
}

impl From<secp256k1::PublicKey> for EcdsaPublicKey {
    fn from(inner: secp256k1::PublicKey) -> Self {
        Self(inner)
    }
}

impl From<EcdsaPublicKey> for secp256k1::PublicKey {
    fn from(pk: EcdsaPublicKey) -> Self {
        pk.0
    }
}

/// A hex string of the compressed encoding in human-readable formats, the
/// bare 33-byte tuple otherwise.
#[cfg(feature = "serde")]
impl serde::Serialize for EcdsaPublicKey {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeTuple;

        if s.is_human_readable() {
            s.collect_str(self)
        } else {
            let mut tuple = s.serialize_tuple(ECDSA_PK_LEN)?;
            for byte in self.to_compressed() {
                tuple.serialize_element(&byte)?;
            }
            tuple.end()
        }
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for EcdsaPublicKey {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        if d.is_human_readable() {
            struct HexVisitor;

            impl serde::de::Visitor<'_> for HexVisitor {
                type Value = EcdsaPublicKey;

                fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                    f.write_str("an ASCII hex string")
                }

                fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
                    v.parse().map_err(E::custom)
                }
            }

            d.deserialize_str(HexVisitor)
        } else {
            let bytes = d.deserialize_tuple(ECDSA_PK_LEN, ByteTupleVisitor::<ECDSA_PK_LEN>)?;
            EcdsaPublicKey::from_bytes(&bytes).map_err(serde::de::Error::custom)
        }
    }
}

/// A secp256k1 secret key (a scalar, without a serialization form).
///
/// Not `Copy`: the scalar is erased when the key is dropped, and an implicit
/// copy would outlive that. The backend's type stays behind this one; convert
/// with [`From`] where a backend-only API (Schnorr) still needs it.
#[derive(Clone, Eq, PartialEq)]
pub struct EcdsaSecretKey(secp256k1::SecretKey);

impl EcdsaSecretKey {
    /// Wraps a big-endian scalar.
    ///
    /// # Errors
    ///
    /// Returns `InvalidSecretKey` when the scalar is zero or not below the
    /// curve order.
    pub fn from_bytes(bytes: &[u8; ECDSA_SK_LEN]) -> Result<Self, EcdsaError> {
        secp256k1::SecretKey::from_secret_bytes(*bytes)
            .map(Self)
            .map_err(|_| EcdsaError::InvalidSecretKey)
    }

    /// Copies out the big-endian scalar.
    pub fn to_bytes(&self) -> Zeroizing<[u8; ECDSA_SK_LEN]> {
        Zeroizing::new(self.0.to_secret_bytes())
    }

    /// Derives the corresponding public key.
    pub fn public_key(&self) -> EcdsaPublicKey {
        EcdsaPublicKey(self.0.public_key())
    }

    /// Adds `tweak` to the scalar.
    ///
    /// # Errors
    ///
    /// Returns `InvalidTweak` when the tweak is not a valid scalar or the sum
    /// is zero.
    pub fn add_tweak(&self, tweak: &[u8; ECDSA_SK_LEN]) -> Result<Self, EcdsaError> {
        let tweak =
            secp256k1::Scalar::from_be_bytes(*tweak).map_err(|_| EcdsaError::InvalidTweak)?;
        self.0.add_tweak(&tweak).map(Self).map_err(|_| EcdsaError::InvalidTweak)
    }

    /// Multiplies the scalar by `tweak`.
    ///
    /// # Errors
    ///
    /// Returns `InvalidTweak` when the tweak is zero or not a valid scalar.
    pub fn mul_tweak(&self, tweak: &[u8; ECDSA_SK_LEN]) -> Result<Self, EcdsaError> {
        let tweak =
            secp256k1::Scalar::from_be_bytes(*tweak).map_err(|_| EcdsaError::InvalidTweak)?;
        self.0.mul_tweak(&tweak).map(Self).map_err(|_| EcdsaError::InvalidTweak)
    }
}

impl Zeroize for EcdsaSecretKey {
    fn zeroize(&mut self) {
        self.0.non_secure_erase();
    }
}

impl Drop for EcdsaSecretKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl fmt::Debug for EcdsaSecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("EcdsaSecretKey(..)")
    }
}

impl From<secp256k1::SecretKey> for EcdsaSecretKey {
    fn from(inner: secp256k1::SecretKey) -> Self {
        Self(inner)
    }
}

impl From<&EcdsaSecretKey> for secp256k1::SecretKey {
    fn from(sk: &EcdsaSecretKey) -> Self {
        sk.0
    }
}

impl From<EcdsaSecretKey> for secp256k1::SecretKey {
    fn from(sk: EcdsaSecretKey) -> Self {
        Self::from(&sk)
    }
}

/// A hex string in human-readable formats, the bare 32-byte tuple otherwise.
#[cfg(feature = "serde")]
impl serde::Serialize for EcdsaSecretKey {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeTuple;

        let bytes = self.to_bytes();
        if s.is_human_readable() {
            s.serialize_str(&Zeroizing::new(bytes.to_lower_hex_string()))
        } else {
            let mut tuple = s.serialize_tuple(ECDSA_SK_LEN)?;
            for byte in bytes.iter() {
                tuple.serialize_element(byte)?;
            }
            tuple.end()
        }
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for EcdsaSecretKey {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let bytes = if d.is_human_readable() {
            struct HexVisitor;

            impl serde::de::Visitor<'_> for HexVisitor {
                type Value = Zeroizing<[u8; ECDSA_SK_LEN]>;

                fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                    f.write_str("a hex string representing a 32-byte secret key")
                }

                fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
                    <[u8; ECDSA_SK_LEN]>::from_hex(v).map(Zeroizing::new).map_err(E::custom)
                }
            }

            d.deserialize_str(HexVisitor)?
        } else {
            Zeroizing::new(d.deserialize_tuple(ECDSA_SK_LEN, ByteTupleVisitor::<ECDSA_SK_LEN>)?)
        };
        EcdsaSecretKey::from_bytes(&bytes).map_err(serde::de::Error::custom)
    }
}

/// Reads a fixed-size tuple of bytes, the non-human-readable key encoding.
#[cfg(feature = "serde")]
struct ByteTupleVisitor<const N: usize>;

#[cfg(feature = "serde")]
impl<'de, const N: usize> serde::de::Visitor<'de> for ByteTupleVisitor<N> {
    type Value = [u8; N];

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "a {}-byte tuple", N)
    }

    fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        let mut bytes = [0u8; N];
        for (i, byte) in bytes.iter_mut().enumerate() {
            *byte =
                seq.next_element()?.ok_or_else(|| serde::de::Error::invalid_length(i, &self))?;
        }
        Ok(bytes)
    }
}

#[cfg(all(test, feature = "serde"))]
mod tests {
    use super::*;

    /// The serde image of the inner signature is its DER encoding: a hex
    /// string in human-readable formats, a byte string otherwise.
    #[test]
    fn serde_layout_is_der() {
        const DER_HEX: &str = "3045022100d2e84c0a1a8e0d31d1b0f8b3cde37ab19ef8e6bff4f72c5ac6f0a4b8a8d1ec2d\
                               02204c7b8e3f2a5d6c1b0e9f8a7d6c5b4a39281706f5e4d3c2b1a09f8e7d6c5b4a39";

        let sig = Signature::from_str(&format!("{}01", DER_HEX)).expect("parse signature");

        let json = serde_json::to_string(&sig).expect("serialize signature");
        assert_eq!(json, format!("{{\"sig\":\"{}\",\"hash_ty\":\"SIGHASH_ALL\"}}", DER_HEX));
        assert_eq!(serde_json::from_str::<Signature>(&json).expect("deserialize signature"), sig);

        let config = bincode::config::standard();
        let bytes = bincode::serde::encode_to_vec(sig, config).expect("encode signature");
        let expected = Vec::from_hex(&format!("47{}0b{}", DER_HEX, ::hex::encode("SIGHASH_ALL")))
            .expect("decode hex");
        assert_eq!(bytes, expected);
        let (decoded, _): (Signature, _) =
            bincode::serde::decode_from_slice(&bytes, config).expect("decode signature");
        assert_eq!(decoded, sig);
    }
}
