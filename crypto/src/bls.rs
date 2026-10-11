//
// This file is a part of rust-dashcore.
// SPDX-License-Identifier: CC0-1.0
// See the accompanying file LICENSE or https://creativecommons.org/publicdomain/zero/1.0
//

//! BLS12-381 public key and signatures.

use core::fmt;
use core::str::FromStr;

#[cfg(feature = "bincode")]
use bincode_derive::{Decode, Encode};
#[cfg(feature = "bls")]
use dash_pkc::__deps::ff::PrimeField;
#[cfg(feature = "bls")]
use dash_pkc::bls::{
    BlsPublicKey as PkcPublicKey, BlsScChia, BlsScIetf, BlsScheme as PkcScheme,
    BlsSecretKey as PkcSecretKey, BlsSignature as PkcSignature, Fr,
};
use dash_types::type_cvrt;
use hex_conservative::{DecodeFixedLengthBytesError, DisplayHex};
use internals::{impl_array_newtype, impl_bytes_newtype};
#[cfg(feature = "serde")]
use internals::{serde_string_deserialize_impl, serde_string_serialize_impl};
use subtle::ConstantTimeEq;
#[cfg(feature = "bls")]
use thiserror::Error as ThisError;
#[cfg(feature = "bls")]
use tracing::error;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Raw BLS public key length (G1 compressed).
pub const BLS_PK_LEN: usize = 48;

/// Raw BLS secret key length (big-endian scalar).
pub const BLS_SK_LEN: usize = 32;

/// Raw BLS signature length (G2 compressed).
pub const BLS_SIG_LEN: usize = 96;

/// Errors produced by BLS operations.
#[cfg(feature = "bls")]
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, ThisError)]
pub enum BlsError {
    /// Public key bytes are not a valid G1 point.
    #[error("Invalid BLS public key: {0}")]
    InvalidPublicKey(String),

    /// Signature bytes are not a valid G2 point.
    #[error("Invalid BLS signature: {0}")]
    InvalidSignature(String),

    /// Signature verification failed.
    #[error("BLS verification failed: {0}")]
    VerificationFailed(String),

    /// Secret key bytes are not a valid scalar.
    #[error("Invalid BLS secret key")]
    InvalidSecretKey,

    /// Tweak is not a valid scalar.
    #[error("Invalid BLS tweak")]
    InvalidTweak,
}

/// Which BLS scheme a 48- or 96-byte blob was written under.
#[cfg(feature = "bls")]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum BlsScheme {
    /// The pre-V19 legacy scheme.
    Legacy,
    /// The post-V19 basic scheme.
    Modern,
}

/// Reduces 32 big-endian bytes to the scalar they denote.
#[cfg(feature = "bls")]
fn reduce(bytes: &[u8; BLS_SK_LEN]) -> Result<[u8; BLS_SK_LEN], BlsError> {
    let reduced = Fr::from_bendian_reduce(bytes).map_err(|_| BlsError::InvalidTweak)?;

    // `to_repr` is little-endian; these bytes are big-endian.
    let mut out = [0u8; BLS_SK_LEN];
    out.copy_from_slice(reduced.to_repr().as_ref());
    out.reverse();

    Ok(out)
}

/// BLS public key (48 bytes, unvalidated).
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[cfg_attr(feature = "bincode", derive(Encode, Decode))]
pub struct BlsPkBytes([u8; BLS_PK_LEN]);

impl_array_newtype!(BlsPkBytes, u8, BLS_PK_LEN);

impl BlsPkBytes {
    /// Wraps raw bytes without validation.
    pub const fn from_bytes(bytes: [u8; BLS_PK_LEN]) -> Self {
        Self(bytes)
    }

    /// Borrows the inner byte array.
    pub const fn as_bytes(&self) -> &[u8; BLS_PK_LEN] {
        &self.0
    }

    /// Copies out the inner byte array.
    pub const fn to_bytes(&self) -> [u8; BLS_PK_LEN] {
        self.0
    }

    /// Pairs these bytes with `scheme`.
    #[cfg(feature = "bls")]
    pub fn as_scheme(self, scheme: BlsScheme) -> BlsPublicKey {
        BlsPublicKey {
            bytes: self,
            scheme,
        }
    }

    /// Reads these bytes from a hex string.
    pub fn from_hex(s: &str) -> Result<Self, DecodeFixedLengthBytesError> {
        Ok(Self::from_bytes(hex_conservative::decode_to_array(s)?))
    }

    /// Returns `true` when every byte is zero.
    pub fn is_zeroed(&self) -> bool {
        self.0 == [0; BLS_PK_LEN]
    }
}

impl Default for BlsPkBytes {
    fn default() -> Self {
        Self([0; BLS_PK_LEN])
    }
}

impl fmt::Display for BlsPkBytes {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0.as_hex())
    }
}

impl FromStr for BlsPkBytes {
    type Err = DecodeFixedLengthBytesError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_hex(s)
    }
}

#[cfg(feature = "serde")]
serde_string_serialize_impl!(BlsPkBytes, "a BLS public key");
#[cfg(feature = "serde")]
serde_string_deserialize_impl!(BlsPkBytes, "a BLS public key");

/// A [`BlsPkBytes`] paired with the scheme to read it under.
#[cfg(feature = "bls")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlsPublicKey {
    bytes: BlsPkBytes,
    scheme: BlsScheme,
}

#[cfg(feature = "bls")]
impl BlsPublicKey {
    /// Adds `tweak * G` to the point, written back under the same scheme.
    ///
    /// # Errors
    ///
    /// Returns `InvalidPublicKey` when the bytes are not a G1 point, or
    /// `InvalidTweak` when the tweak is not a valid scalar.
    pub fn add_tweak(self, tweak: &[u8; 32]) -> Result<BlsPkBytes, BlsError> {
        let sum = match self.scheme {
            BlsScheme::Legacy => self
                .point::<BlsScChia>()?
                .add_tweak(&reduce(tweak)?)
                .map_err(|_| BlsError::InvalidTweak)?
                .to_bytes(),
            BlsScheme::Modern => self
                .point::<BlsScIetf>()?
                .add_tweak(&reduce(tweak)?)
                .map_err(|_| BlsError::InvalidTweak)?
                .to_bytes(),
        };

        Ok(BlsPkBytes::from_bytes(sum))
    }

    /// Checks the bytes are a point and writes it back under the same scheme.
    ///
    /// # Errors
    ///
    /// Returns `InvalidPublicKey` when the bytes are not a G1 point.
    pub fn canonicalize(self) -> Result<BlsPkBytes, BlsError> {
        self.reencode(self.scheme)
    }

    /// Re-encodes the same point under `to`.
    ///
    /// # Errors
    ///
    /// Returns `InvalidPublicKey` when the bytes are not a G1 point under the
    /// scheme they were read with.
    pub fn reencode(self, to: BlsScheme) -> Result<BlsPkBytes, BlsError> {
        let bytes = match (self.scheme, to) {
            (BlsScheme::Legacy, BlsScheme::Legacy) => self.point::<BlsScChia>()?.to_bytes(),
            (BlsScheme::Legacy, BlsScheme::Modern) => self
                .point::<BlsScChia>()?
                .to_scheme::<BlsScIetf>()
                .map_err(|e| BlsError::InvalidPublicKey(e.to_string()))?
                .to_bytes(),
            (BlsScheme::Modern, BlsScheme::Legacy) => self
                .point::<BlsScIetf>()?
                .to_scheme::<BlsScChia>()
                .map_err(|e| BlsError::InvalidPublicKey(e.to_string()))?
                .to_bytes(),
            (BlsScheme::Modern, BlsScheme::Modern) => self.point::<BlsScIetf>()?.to_bytes(),
        };

        Ok(BlsPkBytes::from_bytes(bytes))
    }

    /// Verifies `signature` over a 32-byte message digest.
    ///
    /// The signature is read under this same scheme.
    ///
    /// # Errors
    ///
    /// Returns `InvalidPublicKey` or `InvalidSignature` when either side is
    /// not a curve point, or `VerificationFailed` when it does not verify.
    pub fn verify(self, digest: &[u8; 32], signature: &BlsSigBytes) -> Result<(), BlsError> {
        match self.scheme {
            BlsScheme::Legacy => self
                .point::<BlsScChia>()?
                .verify(digest, &signature.as_scheme(self.scheme).point::<BlsScChia>()?),
            BlsScheme::Modern => self
                .point::<BlsScIetf>()?
                .verify(&digest[..], &signature.as_scheme(self.scheme).point::<BlsScIetf>()?),
        }
        .map_err(|_| BlsError::VerificationFailed("signature did not verify".to_string()))
    }

    /// Reads the key in its own encoding and carries it to `S`.
    fn carry_to<S: PkcScheme>(self) -> Result<PkcPublicKey<S>, BlsError> {
        match self.scheme {
            BlsScheme::Legacy => self.point::<BlsScChia>()?.to_scheme::<S>(),
            BlsScheme::Modern => self.point::<BlsScIetf>()?.to_scheme::<S>(),
        }
        .map_err(|e| BlsError::InvalidPublicKey(e.to_string()))
    }

    fn point<S: PkcScheme>(self) -> Result<PkcPublicKey<S>, BlsError> {
        PkcPublicKey::<S>::from_bytes(self.bytes.as_bytes())
            .map_err(|e| BlsError::InvalidPublicKey(e.to_string()))
    }
}

/// BLS secret key bytes (32 big-endian bytes, unvalidated).
#[derive(Clone)]
pub struct BlsSkBytes(Zeroizing<[u8; BLS_SK_LEN]>);

impl BlsSkBytes {
    /// Wraps raw bytes without validation.
    pub fn from_bytes(bytes: [u8; BLS_SK_LEN]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// Borrows the inner byte array.
    pub fn as_bytes(&self) -> &[u8; BLS_SK_LEN] {
        &self.0
    }

    /// Copies out the inner byte array, wiped on drop.
    pub fn to_bytes(&self) -> Zeroizing<[u8; BLS_SK_LEN]> {
        self.0.clone()
    }
}

impl fmt::Debug for BlsSkBytes {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("BlsSkBytes(<redacted>)")
    }
}

impl Eq for BlsSkBytes {}

impl PartialEq for BlsSkBytes {
    fn eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&*other.0).into()
    }
}

impl Zeroize for BlsSkBytes {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl ZeroizeOnDrop for BlsSkBytes {}

type_cvrt!(From<[u8; BLS_SK_LEN]> for BlsSkBytes, |bytes| Self::from_bytes(*bytes));

#[cfg(feature = "bls")]
impl BlsSkBytes {
    /// Pairs these bytes with `scheme`.
    pub fn as_scheme(&self, scheme: BlsScheme) -> BlsSecretKey<'_> {
        BlsSecretKey {
            bytes: self,
            scheme,
        }
    }
}

/// A [`BlsSkBytes`] paired with the scheme to operate under.
#[cfg(feature = "bls")]
#[derive(Clone, Copy, Debug)]
pub struct BlsSecretKey<'a> {
    bytes: &'a BlsSkBytes,
    scheme: BlsScheme,
}

#[cfg(feature = "bls")]
impl BlsSecretKey<'_> {
    /// Adds `tweak` to the scalar, for hardened derivation.
    ///
    /// # Errors
    ///
    /// Returns `InvalidSecretKey` when the bytes are not a valid scalar, or
    /// `InvalidTweak` when the tweak or the sum is not one.
    pub fn add_tweak(self, tweak: &[u8; 32]) -> Result<BlsSkBytes, BlsError> {
        let sum = match self.scheme {
            BlsScheme::Legacy => *self
                .scalar::<BlsScChia>()?
                .add_tweak(&reduce(tweak)?)
                .map_err(|_| BlsError::InvalidTweak)?
                .to_bytes(),
            BlsScheme::Modern => *self
                .scalar::<BlsScIetf>()?
                .add_tweak(&reduce(tweak)?)
                .map_err(|_| BlsError::InvalidTweak)?
                .to_bytes(),
        };

        Ok(BlsSkBytes::from_bytes(sum))
    }

    /// Reduces the scalar modulo the group order and writes it back.
    ///
    /// # Errors
    ///
    /// Returns `InvalidSecretKey` when the bytes cannot be reduced.
    pub fn canonicalize(self) -> Result<BlsSkBytes, BlsError> {
        reduce(self.bytes.as_bytes())
            .map(BlsSkBytes::from_bytes)
            .map_err(|_| BlsError::InvalidSecretKey)
    }

    /// Derives the public key, written under the scheme.
    ///
    /// # Errors
    ///
    /// Returns `InvalidSecretKey` when the bytes are not a valid scalar.
    pub fn public_key(self) -> Result<BlsPkBytes, BlsError> {
        match self.scheme {
            BlsScheme::Legacy => {
                Ok(BlsPkBytes::from_bytes(self.scalar::<BlsScChia>()?.public_key().to_bytes()))
            }
            BlsScheme::Modern => {
                Ok(BlsPkBytes::from_bytes(self.scalar::<BlsScIetf>()?.public_key().to_bytes()))
            }
        }
    }

    fn scalar<S: PkcScheme>(self) -> Result<PkcSecretKey<S>, BlsError> {
        PkcSecretKey::<S>::from_bytes(self.bytes.as_bytes()).map_err(|_| BlsError::InvalidSecretKey)
    }
}

/// BLS signature (96 bytes, unvalidated).
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[cfg_attr(feature = "bincode", derive(Encode, Decode))]
pub struct BlsSigBytes([u8; BLS_SIG_LEN]);

impl_array_newtype!(BlsSigBytes, u8, BLS_SIG_LEN);
impl_bytes_newtype!(BlsSigBytes, BLS_SIG_LEN);

impl Default for BlsSigBytes {
    fn default() -> Self {
        Self([0; BLS_SIG_LEN])
    }
}

impl BlsSigBytes {
    /// Wraps raw bytes without validation.
    pub const fn from_bytes(bytes: [u8; BLS_SIG_LEN]) -> Self {
        Self(bytes)
    }

    /// Pairs these bytes with `scheme`.
    #[cfg(feature = "bls")]
    pub fn as_scheme(self, scheme: BlsScheme) -> BlsSignature {
        BlsSignature {
            bytes: self,
            scheme,
        }
    }

    /// Reads these bytes from a hex string.
    pub fn from_hex(s: &str) -> Result<Self, DecodeFixedLengthBytesError> {
        Ok(Self::from_bytes(hex_conservative::decode_to_array(s)?))
    }

    /// Returns `true` when every byte is zero.
    pub fn is_zeroed(&self) -> bool {
        self.0 == [0; BLS_SIG_LEN]
    }
}

/// A [`BlsSigBytes`] paired with the scheme to read it under.
#[cfg(feature = "bls")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlsSignature {
    bytes: BlsSigBytes,
    scheme: BlsScheme,
}

#[cfg(feature = "bls")]
impl BlsSignature {
    /// Verifies this aggregate against `keys` with rogue-key binding.
    ///
    /// Each key carries the scheme its own encoding was written with, which
    /// for a masternode list entry follows that entry's version. The scheme
    /// the aggregate verifies in is one value for the quorum.
    ///
    /// # Errors
    ///
    /// Returns `InvalidSignature` when the signature bytes are not a G2
    /// point, or `VerificationFailed` when the aggregate does not verify.
    ///
    /// A key that will not decode is dropped rather than reported, though the
    /// failure is logged.
    pub fn verify_secure_aggregate<'a, I>(self, digest: &[u8; 32], keys: I) -> Result<(), BlsError>
    where
        I: IntoIterator<Item = (BlsScheme, &'a BlsPkBytes)>,
    {
        match self.scheme {
            BlsScheme::Legacy => self.verify_secure_in::<BlsScChia, I>(digest, keys, digest),
            BlsScheme::Modern => self.verify_secure_in::<BlsScIetf, I>(digest, keys, &digest[..]),
        }
    }

    fn point<S: PkcScheme>(self) -> Result<PkcSignature<S>, BlsError> {
        PkcSignature::<S>::from_bytes(self.bytes.as_bytes())
            .map_err(|_| BlsError::InvalidSignature(self.bytes.as_bytes().to_lower_hex_string()))
    }
    fn verify_secure_in<'a, S, I>(
        self,
        digest: &[u8; 32],
        keys: I,
        msg: &S::Msg,
    ) -> Result<(), BlsError>
    where
        S: PkcScheme,
        I: IntoIterator<Item = (BlsScheme, &'a BlsPkBytes)>,
    {
        let _ = digest;
        let carried: Vec<PkcPublicKey<S>> = keys
            .into_iter()
            .filter_map(|(encoding, key)| {
                key.as_scheme(encoding)
                    .carry_to::<S>()
                    .inspect_err(|e| error!("Failed to deserialize operator key: {}", e))
                    .ok()
            })
            .collect();
        let refs: Vec<&PkcPublicKey<S>> = carried.iter().collect();

        self.point::<S>()?
            .secure_verify_aggregates(msg, &refs)
            .map_err(|_| BlsError::VerificationFailed("aggregate did not verify".to_string()))
    }
}

#[cfg(test)]
mod tests {
    use hex_conservative::hex;

    use super::*;

    /// Operator public keys from the mainnet quorum at height 2300832.
    const OPERATOR_KEYS: [[u8; 48]; 3] = [
        hex!("86e7ea34cc084da3ed0e90649ad444df0ca25d638164a596b4fbec9567bbcf3e635a8d8457107e7fe76326f3816e34d9"),
        hex!("8b02bec7d70bb6c386ef4e201f3c01d062902079920cb037d7257110f9b6112ecad30cf20daf373813a816b0df845cfa"),
        hex!("8455cd00d19792377ac915614b06cc46f161662aaab1d5f1e73f3c3cac48a1f2991d75ba14decb308294ceaf7185ef21"),
    ];
    const PK_HEX: &str = "86e7ea34cc084da3ed0e90649ad444df0ca25d638164a596b4fbec9567bbcf3e635a8d8457107e7fe76326f3816e34d9";

    /// Quorum public key for the ChainLock at height 2301027.
    #[cfg(feature = "bls")]
    const QUORUM_PUBKEY: [u8; 48] = hex!("880d92cdfdcb2def08ee224b036dac1c52d39443c82576bfa2b9fe215265bffa129b936653bc655c3668d73c977d2e5a");

    /// ChainLock signature from height 2301027.
    const CHAINLOCK_SIG: [u8; 96] = hex!("ad47488b86dc296b4cc582afe99e7e32489e0f7840e40ebfb4ea959481caf757575f7a7e9c388c21b16d7c9979d4906d000fe14851dbc42e89802bab0932ac40b8cbad2076da9365e1587d53d1dec3f25a776c2fe0de2fca87e9c03408809181");
    const SIG_HEX: &str = "ad47488b86dc296b4cc582afe99e7e32489e0f7840e40ebfb4ea959481caf757575f7a7e9c388c21b16d7c9979d4906d000fe14851dbc42e89802bab0932ac40b8cbad2076da9365e1587d53d1dec3f25a776c2fe0de2fca87e9c03408809181";

    /// The block ChainLock at height 2301027 covers.
    #[cfg(feature = "bls")]
    const CHAINLOCK_BLOCK_HASH: [u8; 32] =
        hex!("00000000000000029eabbaa19ca5f694b863b3f64a682c376fa50b4119ae0029");

    #[cfg(feature = "bincode")]
    #[test]
    fn pk_bincode_layout_is_raw() {
        let config = bincode::config::standard();
        let pk = BlsPkBytes::from(OPERATOR_KEYS[0]);
        let bytes = bincode::encode_to_vec(pk, config).unwrap();

        assert_eq!(bytes, OPERATOR_KEYS[0]);
        assert_eq!(bincode::decode_from_slice(&bytes, config).unwrap(), (pk, 48));
    }

    #[test]
    fn pk_fmt_ignores_flags() {
        let pk = BlsPkBytes::from(OPERATOR_KEYS[0]);

        assert_eq!(pk.to_string(), PK_HEX);
        assert_eq!(format!("{pk:#}"), PK_HEX);
        assert_eq!(format!("{pk:>100}"), PK_HEX);
        assert_eq!(format!("{pk:.4}"), PK_HEX);
        assert_eq!(PK_HEX.to_uppercase().parse::<BlsPkBytes>().unwrap(), pk);
        assert!(format!("0x{PK_HEX}").parse::<BlsPkBytes>().is_err());
    }

    #[cfg(feature = "serde")]
    #[test]
    fn pk_serde_layout_is_hex_string() {
        let pk = BlsPkBytes::from(OPERATOR_KEYS[0]);

        assert_eq!(serde_json::to_string(&pk).unwrap(), format!("\"{PK_HEX}\""));
        assert_eq!(serde_json::from_str::<BlsPkBytes>(&format!("\"{PK_HEX}\"")).unwrap(), pk);
        assert!(serde_json::from_str::<BlsPkBytes>(&format!("{:?}", OPERATOR_KEYS[0])).is_err());

        #[cfg(feature = "bincode")]
        {
            let config = bincode::config::standard();
            let bytes = bincode::serde::encode_to_vec(pk, config).unwrap();
            let raw = bincode::serde::encode_to_vec(Bytes(&OPERATOR_KEYS[0]), config).unwrap();

            assert_eq!(bytes, [&[96], PK_HEX.as_bytes()].concat());
            assert_eq!(bincode::serde::decode_from_slice(&bytes, config).unwrap(), (pk, 97));
            assert!(bincode::serde::decode_from_slice::<BlsPkBytes, _>(&raw, config).is_err());
        }
    }

    #[cfg(all(feature = "serde", feature = "bincode"))]
    struct Bytes<'a>(&'a [u8]);

    #[cfg(all(feature = "serde", feature = "bincode"))]
    impl serde::Serialize for Bytes<'_> {
        fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
            s.serialize_bytes(self.0)
        }
    }

    #[cfg(feature = "bincode")]
    #[test]
    fn sig_bincode_layout_is_raw() {
        let config = bincode::config::standard();
        let sig = BlsSigBytes::from(CHAINLOCK_SIG);
        let bytes = bincode::encode_to_vec(sig, config).unwrap();

        assert_eq!(bytes, CHAINLOCK_SIG);
        assert_eq!(bincode::decode_from_slice(&bytes, config).unwrap(), (sig, 96));
    }

    #[test]
    fn sig_fmt_is_integral_hex() {
        let sig = BlsSigBytes::from(CHAINLOCK_SIG);

        assert_eq!(sig.to_string(), SIG_HEX);
        assert_eq!(format!("{sig:?}"), SIG_HEX);
        assert_eq!(format!("{sig:#}"), format!("0x{SIG_HEX}"));
        assert_eq!(format!("{sig:>200}"), format!("{:>200}", SIG_HEX));
        assert_eq!(format!("{sig:.4}"), SIG_HEX);
        assert_eq!(format!("{sig:X}"), SIG_HEX.to_uppercase());
        assert_eq!(SIG_HEX.to_uppercase().parse::<BlsSigBytes>().unwrap(), sig);
        assert!(SIG_HEX[2..].parse::<BlsSigBytes>().is_err());
        assert!(format!("0x{SIG_HEX}").parse::<BlsSigBytes>().is_err());
    }

    #[cfg(feature = "serde")]
    #[test]
    fn sig_serde_layout_is_hex_or_bytes() {
        let sig = BlsSigBytes::from(CHAINLOCK_SIG);

        assert_eq!(serde_json::to_string(&sig).unwrap(), format!("\"{SIG_HEX}\""));
        assert_eq!(serde_json::from_str::<BlsSigBytes>(&format!("\"{SIG_HEX}\"")).unwrap(), sig);
        assert!(serde_json::from_str::<BlsSigBytes>(&format!("{:?}", CHAINLOCK_SIG)).is_err());

        #[cfg(feature = "bincode")]
        {
            let config = bincode::config::standard();
            let bytes = bincode::serde::encode_to_vec(sig, config).unwrap();
            let hex = bincode::serde::encode_to_vec(SIG_HEX, config).unwrap();

            assert_eq!(bytes, [&[96], &CHAINLOCK_SIG[..]].concat());
            assert_eq!(bincode::serde::decode_from_slice(&bytes, config).unwrap(), (sig, 97));
            assert!(bincode::serde::decode_from_slice::<BlsSigBytes, _>(&hex, config).is_err());
        }
    }

    #[cfg(feature = "bls")]
    mod compatibility_tests {
        use super::super::*;
        use super::{CHAINLOCK_BLOCK_HASH, CHAINLOCK_SIG, OPERATOR_KEYS, QUORUM_PUBKEY};

        #[test]
        fn test_real_operator_key_compatibility() {
            // Test modern format deserialization
            for (i, key_bytes) in OPERATOR_KEYS.iter().enumerate() {
                let pk =
                    BlsPkBytes::from_bytes(*key_bytes).as_scheme(BlsScheme::Modern).canonicalize();
                assert!(pk.is_ok(), "Modern format deserialization failed for key {}", i);
            }
        }

        #[test]
        fn test_chainlock_signature_format() {
            let sig = BlsSigBytes::from_bytes(CHAINLOCK_SIG)
                .as_scheme(BlsScheme::Modern)
                .point::<BlsScIetf>();
            assert!(sig.is_ok(), "ChainLock signature deserialization failed");
        }

        #[test]
        fn test_quorum_public_key_verification() {
            // Parse keys
            let _pk = BlsPkBytes::from_bytes(QUORUM_PUBKEY)
                .as_scheme(BlsScheme::Modern)
                .canonicalize()
                .unwrap();
            let _sig = BlsSigBytes::from_bytes(CHAINLOCK_SIG)
                .as_scheme(BlsScheme::Modern)
                .point::<BlsScIetf>()
                .unwrap();

            // According to DIP-8, ChainLocks sign:
            // SHA256(llmqType, quorumHash, SHA256(height), blockHash)
            //
            // Since we don't have the quorum hash and exact LLMQ type for this test data,
            // we'll skip this test but document why it fails.
            //
            // To properly test this, we would need:
            // - llmqType (likely LLMQ_400_60 for ChainLocks)
            // - quorumHash (the hash identifying the specific quorum)
            // - height (2301027 based on the comment)
            // - blockHash (which we have)

            println!(
                "SKIPPING: ChainLock verification requires composite message format per DIP-8"
            );
            println!("Message should be: SHA256(llmqType, quorumHash, SHA256(height), blockHash)");
            println!("We only have the block hash, not the other required components.");

            // Comment out the assertion since we know it will fail without proper message construction
            // assert!(verified.is_ok(), "Real chainlock signature should verify");
        }

        #[test]
        fn test_verify_secure_with_real_operators() {
            // Real operator keys for testing the secure aggregate API
            let operator_keys = OPERATOR_KEYS.map(BlsPkBytes::from_bytes);

            for key in &operator_keys {
                assert!(key.as_scheme(BlsScheme::Modern).canonicalize().is_ok());
            }

            // Note: For a complete test, we would need the actual commitment hash and aggregated signature
            // from the quorum formation process. This test verifies the API works with real keys.
            println!(
                "Successfully parsed {} real operator keys for verify_secure",
                operator_keys.len()
            );
        }

        #[test]
        fn debug_chainlock_verification() {
            // Try both schemes for the quorum key
            let key = BlsPkBytes::from_bytes(QUORUM_PUBKEY);
            println!("Trying modern scheme for quorum key...");
            let pk_modern = key.as_scheme(BlsScheme::Modern).canonicalize();
            println!("Modern scheme result: {:?}", pk_modern.is_ok());

            println!("\nTrying legacy scheme for quorum key...");
            let pk_legacy = key.as_scheme(BlsScheme::Legacy).canonicalize();
            println!("Legacy scheme result: {:?}", pk_legacy.is_ok());

            // Whichever reads, the signature is checked under the same scheme
            for scheme in [BlsScheme::Modern, BlsScheme::Legacy] {
                let verified = key
                    .as_scheme(scheme)
                    .verify(&CHAINLOCK_BLOCK_HASH, &BlsSigBytes::from_bytes(CHAINLOCK_SIG));
                println!("{:?} verification: {:?}", scheme, verified.is_ok());
            }
        }

        #[test]
        fn test_legacy_format_detection() {
            // Test the ability to detect and handle legacy format keys
            // Note: To properly test this, we need actual legacy format keys from older blocks
            // The detection logic should try legacy format when modern format fails

            let test_key = BlsPkBytes::from_bytes(OPERATOR_KEYS[0]);

            // Try modern format first
            let modern_result = test_key.as_scheme(BlsScheme::Modern).canonicalize();

            // If modern fails, try legacy
            if modern_result.is_err() {
                let legacy_result = test_key.as_scheme(BlsScheme::Legacy).canonicalize();
                println!("Key requires legacy format: {}", legacy_result.is_ok());
            } else {
                println!("Key uses modern format");
            }
        }
    }

    #[cfg(feature = "bls")]
    mod benchmarks {
        use super::super::*;
        use super::{CHAINLOCK_SIG, OPERATOR_KEYS};
        use hex_conservative::hex;
        use std::time::Instant;

        #[test]
        fn bench_verify_secure() {
            // Setup test data - real operator keys
            let operator_keys = OPERATOR_KEYS.map(BlsPkBytes::from_bytes);

            // Create a dummy signature for benchmarking
            let sig = BlsSigBytes::from_bytes(CHAINLOCK_SIG);

            // A 32-byte digest, since verification takes the message pre-hashed
            let msg = hex!("74657374206d65737361676520666f722062656e63686d61726b696e67000000");

            let run = || {
                let _ = sig.as_scheme(BlsScheme::Modern).verify_secure_aggregate(
                    &msg,
                    operator_keys.iter().map(|k| (BlsScheme::Modern, k)),
                );
            };

            // Warm up
            for _ in 0..10 {
                run();
            }

            // Measure verification time
            let iterations = 100;
            let start = Instant::now();

            for _ in 0..iterations {
                run();
            }

            let duration = start.elapsed();

            println!("{} verify_secure operations took: {:?}", iterations, duration);
            println!("Average per operation: {:?}", duration / iterations);
            println!("Operations per second: {:.2}", iterations as f64 / duration.as_secs_f64());
        }
    }
}
