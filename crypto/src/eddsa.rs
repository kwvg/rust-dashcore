//
// This file is a part of rust-dashcore.
// SPDX-License-Identifier: CC0-1.0
// See the accompanying file LICENSE or https://creativecommons.org/publicdomain/zero/1.0
//

//! Ed25519 keys for Platform node identity.

use core::fmt;

#[cfg(feature = "bincode")]
use bincode_derive::{Decode, Encode};
use dash_pkc::eddsa::{EddsaPkBytes as PkcPkBytes, EddsaSkBytes as PkcSkBytes};
#[cfg(feature = "eddsa")]
use dash_pkc::eddsa::{EddsaPublicKey as PkcPublicKey, EddsaSecretKey as PkcSecretKey};
use dash_types::type_cvrt;
use dashcore_hashes::{sha256, Hash};
use delegate::delegate;
use hex_conservative::DisplayHex;
use internals::{debug_from_display, impl_array_newtype, impl_bytes_newtype};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

pub use dash_pkc::eddsa::EddsaError;

/// Ed25519 public key length.
pub const EDDSA_PK_LEN: usize = 32;

/// Ed25519 secret key seed length.
pub const EDDSA_SK_LEN: usize = 32;

/// Ed25519 public key hash length.
pub const EDDSA_PK_HASH_LEN: usize = 20;

/// Ed25519 public key bytes (32 bytes, unvalidated).
#[derive(Clone, Copy, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct EddsaPkBytes(PkcPkBytes);

impl EddsaPkBytes {
    delegate! {
        to PkcPkBytes {
            /// Wraps raw bytes without validation.
            #[expr(Self($))]
            pub fn from_bytes(bytes: [u8; EDDSA_PK_LEN]) -> Self;
        }
        to self.0 {
            /// Borrows the inner byte array.
            pub fn as_bytes(&self) -> &[u8; EDDSA_PK_LEN];

            /// Copies out the inner byte array.
            pub fn to_bytes(&self) -> [u8; EDDSA_PK_LEN];
        }
    }
}

debug_from_display!(EddsaPkBytes);

/// Hex of the 32 bytes.
impl fmt::Display for EddsaPkBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:x}", self.as_bytes().as_hex())
    }
}

/// Ed25519 secret key seed (32 bytes).
#[derive(Clone, Eq, PartialEq)]
pub struct EddsaSkBytes(PkcSkBytes);

impl EddsaSkBytes {
    delegate! {
        to PkcSkBytes {
            /// Wraps a seed.
            #[expr(Self($))]
            pub fn from_bytes(bytes: [u8; EDDSA_SK_LEN]) -> Self;
        }
        to self.0 {
            /// Borrows the seed.
            pub fn as_bytes(&self) -> &[u8; EDDSA_SK_LEN];

            /// Copies out the seed, wiped on drop.
            pub fn to_bytes(&self) -> Zeroizing<[u8; EDDSA_SK_LEN]>;
        }
    }
}

impl fmt::Debug for EddsaSkBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("EddsaSkBytes(..)")
    }
}

impl Zeroize for EddsaSkBytes {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl ZeroizeOnDrop for EddsaSkBytes {}

/// An Ed25519 public key.
#[cfg(feature = "eddsa")]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct EddsaPublicKey(PkcPublicKey);

#[cfg(feature = "eddsa")]
impl EddsaPublicKey {
    delegate! {
        to self.0 {
            /// The 32-byte encoding.
            pub fn to_bytes(&self) -> [u8; EDDSA_PK_LEN];
        }
    }
}

#[cfg(feature = "eddsa")]
type_cvrt!(From<EddsaPublicKey> for EddsaPkBytes, |pk| Self(pk.0.into()));
#[cfg(feature = "eddsa")]
type_cvrt!(TryFrom<EddsaPkBytes> for EddsaPublicKey, EddsaError, |pk| {
    PkcPublicKey::try_from(&pk.0).map(Self)
});

/// An Ed25519 secret key.
#[cfg(feature = "eddsa")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EddsaSecretKey(PkcSecretKey);

#[cfg(feature = "eddsa")]
impl EddsaSecretKey {
    delegate! {
        to self.0 {
            /// Derives the corresponding public key.
            #[expr(EddsaPublicKey($))]
            pub fn public_key(&self) -> EddsaPublicKey;
        }
    }
}

#[cfg(feature = "eddsa")]
type_cvrt!(From<EddsaSkBytes> for EddsaSecretKey, |sk| Self(PkcSecretKey::from(&sk.0)));
#[cfg(feature = "eddsa")]
type_cvrt!(From<EddsaSecretKey> for EddsaSkBytes, |sk| Self(PkcSkBytes::from(&sk.0)));

/// Ed25519 public key hash, in canonical (i.e. Tenderdash) order.
#[derive(Clone, Copy, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[cfg_attr(feature = "bincode", derive(Encode, Decode))]
pub struct EddsaPkHash([u8; EDDSA_PK_HASH_LEN]);

impl_array_newtype!(EddsaPkHash, u8, EDDSA_PK_HASH_LEN);
impl_bytes_newtype!(EddsaPkHash, EDDSA_PK_HASH_LEN);

impl EddsaPkHash {
    /// Wraps the canonical order bytes.
    pub const fn from_byte_array(bytes: [u8; EDDSA_PK_HASH_LEN]) -> Self {
        Self(bytes)
    }

    /// Copies out the canonical order bytes.
    pub const fn to_byte_array(self) -> [u8; EDDSA_PK_HASH_LEN] {
        self.0
    }

    /// Borrows the canonical order bytes.
    pub const fn as_byte_array(&self) -> &[u8; EDDSA_PK_HASH_LEN] {
        &self.0
    }

    /// Hashes an Ed25519 public key as `SHA256(public_key)[..20]`.
    pub fn from_ed25519_public_key(public_key: &[u8; EDDSA_PK_LEN]) -> Self {
        let digest = sha256::Hash::hash(public_key).to_byte_array();
        let mut bytes = [0u8; EDDSA_PK_HASH_LEN];
        bytes.copy_from_slice(&digest[..EDDSA_PK_HASH_LEN]);
        Self(bytes)
    }
}

type_cvrt!(From<EddsaPkBytes> for EddsaPkHash, |pk| Self::from_ed25519_public_key(pk.as_bytes()));

#[cfg(test)]
mod tests {
    use hex_conservative::hex;

    use super::*;

    const CANONICAL: [u8; EDDSA_PK_HASH_LEN] = hex!("68794393a374954b56d3634a81f418a49779b98c");
    const CANONICAL_HEX: &str = "68794393a374954b56d3634a81f418a49779b98c";

    #[cfg(feature = "bincode")]
    #[test]
    fn bincode_layout_is_canonical() {
        use crate::key::PubkeyHash;

        let config = bincode::config::standard();
        let hash = EddsaPkHash::from_byte_array(CANONICAL);
        let bytes = bincode::encode_to_vec(hash, config).unwrap();
        let pubkey_hash = PubkeyHash::from_byte_array(CANONICAL);

        assert_eq!(bytes, CANONICAL);
        assert_eq!(bytes, bincode::encode_to_vec(pubkey_hash, config).unwrap());
        assert_eq!(bincode::decode_from_slice(&bytes, config).unwrap(), (hash, bytes.len()));
    }

    #[test]
    fn fmt_layout_is_canonical_hex() {
        let hash = EddsaPkHash::from_byte_array(CANONICAL);

        assert_eq!(hash.to_string(), CANONICAL_HEX);
        assert_eq!(format!("{hash:?}"), CANONICAL_HEX);
        assert_eq!(format!("{hash:#}"), format!("0x{CANONICAL_HEX}"));
        assert_eq!(CANONICAL_HEX.parse::<EddsaPkHash>().unwrap(), hash);
        assert!("abcd".parse::<EddsaPkHash>().is_err());
        assert!("zz".repeat(20).parse::<EddsaPkHash>().is_err());
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_layout_is_canonical() {
        let hash = EddsaPkHash::from_byte_array(CANONICAL);
        let json = serde_json::to_string(&hash).unwrap();

        assert_eq!(json, format!("\"{CANONICAL_HEX}\""));
        assert_eq!(serde_json::from_str::<EddsaPkHash>(&json).unwrap(), hash);

        #[cfg(feature = "bincode")]
        {
            let config = bincode::config::standard();
            let bytes = bincode::serde::encode_to_vec(hash, config).unwrap();

            assert_eq!(bytes, [&[20], &CANONICAL[..]].concat());
            assert_eq!(
                bincode::serde::decode_from_slice(&bytes, config).unwrap(),
                (hash, bytes.len())
            );
        }
    }

    #[test]
    fn hash_is_truncated_sha256() {
        let public_key = [7u8; EDDSA_PK_LEN];
        let digest = sha256::Hash::hash(&public_key).to_byte_array();
        let hash = EddsaPkHash::from_ed25519_public_key(&public_key);

        assert_eq!(hash.as_byte_array()[..], digest[..EDDSA_PK_HASH_LEN]);
        assert_eq!(EddsaPkHash::from(EddsaPkBytes::from_bytes(public_key)), hash);
    }
}
