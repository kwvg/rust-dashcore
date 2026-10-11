//
// This file is a part of rust-dashcore.
// SPDX-License-Identifier: CC0-1.0
// See the accompanying file LICENSE or https://creativecommons.org/publicdomain/zero/1.0
//

//! Ed25519 keys for Platform node identity.

#[cfg(feature = "bincode")]
use bincode_derive::{Decode, Encode};
#[cfg(feature = "eddsa")]
pub use dash_pkc::eddsa::{EddsaError, EddsaPublicKey, EddsaSecretKey};
pub use dash_pkc::eddsa::{EddsaPkBytes, EddsaSkBytes, EDDSA_PK_LEN, EDDSA_SK_LEN};
use dash_types::type_cvrt;
use dashcore_hashes::{sha256, Hash};
use internals::{impl_array_newtype, impl_bytes_newtype};

/// Ed25519 public key hash length.
pub const EDDSA_PK_HASH_LEN: usize = 20;

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
