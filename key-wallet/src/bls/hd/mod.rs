//! BIP32-like implementation for BLS12-381.
//!
//! Implementation of hierarchical deterministic wallets for BLS12-381,
//! matching the dashbls (`bls-signatures`) `ExtendedPrivateKey` /
//! `ExtendedPublicKey` scheme used by Dash Core and DashSync for masternode
//! operator keys (DIP-3 `m/9'/coin'/3'/3'`).
//!
//! Key differences from standard BIP32:
//! - Uses BLS12-381 curve instead of secp256k1
//! - Keys are 32 bytes (private) and 48 bytes (public)
//! - Uses "BLS HD seed" as the HMAC key for master key generation
//! - Supports both hardened and non-hardened derivation
//! - Hardened child HMAC input is `sk(32) || index(4 BE) || {0,1}` — unlike
//!   secp256k1 BIP32 there is **no** leading `0x00` byte
//!
//! # Serialization modes
//!
//! Non-hardened derivation feeds the parent public key into the HMAC, so the
//! G1 serialization format is part of the derivation itself — dashbls
//! parameterizes it as `fLegacy`. Both modes are supported, mirroring dashbls:
//!
//! - [`ExtendedBLSPrivKey::derive_priv`] / [`ExtendedBLSPubKey::derive_pub`]
//!   use the **modern** (IETF/basic-scheme) serialization, like dashbls
//!   `PrivateChild(i)` with the default `fLegacy = false`.
//! - [`ExtendedBLSPrivKey::derive_priv_legacy`] /
//!   [`ExtendedBLSPubKey::derive_pub_legacy`] use the **legacy** Dash
//!   serialization (`fLegacy = true`). This is what dashbls/DashSync use for
//!   masternode operator keys (DIP-3 `m/9'/coin'/3'/3'`), so the provider-key
//!   account layer derives with these.
//! - The `*_with_mode` variants take an explicit [`SerializationFormat`].
//!
//! Hardened derivation never serializes the public key, so the mode only
//! matters for non-hardened children. Output serialization is likewise
//! available in both formats ([`ExtendedBLSPubKey::to_bytes`] /
//! [`ExtendedBLSPubKey::to_bytes_legacy`]).

mod backend;
mod codec;
mod error;
mod public;
mod secret;

pub use backend::{BlsDerivationMode, BlsPublicKey, BlsSecretKey};
pub use error::Error;
pub use public::ExtendedBLSPubKey;
pub use secret::ExtendedBLSPrivKey;

#[cfg(test)]
mod tests;
