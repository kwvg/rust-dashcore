//! Extended BLS public keys.

use core::fmt;
use dashcore_hashes::{sha256, Hash, HashEngine, Hmac, HmacEngine};

use dashcore::Network;

use crate::bip32::{ChainCode, ChildNumber, DerivationPath, Fingerprint};
use crate::bls::hd::{BlsDerivationMode, BlsPublicKey, BlsSecretKey, Error, ExtendedBLSPrivKey};

/// Extended BLS public key for HD derivation
#[derive(Clone)]
pub struct ExtendedBLSPubKey {
    /// Network this key is for
    pub network: Network,
    /// Depth in the HD tree
    pub depth: u8,
    /// Parent key fingerprint
    pub parent_fingerprint: Fingerprint,
    /// Child number
    pub child_number: ChildNumber,
    /// Public key (BLS G2 element - 48 bytes)
    pub public_key: BlsPublicKey,
    /// Chain code for derivation
    pub chain_code: ChainCode,
}

impl ExtendedBLSPubKey {
    /// Create from a private key
    pub fn from_private_key(priv_key: &ExtendedBLSPrivKey) -> Self {
        ExtendedBLSPubKey {
            network: priv_key.network,
            depth: priv_key.depth,
            parent_fingerprint: priv_key.parent_fingerprint,
            child_number: priv_key.child_number,
            public_key: priv_key.public_key(),
            chain_code: priv_key.chain_code,
        }
    }

    /// Derive a child public key using the modern (IETF) serialization mode
    /// (only for non-hardened derivation).
    pub fn ckd_pub(&self, child: ChildNumber) -> Result<Self, Error> {
        self.derive_pub(child)
    }

    /// Derive a child public key using the modern (IETF) public key
    /// serialization (only for non-hardened derivation).
    ///
    /// Equivalent to dashbls `PublicChild(i)` with the default
    /// `fLegacy = false`. For Dash masternode operator keys use
    /// [`Self::derive_pub_legacy`], which matches DashSync.
    pub fn derive_pub(&self, child: ChildNumber) -> Result<Self, Error> {
        self.derive_pub_with_mode(child, BlsDerivationMode::Modern)
    }

    /// Derive a child public key using the legacy Dash public key
    /// serialization (only for non-hardened derivation).
    ///
    /// Equivalent to dashbls `PublicChild(i, fLegacy = true)` — the mode
    /// dashbls/DashSync use for masternode operator keys.
    pub fn derive_pub_legacy(&self, child: ChildNumber) -> Result<Self, Error> {
        self.derive_pub_with_mode(child, BlsDerivationMode::Legacy)
    }

    /// Derive a child public key with an explicit serialization mode
    /// (only for non-hardened derivation).
    pub fn derive_pub_with_mode(
        &self,
        child: ChildNumber,
        format: BlsDerivationMode,
    ) -> Result<Self, Error> {
        if child.is_hardened() {
            return Err(Error::CannotDeriveFromHardenedPublic);
        }

        // Build the input data for HMAC: public_key || index — matches
        // dashbls `ExtendedPublicKey::PublicChild`, whose fLegacy flag
        // corresponds to `format`.
        let mut input_data = Vec::new();
        input_data.extend_from_slice(&self.public_key.to_bytes_with_mode(format));
        let child_bytes = u32::from(child).to_be_bytes();
        input_data.extend_from_slice(&child_bytes);

        // First HMAC-SHA256 with suffix 0 for the tweak
        let mut input_with_suffix = input_data.clone();
        input_with_suffix.push(0);

        let mut hmac_engine: HmacEngine<sha256::Hash> = HmacEngine::new(&self.chain_code[..]);
        hmac_engine.input(&input_with_suffix);
        let hmac_result: Hmac<sha256::Hash> = Hmac::from_engine(hmac_engine);
        let tweak_bytes = hmac_result.as_byte_array();

        // Second HMAC-SHA256 with suffix 1 for the chain code
        input_with_suffix[input_data.len()] = 1;

        let mut hmac_engine2: HmacEngine<sha256::Hash> = HmacEngine::new(&self.chain_code[..]);
        hmac_engine2.input(&input_with_suffix);
        let hmac_result2: Hmac<sha256::Hash> = Hmac::from_engine(hmac_engine2);
        let chain_code_bytes = hmac_result2.as_byte_array();

        // For BLS public key derivation, we need to do elliptic curve point addition
        // First, convert the tweak bytes to a scalar (private key)
        let tweak_privkey =
            BlsSecretKey::from_be_bytes_reduce(tweak_bytes).ok_or(Error::InvalidPrivateKey)?;

        // Convert the scalar to a public key point (scalar * G where G is the generator)
        let tweak_pubkey = tweak_privkey.public_key();

        // Perform elliptic curve point addition
        let derived_pubkey = self.public_key.add(&tweak_pubkey);

        Ok(ExtendedBLSPubKey {
            network: self.network,
            depth: self.depth + 1,
            parent_fingerprint: self.fingerprint(),
            child_number: child,
            public_key: derived_pubkey,
            chain_code: ChainCode::from(*chain_code_bytes),
        })
    }

    /// Get the fingerprint of this key
    pub fn fingerprint(&self) -> Fingerprint {
        use dashcore_hashes::hash160;
        let public_key_bytes = self.public_key.to_bytes();
        let hash = hash160::Hash::hash(&public_key_bytes);
        let mut fingerprint_bytes = [0u8; 4];
        fingerprint_bytes.copy_from_slice(&hash.as_byte_array()[..4]);
        Fingerprint::from_bytes(fingerprint_bytes)
    }

    /// Get the public key bytes (modern/IETF serialization)
    pub fn to_bytes(&self) -> [u8; 48] {
        let bytes = self.public_key.to_bytes();
        let mut array = [0u8; 48];
        array.copy_from_slice(&bytes[..48.min(bytes.len())]);
        array
    }

    /// Get the public key bytes in Dash legacy serialization.
    ///
    /// This is the format dashbls/DashSync use throughout the BLS HD chain.
    pub fn to_bytes_legacy(&self) -> [u8; 48] {
        let bytes = self.public_key.to_bytes_with_mode(BlsDerivationMode::Legacy);
        let mut array = [0u8; 48];
        array.copy_from_slice(&bytes[..48.min(bytes.len())]);
        array
    }

    /// Derive at a path using the modern (IETF) serialization mode
    /// (only non-hardened paths allowed; see [`Self::derive_pub`]).
    pub fn derive_path(&self, path: &DerivationPath) -> Result<Self, Error> {
        self.derive_path_with_mode(path, BlsDerivationMode::Modern)
    }

    /// Derive at a path using the legacy Dash serialization mode
    /// (only non-hardened paths allowed; see [`Self::derive_pub_legacy`]).
    pub fn derive_path_legacy(&self, path: &DerivationPath) -> Result<Self, Error> {
        self.derive_path_with_mode(path, BlsDerivationMode::Legacy)
    }

    /// Derive at a path with an explicit serialization mode
    /// (only non-hardened paths allowed).
    pub fn derive_path_with_mode(
        &self,
        path: &DerivationPath,
        format: BlsDerivationMode,
    ) -> Result<Self, Error> {
        let mut key = self.clone();
        for child in path.as_ref() {
            key = key.derive_pub_with_mode(*child, format)?;
        }
        Ok(key)
    }
}

impl fmt::Debug for ExtendedBLSPubKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("ExtendedBLSPubKey")
            .field("network", &self.network)
            .field("depth", &self.depth)
            .field("parent_fingerprint", &self.parent_fingerprint)
            .field("child_number", &self.child_number)
            .field("chain_code", &self.chain_code)
            .field("public_key", &hex::encode(self.public_key.to_bytes()))
            .finish()
    }
}
