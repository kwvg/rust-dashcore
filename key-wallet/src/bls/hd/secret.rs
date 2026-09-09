//! Extended BLS secret keys.

use core::fmt;
use dashcore_hashes::{sha256, Hash, HashEngine, Hmac, HmacEngine};

// NOTE: We use Bls12381G2Impl for BLS keys (48-byte public keys)
use dashcore::blsful::SerializationFormat;
use dashcore::blsful::{Bls12381G2Impl, PublicKey as BlsPublicKey, SecretKey as BlsSecretKey};

use dashcore::Network;

use crate::bip32::{ChainCode, ChildNumber, DerivationPath, Fingerprint};
use crate::bls::hd::{Error, ExtendedBLSPubKey};

/// Extended BLS private key for HD derivation
#[derive(Clone)]
pub struct ExtendedBLSPrivKey {
    /// Network this key is for
    pub network: Network,
    /// Depth in the HD tree
    pub depth: u8,
    /// Parent key fingerprint
    pub parent_fingerprint: Fingerprint,
    /// Child number
    pub child_number: ChildNumber,
    /// Private key (BLS secret key)
    pub private_key: BlsSecretKey<Bls12381G2Impl>,
    /// Chain code for derivation
    pub chain_code: ChainCode,
}

// Hand-written (not `#[derive(Zeroize)]`): `BlsSecretKey` has no `Zeroize`
// impl of its own, but its inner scalar (public field `0`) does, so we wipe
// the value field by field. `Drop` (below) calls this, so the key is wiped
// automatically on scope exit with no caller action required.
// Cf. `ExtendedPrivKey` in `bip32`.
impl zeroize::Zeroize for ExtendedBLSPrivKey {
    fn zeroize(&mut self) {
        // Secret key material.
        self.private_key.0.zeroize();
        self.chain_code.zeroize();
        // Derivation metadata — cleared too so the whole value is wiped.
        self.depth.zeroize();
        self.parent_fingerprint.zeroize();
        self.child_number = ChildNumber::Normal {
            index: 0,
        };
        self.network = Network::Mainnet; // repr(u8)=0 discriminant, the "zero" value
    }
}

impl Drop for ExtendedBLSPrivKey {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.zeroize();
    }
}

impl ExtendedBLSPrivKey {
    /// Create a new master key from a seed
    pub fn new_master(network: Network, seed: &[u8]) -> Result<Self, Error> {
        // Allow shorter seeds for testing compatibility with C++ implementation
        // In production, seeds should be at least 16 bytes for security
        #[cfg(not(test))]
        if seed.len() < 16 || seed.len() > 64 {
            return Err(Error::InvalidSeed);
        }
        #[cfg(test)]
        if seed.len() < 8 || seed.len() > 64 {
            return Err(Error::InvalidSeed);
        }

        // Following the bls-signatures C++ implementation:
        // They do two separate HMAC-SHA256 operations with different suffixes

        // First HMAC with seed||0 for the private key
        let mut seed_with_suffix = Vec::with_capacity(seed.len() + 1);
        seed_with_suffix.extend_from_slice(seed);
        seed_with_suffix.push(0);

        let mut hmac_engine: HmacEngine<sha256::Hash> = HmacEngine::new(b"BLS HD seed");
        hmac_engine.input(&seed_with_suffix);
        let hmac_result: Hmac<sha256::Hash> = Hmac::from_engine(hmac_engine);
        let private_key_bytes = hmac_result.as_byte_array();

        // #[cfg(test)]
        // {
        //     eprintln!("Seed length: {}", seed.len());
        //     eprintln!("Seed||0 (hex): {}", hex::encode(&seed_with_suffix));
        //     eprintln!("HMAC output (hex): {}", hex::encode(private_key_bytes));
        // }

        // The C++ implementation does modulo reduction by curve order
        // We need to do the same before converting to BLS private key
        let private_key = BlsSecretKey::<Bls12381G2Impl>::from_be_bytes(private_key_bytes)
            .into_option()
            .ok_or(Error::InvalidPrivateKey)?;

        // #[cfg(test)]
        // {
        //     eprintln!("After from_be_bytes (hex): {}", hex::encode(private_key.to_be_bytes()));
        // }

        // Second HMAC with seed||1 for the chain code
        seed_with_suffix[seed.len()] = 1;

        let mut hmac_engine2: HmacEngine<sha256::Hash> = HmacEngine::new(b"BLS HD seed");
        hmac_engine2.input(&seed_with_suffix);
        let hmac_result2: Hmac<sha256::Hash> = Hmac::from_engine(hmac_engine2);
        let chain_code_bytes = hmac_result2.as_byte_array();

        Ok(ExtendedBLSPrivKey {
            network,
            depth: 0,
            parent_fingerprint: Default::default(),
            child_number: ChildNumber::from_normal_idx(0).unwrap(),
            private_key,
            chain_code: ChainCode::from(*chain_code_bytes),
        })
    }

    /// Derive a child private key using the modern (IETF) public key
    /// serialization for non-hardened children.
    ///
    /// Equivalent to dashbls `PrivateChild(i)` with the default
    /// `fLegacy = false`. For Dash masternode operator keys use
    /// [`Self::derive_priv_legacy`], which matches DashSync.
    pub fn derive_priv(&self, child: ChildNumber) -> Result<Self, Error> {
        self.derive_priv_with_mode(child, SerializationFormat::Modern)
    }

    /// Derive a child private key using the legacy Dash public key
    /// serialization for non-hardened children.
    ///
    /// Equivalent to dashbls `PrivateChild(i, fLegacy = true)` — the mode
    /// dashbls/DashSync use for masternode operator keys.
    pub fn derive_priv_legacy(&self, child: ChildNumber) -> Result<Self, Error> {
        self.derive_priv_with_mode(child, SerializationFormat::Legacy)
    }

    /// Derive a child private key with an explicit serialization mode.
    ///
    /// The mode selects the G1 serialization of the parent public key in the
    /// HMAC input for non-hardened children; hardened derivation never
    /// serializes the public key, so both modes agree there.
    pub fn derive_priv_with_mode(
        &self,
        child: ChildNumber,
        format: SerializationFormat,
    ) -> Result<Self, Error> {
        // Build the input data for HMAC, following dashbls
        // `ExtendedPrivateKey::PrivateChild` (extendedprivatekey.cpp)
        let mut input_data = Vec::new();

        if child.is_hardened() {
            // Hardened derivation: private_key || index
            // (no leading 0x00 — that prefix belongs to secp256k1 BIP32,
            // where it pads the 33-byte pubkey slot; dashbls doesn't use it)
            input_data.extend_from_slice(&self.private_key.to_be_bytes());
        } else {
            // Non-hardened derivation: public_key || index
            input_data.extend_from_slice(&self.public_key().to_bytes_with_mode(format));
        }
        let child_bytes = u32::from(child).to_be_bytes();
        input_data.extend_from_slice(&child_bytes);

        // First HMAC-SHA256 with suffix 0 for the private key
        let mut input_with_suffix = input_data.clone();
        input_with_suffix.push(0);

        let mut hmac_engine: HmacEngine<sha256::Hash> = HmacEngine::new(&self.chain_code[..]);
        hmac_engine.input(&input_with_suffix);
        let hmac_result: Hmac<sha256::Hash> = Hmac::from_engine(hmac_engine);
        let key_bytes = hmac_result.as_byte_array();

        // Second HMAC-SHA256 with suffix 1 for the chain code
        input_with_suffix[input_data.len()] = 1;

        let mut hmac_engine2: HmacEngine<sha256::Hash> = HmacEngine::new(&self.chain_code[..]);
        hmac_engine2.input(&input_with_suffix);
        let hmac_result2: Hmac<sha256::Hash> = Hmac::from_engine(hmac_engine2);
        let chain_code_bytes = hmac_result2.as_byte_array();

        // Derive the new private key using proper scalar field arithmetic
        let derived_private_key = {
            // Convert tweak to secret key
            let tweak_key = BlsSecretKey::<Bls12381G2Impl>::from_be_bytes(key_bytes)
                .into_option()
                .ok_or(Error::InvalidPrivateKey)?;

            // Perform scalar addition in the BLS12-381 field
            // The SecretKey struct has a public field (0) containing the scalar
            // We add the scalars and create a new SecretKey from the result
            let parent_scalar = self.private_key.0;
            let tweak_scalar = tweak_key.0;
            let derived_scalar = parent_scalar + tweak_scalar;

            BlsSecretKey::<Bls12381G2Impl>(derived_scalar)
        };

        Ok(ExtendedBLSPrivKey {
            network: self.network,
            depth: self.depth + 1,
            parent_fingerprint: self.fingerprint(),
            child_number: child,
            private_key: derived_private_key,
            chain_code: ChainCode::from(*chain_code_bytes),
        })
    }

    /// Get the public key for this private key
    pub fn public_key(&self) -> BlsPublicKey<Bls12381G2Impl> {
        BlsPublicKey::from(&self.private_key)
    }

    /// Get the public key bytes (modern/IETF serialization)
    pub fn public_key_bytes(&self) -> [u8; 48] {
        let bytes = self.public_key().to_bytes();
        let mut array = [0u8; 48];
        array.copy_from_slice(&bytes[..48.min(bytes.len())]);
        array
    }

    /// Get the public key bytes in Dash legacy serialization.
    ///
    /// This is the format dashbls/DashSync use throughout the BLS HD chain.
    pub fn public_key_bytes_legacy(&self) -> [u8; 48] {
        let bytes = self.public_key().to_bytes_with_mode(SerializationFormat::Legacy);
        let mut array = [0u8; 48];
        array.copy_from_slice(&bytes[..48.min(bytes.len())]);
        array
    }

    /// Get the fingerprint of this key
    pub fn fingerprint(&self) -> Fingerprint {
        use dashcore_hashes::hash160;
        let public_key_bytes = self.public_key_bytes();
        let hash = hash160::Hash::hash(&public_key_bytes);
        let mut fingerprint_bytes = [0u8; 4];
        fingerprint_bytes.copy_from_slice(&hash[..4]);
        Fingerprint::from_bytes(fingerprint_bytes)
    }

    /// Get the extended public key
    pub fn to_extended_pub_key(&self) -> ExtendedBLSPubKey {
        ExtendedBLSPubKey {
            network: self.network,
            depth: self.depth,
            parent_fingerprint: self.parent_fingerprint,
            child_number: self.child_number,
            public_key: self.public_key(),
            chain_code: self.chain_code,
        }
    }

    /// Derive at a path using the modern (IETF) serialization mode
    /// (see [`Self::derive_priv`]).
    pub fn derive_path(&self, path: &DerivationPath) -> Result<Self, Error> {
        self.derive_path_with_mode(path, SerializationFormat::Modern)
    }

    /// Derive at a path using the legacy Dash serialization mode
    /// (see [`Self::derive_priv_legacy`]).
    pub fn derive_path_legacy(&self, path: &DerivationPath) -> Result<Self, Error> {
        self.derive_path_with_mode(path, SerializationFormat::Legacy)
    }

    /// Derive at a path with an explicit serialization mode.
    pub fn derive_path_with_mode(
        &self,
        path: &DerivationPath,
        format: SerializationFormat,
    ) -> Result<Self, Error> {
        let mut key = self.clone();
        for child in path.as_ref() {
            key = key.derive_priv_with_mode(*child, format)?;
        }
        Ok(key)
    }
}

impl fmt::Debug for ExtendedBLSPrivKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("ExtendedBLSPrivKey")
            .field("network", &self.network)
            .field("depth", &self.depth)
            .field("parent_fingerprint", &self.parent_fingerprint)
            .field("child_number", &self.child_number)
            .field("chain_code", &self.chain_code)
            .field("private_key", &"[REDACTED]")
            .finish()
    }
}
