//! BIP38 password-protected private key encryption
//!
//! This module implements BIP38, which provides a standard way to encrypt
//! private keys with a password using scrypt for key derivation and AES for encryption.
//!
//! BIP38 supports two modes:
//! 1. Non-EC-multiply mode: Simple encryption of existing private keys
//! 2. EC-multiply mode: Generate encrypted keys without knowing the private key
//!
//! Format of encrypted keys:
//! - Prefix: 0x0142 for non-EC-multiply mode (base58 starts with "6P")
//! - Prefix: 0x0143 for EC-multiply mode (base58 starts with "6P")

use core::fmt;

use crate::error::{Error, Result};
use crate::Network;
use dashcore::{Address, PrivateKey};

use dashcore_hashes::{sha256d, Hash};
use secp256k1::{PublicKey, SecretKey};
use unicode_normalization::UnicodeNormalization;

// BIP38 constants
const BIP38_PREFIX_NON_EC: [u8; 2] = [0x01, 0x42];
const BIP38_PREFIX_EC: [u8; 2] = [0x01, 0x43];
/// The two high bits every non-EC-multiplied flag byte carries.
const BIP38_FLAG_NON_EC: u8 = 0xC0;
const BIP38_FLAG_COMPRESSED: u8 = 0x20;
const BIP38_FLAG_EC_LOT_SEQUENCE: u8 = 0x04;
/// Intermediate code magic, without and with lot/sequence numbers.
const BIP38_MAGIC_NO_LOT: [u8; 8] = [0x2C, 0xE9, 0xB3, 0xE1, 0xFF, 0x39, 0xE2, 0x53];
const BIP38_MAGIC_LOT: [u8; 8] = [0x2C, 0xE9, 0xB3, 0xE1, 0xFF, 0x39, 0xE2, 0x51];

const BIP38_KEY_LEN: usize = 39;

// Scrypt parameters for the passphrase (n = 2^14) and, in EC-multiply mode,
// for the passpoint (n = 2^10).
const SCRYPT_LOG_N: u8 = 14;
const SCRYPT_R: u32 = 8;
const SCRYPT_P: u32 = 8;
const SCRYPT_SEED_LOG_N: u8 = 10;
const SCRYPT_KEY_LEN: usize = 64;

/// Renders a public key as the address string BIP38 hashes. Dash uses its
/// own P2PKH encoding, which is how the spec has alt-chains tell keys apart.
type AddressFn<'a> = &'a dyn Fn(&dashcore::PublicKey) -> String;

/// BIP38 encryption mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bip38Mode {
    /// Non-EC-multiply mode (standard encryption)
    NonEcMultiply,
    /// EC-multiply mode (encryption without private key)
    EcMultiply,
}

/// BIP38 encrypted private key
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bip38EncryptedKey {
    /// The encrypted key data
    data: Vec<u8>,
    /// Encryption mode
    mode: Bip38Mode,
    /// Whether the key is compressed
    compressed: bool,
    /// The network whose address the key hashes
    network: Network,
}

impl Bip38EncryptedKey {
    /// Parses a base58-encoded BIP38 key for `network`.
    ///
    /// The address hash inside the key depends on the network's address
    /// encoding, so decryption only succeeds under the network it was made
    /// for.
    pub fn from_base58(s: &str, network: Network) -> Result<Self> {
        let data = base58::decode_check(s)
            .map_err(|_| Error::InvalidParameter("Invalid base58 encoding".into()))?;

        if data.len() != BIP38_KEY_LEN {
            return Err(Error::InvalidParameter("Invalid BIP38 key length".into()));
        }

        let prefix = [data[0], data[1]];
        let flag = data[2];
        let compressed = (flag & BIP38_FLAG_COMPRESSED) != 0;

        // Every bit the spec does not assign must be clear.
        let mode = if prefix == BIP38_PREFIX_NON_EC {
            if flag & !BIP38_FLAG_COMPRESSED != BIP38_FLAG_NON_EC {
                return Err(Error::InvalidParameter("Invalid BIP38 flag byte".into()));
            }
            Bip38Mode::NonEcMultiply
        } else if prefix == BIP38_PREFIX_EC {
            if flag & !(BIP38_FLAG_COMPRESSED | BIP38_FLAG_EC_LOT_SEQUENCE) != 0 {
                return Err(Error::InvalidParameter("Invalid BIP38 flag byte".into()));
            }
            Bip38Mode::EcMultiply
        } else {
            return Err(Error::InvalidParameter("Invalid BIP38 prefix".into()));
        };

        Ok(Self {
            data,
            mode,
            compressed,
            network,
        })
    }

    /// Convert to base58 string
    pub fn to_base58(&self) -> String {
        base58::encode_check(&self.data)
    }

    /// Decrypts the key with `password`, keeping its compression and network.
    pub fn decrypt(&self, password: &str) -> Result<PrivateKey> {
        let network = self.network;
        let secret = self.decrypt_with(password, &|pk| Address::p2pkh(pk, network).to_string())?;
        Ok(if self.compressed {
            PrivateKey::new(secret, network)
        } else {
            PrivateKey::new_uncompressed(secret, network)
        })
    }

    fn decrypt_with(&self, password: &str, address: AddressFn) -> Result<SecretKey> {
        let password = &normalize(password);
        let secret = match self.mode {
            Bip38Mode::NonEcMultiply => self.decrypt_non_ec_multiply(password)?,
            Bip38Mode::EcMultiply => self.decrypt_ec_multiply(password)?,
        };

        // A wrong passphrase yields some other key, caught by the hash.
        if address_hash(&secret, self.compressed, address) != self.data[3..7] {
            return Err(Error::InvalidParameter("Invalid password".into()));
        }

        Ok(secret)
    }

    /// Decrypt non-EC-multiply mode
    fn decrypt_non_ec_multiply(&self, password: &str) -> Result<SecretKey> {
        let address_hash = &self.data[3..7];
        let derived = scrypt(password.as_bytes(), address_hash, SCRYPT_LOG_N, SCRYPT_R, SCRYPT_P)?;
        let (derived_half1, derived_half2) = derived.split_at(32);

        let mut private_key = [0u8; 32];
        private_key[..16].copy_from_slice(&aes_decrypt_block(&self.data[7..23], derived_half2));
        private_key[16..].copy_from_slice(&aes_decrypt_block(&self.data[23..39], derived_half2));
        xor_in_place(&mut private_key, derived_half1);

        SecretKey::from_secret_bytes(private_key)
            .map_err(|_| Error::InvalidParameter("Invalid private key".into()))
    }

    /// Decrypt EC-multiply mode
    fn decrypt_ec_multiply(&self, password: &str) -> Result<SecretKey> {
        let has_lot_sequence = (self.data[2] & BIP38_FLAG_EC_LOT_SEQUENCE) != 0;
        let address_hash = &self.data[3..7];
        let owner_entropy: [u8; 8] = self.data[7..15].try_into().expect("8 bytes");

        let encrypted_part1_head = &self.data[15..23];
        let encrypted_part2 = &self.data[23..39];

        let pass_factor_key = pass_factor(password, &owner_entropy, has_lot_sequence)?;
        let pass_point = PublicKey::from_secret_key(&pass_factor_key).serialize();

        let mut salt = [0u8; 12];
        salt[..4].copy_from_slice(address_hash);
        salt[4..].copy_from_slice(&owner_entropy);
        let derived = scrypt(&pass_point, &salt, SCRYPT_SEED_LOG_N, 1, 1)?;
        let (derived_half1, derived_half2) = derived.split_at(32);

        // encryptedpart2 holds the tail of encryptedpart1 and of seedb.
        let mut part2 = aes_decrypt_block(encrypted_part2, derived_half2);
        xor_in_place(&mut part2, &derived_half1[16..]);

        let mut encrypted_part1 = [0u8; 16];
        encrypted_part1[..8].copy_from_slice(encrypted_part1_head);
        encrypted_part1[8..].copy_from_slice(&part2[..8]);
        let mut part1 = aes_decrypt_block(&encrypted_part1, derived_half2);
        xor_in_place(&mut part1, &derived_half1[..16]);

        let mut seed_b = [0u8; 24];
        seed_b[..16].copy_from_slice(&part1);
        seed_b[16..].copy_from_slice(&part2[8..]);
        let factor_b = sha256d::Hash::hash(&seed_b).to_byte_array();

        // Multiply to get private key
        let factor_b_key = SecretKey::from_secret_bytes(factor_b)
            .map_err(|_| Error::KeyError("Invalid factor b".into()))?;

        let mut private_key = pass_factor_key;
        private_key = private_key
            .mul_tweak(&factor_b_key.into())
            .map_err(|_| Error::KeyError("Key multiplication failed".into()))?;

        Ok(private_key)
    }
}

/// Encrypts `private_key` with `password` (non-EC-multiply mode), hashing
/// the address in the key's own compression and network.
pub fn encrypt_private_key(private_key: &PrivateKey, password: &str) -> Result<Bip38EncryptedKey> {
    let network = private_key.network;
    let compressed = private_key.compressed;
    let data = encrypt_with(&private_key.inner, password, compressed, &|pk| {
        Address::p2pkh(pk, network).to_string()
    })?;

    Ok(Bip38EncryptedKey {
        data,
        mode: Bip38Mode::NonEcMultiply,
        compressed,
        network,
    })
}

fn encrypt_with(
    private_key: &SecretKey,
    password: &str,
    compressed: bool,
    address: AddressFn,
) -> Result<Vec<u8>> {
    let password = &normalize(password);
    let address_hash = address_hash(private_key, compressed, address);

    let derived = scrypt(password.as_bytes(), &address_hash, SCRYPT_LOG_N, SCRYPT_R, SCRYPT_P)?;
    let (derived_half1, derived_half2) = derived.split_at(32);

    let mut to_encrypt = private_key.to_secret_bytes();
    xor_in_place(&mut to_encrypt, derived_half1);

    let mut data = Vec::with_capacity(BIP38_KEY_LEN);
    data.extend_from_slice(&BIP38_PREFIX_NON_EC);
    data.push(
        BIP38_FLAG_NON_EC
            | if compressed {
                BIP38_FLAG_COMPRESSED
            } else {
                0
            },
    );
    data.extend_from_slice(&address_hash);
    data.extend_from_slice(&aes_encrypt_block(&to_encrypt[..16], derived_half2));
    data.extend_from_slice(&aes_encrypt_block(&to_encrypt[16..], derived_half2));
    Ok(data)
}

/// Generate an intermediate code for EC-multiply mode
pub fn generate_intermediate_code(
    password: &str,
    lot: Option<u32>,
    sequence: Option<u32>,
) -> Result<String> {
    use rand::Rng;
    let mut rng = rand::rng();

    let mut owner_entropy = [0u8; 8];
    let has_lot_sequence = match (lot, sequence) {
        (Some(lot), Some(sequence)) => {
            if lot > 1048575 || sequence > 4095 {
                return Err(Error::InvalidParameter("Lot/sequence out of range".into()));
            }
            // 4 random bytes of owner salt, then the lot and sequence.
            rng.fill(&mut owner_entropy[..4]);
            owner_entropy[4..].copy_from_slice(&(lot * 4096 + sequence).to_be_bytes());
            true
        }
        _ => {
            rng.fill(&mut owner_entropy);
            false
        }
    };

    intermediate_code(password, &owner_entropy, has_lot_sequence)
}

fn intermediate_code(
    password: &str,
    owner_entropy: &[u8; 8],
    has_lot_sequence: bool,
) -> Result<String> {
    let pass_factor = pass_factor(&normalize(password), owner_entropy, has_lot_sequence)?;
    let pass_point = PublicKey::from_secret_key(&pass_factor);

    let mut data = Vec::with_capacity(49);
    data.extend_from_slice(if has_lot_sequence {
        &BIP38_MAGIC_LOT
    } else {
        &BIP38_MAGIC_NO_LOT
    });
    data.extend_from_slice(owner_entropy);
    data.extend_from_slice(&pass_point.serialize());

    Ok(base58::encode_check(&data))
}

// Helper functions

/// The EC-multiply passfactor. With lot/sequence numbers the scrypt output
/// is a prefactor, hashed together with the owner entropy.
fn pass_factor(
    password: &str,
    owner_entropy: &[u8; 8],
    has_lot_sequence: bool,
) -> Result<SecretKey> {
    let owner_salt = if has_lot_sequence {
        &owner_entropy[..4]
    } else {
        &owner_entropy[..]
    };
    let scrypted = scrypt(password.as_bytes(), owner_salt, SCRYPT_LOG_N, SCRYPT_R, SCRYPT_P)?;
    let mut factor: [u8; 32] = scrypted[..32].try_into().expect("32 bytes");

    if has_lot_sequence {
        let mut pre_factor = [0u8; 40];
        pre_factor[..32].copy_from_slice(&factor);
        pre_factor[32..].copy_from_slice(owner_entropy);
        factor = sha256d::Hash::hash(&pre_factor).to_byte_array();
    }

    SecretKey::from_secret_bytes(factor).map_err(|_| Error::KeyError("Invalid pass factor".into()))
}

/// The first four bytes of SHA256(SHA256(address)), for the key's address
/// in its compression.
fn address_hash(secret: &SecretKey, compressed: bool, address: AddressFn) -> [u8; 4] {
    let public_key = dashcore::PublicKey {
        compressed,
        inner: PublicKey::from_secret_key(secret),
    };
    let hash = sha256d::Hash::hash(address(&public_key).as_bytes()).to_byte_array();
    hash[..4].try_into().expect("4 bytes")
}

/// The passphrase in Unicode Normalization Form C, as the spec requires.
fn normalize(password: &str) -> String {
    password.nfc().collect()
}

fn xor_in_place(data: &mut [u8], key: &[u8]) {
    for (d, k) in data.iter_mut().zip(key) {
        *d ^= k;
    }
}

/// scrypt with 64 bytes of output.
fn scrypt(password: &[u8], salt: &[u8], log_n: u8, r: u32, p: u32) -> Result<[u8; SCRYPT_KEY_LEN]> {
    let params = scrypt::Params::new(log_n, r, p, SCRYPT_KEY_LEN)
        .map_err(|_| Error::KeyError("Invalid scrypt parameters".into()))?;
    let mut out = [0u8; SCRYPT_KEY_LEN];
    scrypt::scrypt(password, salt, &params, &mut out)
        .map_err(|_| Error::KeyError("Scrypt derivation failed".into()))?;
    Ok(out)
}

/// AES-256 on one 16-byte block, without chaining.
#[allow(deprecated)]
fn aes_encrypt_block(block: &[u8], key: &[u8]) -> [u8; 16] {
    use aes::cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit};
    use aes::Aes256;

    let mut block = GenericArray::clone_from_slice(block);
    Aes256::new(GenericArray::from_slice(key)).encrypt_block(&mut block);
    block.into()
}

/// Inverse of [`aes_encrypt_block`].
#[allow(deprecated)]
fn aes_decrypt_block(block: &[u8], key: &[u8]) -> [u8; 16] {
    use aes::cipher::{generic_array::GenericArray, BlockDecrypt, KeyInit};
    use aes::Aes256;

    let mut block = GenericArray::clone_from_slice(block);
    Aes256::new(GenericArray::from_slice(key)).decrypt_block(&mut block);
    block.into()
}

impl fmt::Display for Bip38EncryptedKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_base58())
    }
}

/// Builder for BIP38 encryption
pub struct Bip38Builder {
    password: Option<String>,
    compressed: bool,
    network: Network,
    lot: Option<u32>,
    sequence: Option<u32>,
}

impl Bip38Builder {
    /// Create a new builder
    pub fn new() -> Self {
        Self {
            password: None,
            compressed: false,
            network: Network::Mainnet,
            lot: None,
            sequence: None,
        }
    }

    /// Set the password
    pub fn password(mut self, password: String) -> Self {
        self.password = Some(password);
        self
    }

    /// Set compressed flag
    pub fn compressed(mut self, compressed: bool) -> Self {
        self.compressed = compressed;
        self
    }

    /// Set the network
    pub fn network(mut self, network: Network) -> Self {
        self.network = network;
        self
    }

    /// Set lot and sequence for EC-multiply mode
    pub fn lot_sequence(mut self, lot: u32, sequence: u32) -> Self {
        self.lot = Some(lot);
        self.sequence = Some(sequence);
        self
    }

    /// Encrypt a private key
    pub fn encrypt(&self, private_key: &SecretKey) -> Result<Bip38EncryptedKey> {
        let password =
            self.password.as_ref().ok_or(Error::InvalidParameter("Password required".into()))?;

        let private_key = if self.compressed {
            PrivateKey::new(*private_key, self.network)
        } else {
            PrivateKey::new_uncompressed(*private_key, self.network)
        };
        encrypt_private_key(&private_key, password)
    }

    /// Generate an intermediate code for EC-multiply mode
    pub fn generate_intermediate(&self) -> Result<String> {
        let password =
            self.password.as_ref().ok_or(Error::InvalidParameter("Password required".into()))?;

        generate_intermediate_code(password, self.lot, self.sequence)
    }
}

impl Default for Bip38Builder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[path = "bip38_tests.rs"]
mod tests;
