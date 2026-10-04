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
use dashcore::ecdsa::{Compression, EcdsaSecretKey};
use dashcore::{Address, PrivateKey};
use dashcore_hashes::{sha256d, Hash};
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

    /// The encryption mode.
    pub fn mode(&self) -> Bip38Mode {
        self.mode
    }

    /// Whether the key's address uses the compressed public key.
    pub fn is_compressed(&self) -> bool {
        self.compressed
    }

    /// The network whose address the key hashes.
    pub fn network(&self) -> Network {
        self.network
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

    fn decrypt_with(&self, password: &str, address: AddressFn) -> Result<EcdsaSecretKey> {
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
    fn decrypt_non_ec_multiply(&self, password: &str) -> Result<EcdsaSecretKey> {
        let address_hash = &self.data[3..7];
        let derived =
            scrypt(normalize(password).as_bytes(), address_hash, SCRYPT_LOG_N, SCRYPT_R, SCRYPT_P)?;
        let (derived_half1, derived_half2) = derived.split_at(32);

        let mut private_key = [0u8; 32];
        for (half, out) in
            [&self.data[7..23], &self.data[23..39]].iter().zip(private_key.chunks_mut(16))
        {
            let block = aes_decrypt_block(half, derived_half2);
            out.copy_from_slice(&block);
        }
        xor_in_place(&mut private_key, derived_half1);

        EcdsaSecretKey::from_bytes(&private_key)
            .map_err(|_| Error::InvalidParameter("Invalid password".into()))
    }

    /// Decrypt EC-multiply mode
    fn decrypt_ec_multiply(&self, password: &str) -> Result<EcdsaSecretKey> {
        let has_lot_sequence = (self.data[2] & BIP38_FLAG_EC_LOT_SEQUENCE) != 0;
        let address_hash = &self.data[3..7];
        let owner_entropy: [u8; 8] = self.data[7..15].try_into().expect("8 bytes");
        let encrypted_part1_head = &self.data[15..23];
        let encrypted_part2 = &self.data[23..39];

        let pass_factor = pass_factor(password, &owner_entropy, has_lot_sequence)?;
        let pass_point = pass_factor.public_key().to_compressed();

        let mut salt = [0u8; 12];
        salt[..4].copy_from_slice(address_hash);
        salt[4..].copy_from_slice(&owner_entropy);
        let derived = scrypt(&pass_point, &salt, SCRYPT_SEED_LOG_N, 1, 1)?;
        let (derived_half1, derived_half2) = derived.split_at(32);

        // encryptedpart2 holds the tail of encryptedpart1 and of seedb.
        let mut part2 = aes_decrypt_block(encrypted_part2, derived_half2);
        xor_in_place(&mut part2, &derived_half1[16..32]);

        let mut encrypted_part1 = [0u8; 16];
        encrypted_part1[..8].copy_from_slice(encrypted_part1_head);
        encrypted_part1[8..].copy_from_slice(&part2[..8]);
        let mut part1 = aes_decrypt_block(&encrypted_part1, derived_half2);
        xor_in_place(&mut part1, &derived_half1[..16]);

        let mut seed_b = [0u8; 24];
        seed_b[..16].copy_from_slice(&part1);
        seed_b[16..].copy_from_slice(&part2[8..]);
        let factor_b = sha256d::Hash::hash(&seed_b).to_byte_array();

        pass_factor
            .mul_tweak(&factor_b)
            .map_err(|_| Error::InvalidParameter("Invalid password".into()))
    }
}

/// Encrypts `private_key` with `password` (non-EC-multiply mode), hashing
/// the address in the key's own compression and network.
pub fn encrypt_private_key(private_key: &PrivateKey, password: &str) -> Result<Bip38EncryptedKey> {
    let network = private_key.network;
    let data = encrypt_with(&private_key.inner, private_key.is_compressed(), password, &|pk| {
        Address::p2pkh(pk, network).to_string()
    })?;

    Ok(Bip38EncryptedKey {
        data,
        mode: Bip38Mode::NonEcMultiply,
        compressed: private_key.is_compressed(),
        network,
    })
}

fn encrypt_with(
    secret: &EcdsaSecretKey,
    compressed: bool,
    password: &str,
    address: AddressFn,
) -> Result<Vec<u8>> {
    let address_hash = address_hash(secret, compressed, address);
    let derived =
        scrypt(normalize(password).as_bytes(), &address_hash, SCRYPT_LOG_N, SCRYPT_R, SCRYPT_P)?;
    let (derived_half1, derived_half2) = derived.split_at(32);

    let mut to_encrypt = secret.to_bytes();
    xor_in_place(&mut *to_encrypt, derived_half1);

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
    let pass_factor = pass_factor(password, owner_entropy, has_lot_sequence)?;
    let pass_point = pass_factor.public_key();

    let mut data = Vec::with_capacity(49);
    data.extend_from_slice(if has_lot_sequence {
        &BIP38_MAGIC_LOT
    } else {
        &BIP38_MAGIC_NO_LOT
    });
    data.extend_from_slice(owner_entropy);
    data.extend_from_slice(&pass_point.to_compressed());

    Ok(base58::encode_check(&data))
}

// Helper functions

/// The EC-multiply passfactor. With lot/sequence numbers the scrypt output
/// is a prefactor, hashed together with the owner entropy.
fn pass_factor(
    password: &str,
    owner_entropy: &[u8; 8],
    has_lot_sequence: bool,
) -> Result<EcdsaSecretKey> {
    let owner_salt = if has_lot_sequence {
        &owner_entropy[..4]
    } else {
        &owner_entropy[..]
    };
    let scrypted =
        scrypt(normalize(password).as_bytes(), owner_salt, SCRYPT_LOG_N, SCRYPT_R, SCRYPT_P)?;

    let factor: [u8; 32] = if has_lot_sequence {
        let mut pre = [0u8; 40];
        pre[..32].copy_from_slice(&scrypted[..32]);
        pre[32..].copy_from_slice(owner_entropy);
        sha256d::Hash::hash(&pre).to_byte_array()
    } else {
        scrypted[..32].try_into().expect("32 bytes")
    };

    EcdsaSecretKey::from_bytes(&factor).map_err(|_| Error::KeyError("Invalid pass factor".into()))
}

/// The first four bytes of SHA256(SHA256(address)), for the key's address.
fn address_hash(secret: &EcdsaSecretKey, compressed: bool, address: AddressFn) -> [u8; 4] {
    let public_key = dashcore::PublicKey {
        compressed,
        inner: secret.public_key(),
    };
    let hash = sha256d::Hash::hash(address(&public_key).as_bytes()).to_byte_array();
    hash[..4].try_into().expect("4 bytes")
}

/// The passphrase in Unicode Normalization Form C, as the spec requires.
fn normalize(password: &str) -> String {
    password.nfc().collect()
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

fn xor_in_place(data: &mut [u8], key: &[u8]) {
    for (d, k) in data.iter_mut().zip(key) {
        *d ^= k;
    }
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
    pub fn encrypt(&self, private_key: &EcdsaSecretKey) -> Result<Bip38EncryptedKey> {
        let password =
            self.password.as_ref().ok_or(Error::InvalidParameter("Password required".into()))?;

        let private_key = PrivateKey {
            network: self.network,
            inner: private_key.clone().with_compression(Compression::from(self.compressed)),
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
mod tests {
    use super::*;
    use dashcore::hashes::Hash;
    use test_case::test_case;

    /// The P2PKH encoding the BIP38 test vectors hash: Bitcoin's, version 0.
    fn bitcoin_address(pk: &dashcore::PublicKey) -> String {
        let mut payload = vec![0u8];
        payload.extend_from_slice(pk.pubkey_hash().as_byte_array());
        base58::encode_check(&payload)
    }

    fn hex32(s: &str) -> [u8; 32] {
        hex::decode(s).unwrap().try_into().unwrap()
    }

    #[test_case(
        "TestingOneTwoThree",
        "6PRVWUbkzzsbcVac2qwfssoUJAN1Xhrg6bNk8J7Nzm5H7kxEbn2Nh2ZoGg",
        "CBF4B9F70470856BB4F40F80B87EDB90865997FFEE6DF315AB166D713AF433A5"
        ; "uncompressed 1"
    )]
    #[test_case(
        "Satoshi",
        "6PRNFFkZc2NZ6dJqFfhRoFNMR9Lnyj7dYGrzdgXXVMXcxoKTePPX1dWByq",
        "09C2686880095B1A4C249EE3AC4EEA8A014F11E6F986D0B5025AC1F39AFBD9AE"
        ; "uncompressed 2"
    )]
    #[test_case(
        "TestingOneTwoThree",
        "6PYNKZ1EAgYgmQfmNVamxyXVWHzK5s6DGhwP4J5o44cvXdoY7sRzhtpUeo",
        "CBF4B9F70470856BB4F40F80B87EDB90865997FFEE6DF315AB166D713AF433A5"
        ; "compressed 1"
    )]
    #[test_case(
        "Satoshi",
        "6PYLtMnXvfG3oJde97zRyLYFZCYizPU5T3LwgdYJz1fRhh16bU7u6PPmY7",
        "09C2686880095B1A4C249EE3AC4EEA8A014F11E6F986D0B5025AC1F39AFBD9AE"
        ; "compressed 2"
    )]
    fn spec_vectors_non_ec_multiply(password: &str, encrypted: &str, hex: &str) {
        let key = Bip38EncryptedKey::from_base58(encrypted, Network::Mainnet).unwrap();
        assert_eq!(key.mode(), Bip38Mode::NonEcMultiply);
        let secret = key.decrypt_with(password, &bitcoin_address).unwrap();
        assert_eq!(*secret.to_bytes(), hex32(hex));

        let data = encrypt_with(&secret, key.is_compressed(), password, &bitcoin_address).unwrap();
        assert_eq!(base58::encode_check(&data), encrypted);

        assert!(key.decrypt_with("wrong", &bitcoin_address).is_err());
    }

    #[test]
    fn spec_vector_unicode_passphrase_is_nfc_normalized() {
        // U+03D2 U+0301 normalizes to U+03D3 under NFC.
        let password = "\u{03D2}\u{0301}\u{0000}\u{10400}\u{1F4A9}";
        let key = Bip38EncryptedKey::from_base58(
            "6PRW5o9FLp4gJDDVqJQKJFTpMvdsSGJxMYHtHaQBF3ooa8mwD69bapcDQn",
            Network::Mainnet,
        )
        .unwrap();
        let secret = key.decrypt_with(password, &bitcoin_address).unwrap();
        let public_key = dashcore::PublicKey::new_uncompressed(secret.public_key());
        assert_eq!(bitcoin_address(&public_key), "16ktGzmfrurhbhi6JGqsMWf7TyqK9HNAeF");
    }

    #[test_case(
        "TestingOneTwoThree",
        "passphrasepxFy57B9v8HtUsszJYKReoNDV6VHjUSGt8EVJmux9n1J3Ltf1gRxyDGXqnf9qm",
        "6PfQu77ygVyJLZjfvMLyhLMQbYnu5uguoJJ4kMCLqWwPEdfpwANVS76gTX",
        "A43A940577F4E97F5C4D39EB14FF083A98187C64EA7C99EF7CE460833959A519"
        ; "no lot 1"
    )]
    #[test_case(
        "Satoshi",
        "passphraseoRDGAXTWzbp72eVbtUDdn1rwpgPUGjNZEc6CGBo8i5EC1FPW8wcnLdq4ThKzAS",
        "6PfLGnQs6VZnrNpmVKfjotbnQuaJK4KZoPFrAjx1JMJUa1Ft8gnf5WxfKd",
        "C2C8036DF268F498099350718C4A3EF3984D2BE84618C2650F5171DCC5EB660A"
        ; "no lot 2"
    )]
    #[test_case(
        "MOLON LABE",
        "passphraseaB8feaLQDENqCgr4gKZpmf4VoaT6qdjJNJiv7fsKvjqavcJxvuR1hy25aTu5sX",
        "6PgNBNNzDkKdhkT6uJntUXwwzQV8Rr2tZcbkDcuC9DZRsS6AtHts4Ypo1j",
        "44EA95AFBF138356A05EA32110DFD627232D0F2991AD221187BE356F19FA8190"
        ; "lot 1"
    )]
    #[test_case(
        "\u{039C}\u{039F}\u{039B}\u{03A9}\u{039D} \u{039B}\u{0391}\u{0392}\u{0395}",
        "passphrased3z9rQJHSyBkNBwTRPkUGNVEVrUAcfAXDyRU1V28ie6hNFbqDwbFBvsTK7yWVK",
        "6PgGWtx25kUg8QWvwuJAgorN6k9FbE25rv5dMRwu5SKMnfpfVe5mar2ngH",
        "CA2759AA4ADB0F96C414F36ABEB8DB59342985BE9FA50FAAC228C8E7D90E3006"
        ; "lot 2 greek"
    )]
    fn spec_vectors_ec_multiply(password: &str, code: &str, encrypted: &str, hex: &str) {
        let key = Bip38EncryptedKey::from_base58(encrypted, Network::Mainnet).unwrap();
        assert_eq!(key.mode(), Bip38Mode::EcMultiply);
        let secret = key.decrypt_with(password, &bitcoin_address).unwrap();
        assert_eq!(*secret.to_bytes(), hex32(hex));
        assert!(key.decrypt_with("wrong", &bitcoin_address).is_err());

        // The owner entropy is fixed by the vector; the rest must match.
        let decoded = base58::decode_check(code).unwrap();
        let has_lot_sequence = decoded[..8] == BIP38_MAGIC_LOT;
        let owner_entropy: [u8; 8] = decoded[8..16].try_into().unwrap();
        assert_eq!(intermediate_code(password, &owner_entropy, has_lot_sequence).unwrap(), code);
    }

    /// An EC-multiplied key from DashSync, hashed with a Dash address.
    #[test]
    fn dash_vector_ec_multiply() {
        let key = Bip38EncryptedKey::from_base58(
            "6PfV898iMrVs3d9gJSw5HTYyGhQRR5xRu5ji4GE6H5QdebT2YgK14Lu1E5",
            Network::Mainnet,
        )
        .unwrap();
        let private_key = key.decrypt("TestingOneTwoThree").unwrap();
        assert_eq!(private_key.to_wif(), "7sEJGJRPeGoNBsW8tKAk4JH52xbxrktPfJcNxEx3uf622ZrGR5k");
    }

    #[test]
    fn round_trip_keeps_compression_and_network() {
        let secret = EcdsaSecretKey::from_bytes(&[0x42; 32]).unwrap();
        for network in [Network::Mainnet, Network::Testnet] {
            for private_key in [
                PrivateKey::new(secret.clone(), network),
                PrivateKey::new_uncompressed(secret.clone(), network),
            ] {
                let encrypted = encrypt_private_key(&private_key, "pass").unwrap();
                let parsed =
                    Bip38EncryptedKey::from_base58(&encrypted.to_base58(), network).unwrap();
                assert_eq!(parsed, encrypted);
                assert_eq!(parsed.decrypt("pass").unwrap(), private_key);
            }
        }

        // The address hash binds the key to its network.
        let encrypted =
            encrypt_private_key(&PrivateKey::new(secret.clone(), Network::Testnet), "pass")
                .unwrap();
        let on_mainnet =
            Bip38EncryptedKey::from_base58(&encrypted.to_base58(), Network::Mainnet).unwrap();
        assert!(on_mainnet.decrypt("pass").is_err());
    }

    #[test]
    fn flag_byte_reserved_bits_are_rejected() {
        let valid =
            base58::decode_check("6PRVWUbkzzsbcVac2qwfssoUJAN1Xhrg6bNk8J7Nzm5H7kxEbn2Nh2ZoGg")
                .unwrap();
        assert_eq!(valid[2], BIP38_FLAG_NON_EC);

        // Non-EC keys must set 0xC0; neither mode may set reserved bits or,
        // for non-EC keys, the lot/sequence bit.
        for (prefix, flag) in [
            (BIP38_PREFIX_NON_EC, 0x00),
            (BIP38_PREFIX_NON_EC, 0xC4),
            (BIP38_PREFIX_NON_EC, 0xC8),
            (BIP38_PREFIX_EC, 0xC0),
            (BIP38_PREFIX_EC, 0x10),
        ] {
            let mut data = valid.clone();
            data[..2].copy_from_slice(&prefix);
            data[2] = flag;
            let s = base58::encode_check(&data);
            assert!(Bip38EncryptedKey::from_base58(&s, Network::Mainnet).is_err(), "{flag:#04x}");
        }
    }
}
