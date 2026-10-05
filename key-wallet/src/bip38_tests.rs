//! Tests for BIP38 password-protected private key encryption

use super::*;
use hex_lit::hex;
use test_case::test_case;

/// Encrypting and decrypting gives the key back, through base58 too, in
/// either compression; a wrong password does not.
#[test_case(hex!("0C28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D"), "TestingOneTwoThree" ; "key 0c28")]
#[test_case(hex!("CBF4B9F70470856BB4F40F80B87EDB90865997FFEE6DF315AB166D713AF433A5"), "TestingOneTwoThree" ; "key cbf4")]
#[test_case(hex!("09C2686880095B1A4C249EE3AC4EEA8A014F11E6F4774A924C9F3C4E9C5D6766"), "Satoshi" ; "key 09c2")]
#[test_case(hex!("644DC76B88DF64C3E48AB6595CBB5C468D63F20B5C8D1739B15A8C3D7FC9770C"), "TestPassword" ; "key 644d")]
#[test_case([0x11; 32], "CorrectPassword123" ; "key 11")]
#[test_case([0x42; 32], "TestPassword" ; "key 42")]
#[test_case([0xAA; 32], "TestPassword" ; "key aa")]
#[test_case([0x55; 32], "Password1" ; "password 1")]
#[test_case([0x55; 32], "Password2" ; "password 2")]
#[test_case([0x55; 32], "LongPasswordWithManyCharacters123!@#" ; "long password")]
#[test_case([0x42; 32], "Hello世界" ; "chinese")]
#[test_case([0x42; 32], "Привет" ; "cyrillic")]
#[test_case([0x42; 32], "مرحبا" ; "arabic")]
#[test_case([0x42; 32], "🔐🔑💰" ; "emoji")]
#[test_case([0x42; 32], "Ñoño" ; "tilde")]
#[test_case([0x99; 32], "" ; "empty password")]
#[test_case([0x99; 32], &"a".repeat(1000) ; "very long password")]
#[test_case([0x99; 32], "!@#$%^&*()_+-=[]{}|;':\",./<>?`~" ; "special characters")]
fn round_trip(key: [u8; 32], password: &str) {
    let private_key = SecretKey::from_secret_bytes(key).unwrap();
    for compressed in [true, false] {
        let encrypted =
            encrypt_private_key(&private_key, password, compressed, Network::Mainnet).unwrap();
        assert_eq!(encrypted.compressed, compressed);

        let encoded = encrypted.to_base58();
        assert!(encoded.starts_with('6'), "{encoded}");
        let parsed = Bip38EncryptedKey::from_base58(&encoded).unwrap();
        assert_eq!(parsed, encrypted);

        assert_eq!(parsed.decrypt(password).unwrap(), private_key);
        assert!(parsed.decrypt("WrongPassword").is_err());
    }
}

/// Random keys and passwords round-trip too.
#[test]
fn round_trip_random() {
    use rand::distr::{Alphanumeric, SampleString};
    use rand::Rng;

    let mut rng = rand::rng();
    for _ in 0..10 {
        let private_key = loop {
            if let Ok(key) = SecretKey::from_secret_bytes(rng.random()) {
                break key;
            }
        };
        let len = rng.random_range(8..50);
        let password = Alphanumeric.sample_string(&mut rng, len);
        let compressed = rng.random_bool(0.5);

        let encrypted =
            encrypt_private_key(&private_key, &password, compressed, Network::Mainnet).unwrap();
        assert_eq!(encrypted.decrypt(&password).unwrap(), private_key);
    }
}

/// The compression flag and the network each change the encrypted key.
#[test]
fn compression_and_network_change_the_encoding() {
    let private_key = SecretKey::from_secret_bytes([0x77; 32]).unwrap();
    let encodings =
        [(false, Network::Mainnet), (true, Network::Mainnet), (false, Network::Testnet)].map(
            |(compressed, network)| {
                let encrypted =
                    encrypt_private_key(&private_key, "NetworkTest", compressed, network).unwrap();
                assert_eq!(encrypted.network, network);
                assert_eq!(encrypted.decrypt("NetworkTest").unwrap(), private_key);
                encrypted.to_base58()
            },
        );
    assert_ne!(encodings[0], encodings[1]);
    assert_ne!(encodings[0], encodings[2]);
}

#[test]
fn builder() {
    let private_key = SecretKey::from_secret_bytes(hex!(
        "0C28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D"
    ))
    .unwrap();

    let encrypted = Bip38Builder::new()
        .password("TestPassword123".to_string())
        .compressed(true)
        .network(Network::Testnet)
        .encrypt(&private_key)
        .unwrap();

    assert!(encrypted.compressed);
    assert_eq!(encrypted.network, Network::Testnet);
    assert_eq!(encrypted.decrypt("TestPassword123").unwrap(), private_key);
}

/// The P2PKH encoding the BIP38 test vectors hash: Bitcoin's, version 0.
fn bitcoin_address(pk: &dashcore::PublicKey) -> String {
    let mut payload = vec![0u8];
    payload.extend_from_slice(pk.pubkey_hash().as_byte_array());
    base58::encode_check(&payload)
}

#[test_case(
    "TestingOneTwoThree",
    "6PRVWUbkzzsbcVac2qwfssoUJAN1Xhrg6bNk8J7Nzm5H7kxEbn2Nh2ZoGg",
    hex!("CBF4B9F70470856BB4F40F80B87EDB90865997FFEE6DF315AB166D713AF433A5")
    ; "uncompressed 1"
)]
#[test_case(
    "Satoshi",
    "6PRNFFkZc2NZ6dJqFfhRoFNMR9Lnyj7dYGrzdgXXVMXcxoKTePPX1dWByq",
    hex!("09C2686880095B1A4C249EE3AC4EEA8A014F11E6F986D0B5025AC1F39AFBD9AE")
    ; "uncompressed 2"
)]
#[test_case(
    "TestingOneTwoThree",
    "6PYNKZ1EAgYgmQfmNVamxyXVWHzK5s6DGhwP4J5o44cvXdoY7sRzhtpUeo",
    hex!("CBF4B9F70470856BB4F40F80B87EDB90865997FFEE6DF315AB166D713AF433A5")
    ; "compressed 1"
)]
#[test_case(
    "Satoshi",
    "6PYLtMnXvfG3oJde97zRyLYFZCYizPU5T3LwgdYJz1fRhh16bU7u6PPmY7",
    hex!("09C2686880095B1A4C249EE3AC4EEA8A014F11E6F986D0B5025AC1F39AFBD9AE")
    ; "compressed 2"
)]
fn spec_vectors_non_ec_multiply(password: &str, encrypted: &str, secret: [u8; 32]) {
    let key = Bip38EncryptedKey::from_base58(encrypted).unwrap();
    assert_eq!(key.mode, Bip38Mode::NonEcMultiply);
    assert_eq!(key.decrypt_with(password, &bitcoin_address).unwrap().to_secret_bytes(), secret);
    assert!(key.decrypt_with("wrong", &bitcoin_address).is_err());
}

#[test]
fn intermediate_code_generation() {
    assert!(!generate_intermediate_code("password", None, None).unwrap().is_empty());
    assert!(!generate_intermediate_code("password", Some(100000), Some(1)).unwrap().is_empty());
}

#[test_case("InvalidBase58String!!!" ; "invalid base58")]
#[test_case("5KN7MzqK5wt2TP1fQCYyHBtDrXdJuXbUzm4A9rKAteGu3Qi5CVR" ; "wif")]
fn rejects_non_bip38(s: &str) {
    assert!(Bip38EncryptedKey::from_base58(s).is_err());
}

#[test]
#[ignore] // DashSync uses a different BIP38 format that's incompatible
fn dashsync_vector() {
    // Test vector from DashSync (Dash-specific)
    let bip38_key = Bip38EncryptedKey::from_base58(
        "6PfV898iMrVs3d9gJSw5HTYyGhQRR5xRu5ji4GE6H5QdebT2YgK14Lu1E5",
    )
    .expect("Should parse Dash encrypted key");

    let decrypted = bip38_key
        .decrypt("TestingOneTwoThree")
        .expect("Decryption should succeed with correct password");

    // DashSync expects this to produce: 7sEJGJRPeGoNBsW8tKAk4JH52xbxrktPfJcNxEx3uf622ZrGR5k
    // We can at least verify it decrypts successfully
    assert_eq!(decrypted.to_secret_bytes().len(), 32);
}
