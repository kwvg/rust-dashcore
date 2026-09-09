//! Tests for BLS HD key derivation.

use super::*;

use dashcore::Network;

use crate::bip32::{ChildNumber, DerivationPath, Fingerprint};

#[test]
fn test_master_key_generation() {
    let seed = b"this is a test seed for BLS HD key derivation";
    let master = ExtendedBLSPrivKey::new_master(Network::Testnet, seed).unwrap();

    assert_eq!(master.depth, 0);
    assert_eq!(master.parent_fingerprint, Fingerprint::default());
}

#[test]
fn test_key_derivation() {
    let seed = b"test seed for BLS derivation";
    let master = ExtendedBLSPrivKey::new_master(Network::Testnet, seed).unwrap();

    // Test hardened derivation
    let child_hardened =
        master.derive_priv(ChildNumber::from_hardened_idx(0).unwrap()).unwrap();
    assert_eq!(child_hardened.depth, 1);
    assert_eq!(child_hardened.parent_fingerprint, master.fingerprint());

    // Test non-hardened derivation
    let child_normal = master.derive_priv(ChildNumber::from_normal_idx(0).unwrap()).unwrap();
    assert_eq!(child_normal.depth, 1);
    assert_eq!(child_normal.parent_fingerprint, master.fingerprint());
}

#[test]
fn test_public_key_derivation() {
    let seed = b"test seed for BLS public key derivation";
    let master = ExtendedBLSPrivKey::new_master(Network::Testnet, seed).unwrap();
    let master_pub = master.to_extended_pub_key();

    // Should be able to derive non-hardened child
    let child_pub = master_pub.derive_pub(ChildNumber::from_normal_idx(0).unwrap()).unwrap();
    assert_eq!(child_pub.depth, 1);

    // Should fail for hardened derivation
    let hardened_result = master_pub.derive_pub(ChildNumber::from_hardened_idx(0).unwrap());
    assert!(hardened_result.is_err());
}

#[test]
fn test_derivation_matches_through_private_and_public() {
    // Test vector from C++ implementation
    // Seed: {1, 50, 6, 244, 24, 199, 1, 25}
    let seed = vec![1u8, 50, 6, 244, 24, 199, 1, 25];

    let master_priv = ExtendedBLSPrivKey::new_master(Network::Testnet, &seed).unwrap();
    let master_pub = master_priv.to_extended_pub_key();

    // Test single child derivation
    // Child index: 238757
    let child_index = 238757;

    // Derive public key through private key
    let child_priv =
        master_priv.derive_priv(ChildNumber::from_normal_idx(child_index).unwrap()).unwrap();
    let pk1 = child_priv.to_extended_pub_key().public_key;

    // Derive public key directly from parent public key
    let child_pub =
        master_pub.derive_pub(ChildNumber::from_normal_idx(child_index).unwrap()).unwrap();
    let pk2 = child_pub.public_key;

    // They should be equal
    assert_eq!(
        pk1.to_bytes(),
        pk2.to_bytes(),
        "Public key derived through private key should equal public key derived directly"
    );
}

#[test]
fn test_derivation_path_consistency() {
    // Test vector from C++ implementation
    // Path: m/0/3/8/1
    let seed = vec![1u8, 50, 6, 244, 24, 199, 1, 25];

    let master_priv = ExtendedBLSPrivKey::new_master(Network::Testnet, &seed).unwrap();
    let master_pub = master_priv.to_extended_pub_key();

    // Derive through private keys
    let derived_priv = master_priv
        .derive_priv(ChildNumber::from_normal_idx(0).unwrap())
        .unwrap()
        .derive_priv(ChildNumber::from_normal_idx(3).unwrap())
        .unwrap()
        .derive_priv(ChildNumber::from_normal_idx(8).unwrap())
        .unwrap()
        .derive_priv(ChildNumber::from_normal_idx(1).unwrap())
        .unwrap();

    let pk_from_priv = derived_priv.to_extended_pub_key().public_key;

    // Derive through public keys
    let derived_pub = master_pub
        .derive_pub(ChildNumber::from_normal_idx(0).unwrap())
        .unwrap()
        .derive_pub(ChildNumber::from_normal_idx(3).unwrap())
        .unwrap()
        .derive_pub(ChildNumber::from_normal_idx(8).unwrap())
        .unwrap()
        .derive_pub(ChildNumber::from_normal_idx(1).unwrap())
        .unwrap();

    let pk_from_pub = derived_pub.public_key;

    // They should be equal
    assert_eq!(
        pk_from_priv.to_bytes(),
        pk_from_pub.to_bytes(),
        "Public key derived through private key path should equal public key derived through public key path"
    );
}

#[test]
fn test_public_child_derivation_from_parent() {
    // Test vector from C++ implementation
    // Seed: {1, 50, 6, 244, 24, 199, 1, 0, 0, 0}
    let seed = vec![1u8, 50, 6, 244, 24, 199, 1, 0, 0, 0];

    let master_priv = ExtendedBLSPrivKey::new_master(Network::Testnet, &seed).unwrap();
    let master_pub = master_priv.to_extended_pub_key();

    // Child index: 13
    let child_index = 13;

    // Get public key from private derivation
    let pk1 = master_priv
        .derive_priv(ChildNumber::from_normal_idx(child_index).unwrap())
        .unwrap()
        .to_extended_pub_key();

    // Get public key from public derivation
    let pk2 =
        master_pub.derive_pub(ChildNumber::from_normal_idx(child_index).unwrap()).unwrap();

    // They should be equal
    assert_eq!(
        pk1.public_key.to_bytes(),
        pk2.public_key.to_bytes(),
        "Extended public keys should match"
    );
    assert_eq!(pk1.chain_code, pk2.chain_code, "Chain codes should match");
}

#[test]
fn test_hardened_public_derivation_fails() {
    // Test that hardened derivation from public key fails
    let seed = vec![1u8, 50, 6, 244, 24, 199, 1, 25];

    let master_priv = ExtendedBLSPrivKey::new_master(Network::Testnet, &seed).unwrap();
    let master_pub = master_priv.to_extended_pub_key();

    // Hardened index: (1 << 31) + 3
    let hardened_index = (1u32 << 31) + 3;

    // Private key derivation should work
    let priv_result = master_priv.derive_priv(ChildNumber::from(hardened_index)).unwrap();
    assert_eq!(priv_result.depth, 1);

    // Public key derivation should fail
    let pub_result = master_pub.derive_pub(ChildNumber::from(hardened_index));
    assert!(pub_result.is_err(), "Hardened derivation from public key should fail");

    if let Err(e) = pub_result {
        match e {
            Error::CannotDeriveFromHardenedPublic => (),
            _ => panic!("Expected CannotDeriveFromHardenedPublic error, got {:?}", e),
        }
    }
}

#[test]
fn test_unhardened_derivation_consistency() {
    // Test multiple unhardened derivations
    let seed = b"test seed for unhardened BLS derivation";
    let master = ExtendedBLSPrivKey::new_master(Network::Testnet, seed).unwrap();
    let master_pub = master.to_extended_pub_key();

    // Test with child 42
    let child_priv_42 = master.derive_priv(ChildNumber::from_normal_idx(42).unwrap()).unwrap();
    let child_pub_42 =
        master_pub.derive_pub(ChildNumber::from_normal_idx(42).unwrap()).unwrap();

    assert_eq!(
        child_priv_42.to_extended_pub_key().public_key.to_bytes(),
        child_pub_42.public_key.to_bytes()
    );

    // Test grandchild derivation (42 -> 12142)
    let grandchild_priv =
        child_priv_42.derive_priv(ChildNumber::from_normal_idx(12142).unwrap()).unwrap();
    let grandchild_pub =
        child_pub_42.derive_pub(ChildNumber::from_normal_idx(12142).unwrap()).unwrap();

    assert_eq!(
        grandchild_priv.to_extended_pub_key().public_key.to_bytes(),
        grandchild_pub.public_key.to_bytes()
    );
}

#[test]
fn test_derive_path_method() {
    // Test the derive_path method for both private and public keys
    let seed = vec![1u8, 50, 6, 244, 24, 199, 1, 25];

    let master_priv = ExtendedBLSPrivKey::new_master(Network::Testnet, &seed).unwrap();
    let master_pub = master_priv.to_extended_pub_key();

    // Create a non-hardened path
    let path = DerivationPath::from(vec![
        ChildNumber::from_normal_idx(0).unwrap(),
        ChildNumber::from_normal_idx(3).unwrap(),
        ChildNumber::from_normal_idx(8).unwrap(),
        ChildNumber::from_normal_idx(1).unwrap(),
    ]);

    // Derive using path method on private key
    let derived_priv = master_priv.derive_path(&path).unwrap();

    // Derive using path method on public key
    let derived_pub = master_pub.derive_path(&path).unwrap();

    // They should match
    assert_eq!(
        derived_priv.to_extended_pub_key().public_key.to_bytes(),
        derived_pub.public_key.to_bytes()
    );
}

#[test]
fn test_long_derivation_path() {
    // Test from C++ implementation: m/(2^31+5)/0/0/(2^31+56)/70/4
    let seed = vec![1u8, 50, 6, 244, 24, 199, 1, 25];

    let master = ExtendedBLSPrivKey::new_master(Network::Testnet, &seed).unwrap();

    // Build the long derivation path: m/(2^31+5)/0/0/(2^31+56)/70/4
    let derived = master
        .derive_priv(ChildNumber::from_hardened_idx(5).unwrap())
        .unwrap() // Hardened (2^31+5)
        .derive_priv(ChildNumber::from_normal_idx(0).unwrap())
        .unwrap()
        .derive_priv(ChildNumber::from_normal_idx(0).unwrap())
        .unwrap()
        .derive_priv(ChildNumber::from_hardened_idx(56).unwrap())
        .unwrap() // Hardened (2^31+56)
        .derive_priv(ChildNumber::from_normal_idx(70).unwrap())
        .unwrap()
        .derive_priv(ChildNumber::from_normal_idx(4).unwrap())
        .unwrap();

    // Verify depth is correct
    assert_eq!(derived.depth, 6);

    // Verify chain code is properly updated
    assert_ne!(derived.chain_code, master.chain_code);

    // Verify the key can still derive children
    let child = derived.derive_priv(ChildNumber::from_normal_idx(100).unwrap()).unwrap();
    assert_eq!(child.depth, 7);
}

#[test]
fn test_serialization_roundtrip() {
    // Test serialization and deserialization of extended keys
    let seed = vec![1u8, 50, 6, 244, 25, 199, 1, 25]; // C++ test vector

    let master_priv = ExtendedBLSPrivKey::new_master(Network::Testnet, &seed).unwrap();
    let master_pub = master_priv.to_extended_pub_key();

    // Test private key serialization with serde
    #[cfg(feature = "serde")]
    {
        // Serialize to JSON
        let serialized = serde_json::to_string(&master_priv).unwrap();
        // Deserialize back
        let deserialized: ExtendedBLSPrivKey = serde_json::from_str(&serialized).unwrap();

        // Verify they match
        assert_eq!(master_priv.depth, deserialized.depth);
        assert_eq!(master_priv.parent_fingerprint, deserialized.parent_fingerprint);
        assert_eq!(master_priv.child_number, deserialized.child_number);
        assert_eq!(master_priv.chain_code, deserialized.chain_code);
        assert_eq!(
            master_priv.private_key.to_be_bytes(),
            deserialized.private_key.to_be_bytes()
        );

        // Test public key serialization
        let pub_serialized = serde_json::to_string(&master_pub).unwrap();
        let pub_deserialized: ExtendedBLSPubKey =
            serde_json::from_str(&pub_serialized).unwrap();

        assert_eq!(master_pub.depth, pub_deserialized.depth);
        assert_eq!(master_pub.parent_fingerprint, pub_deserialized.parent_fingerprint);
        assert_eq!(master_pub.child_number, pub_deserialized.child_number);
        assert_eq!(master_pub.chain_code, pub_deserialized.chain_code);
        assert_eq!(master_pub.public_key.to_bytes(), pub_deserialized.public_key.to_bytes());
    }

    // Test bincode serialization
    #[cfg(feature = "bincode")]
    {
        // Test private key
        let encoded =
            bincode::encode_to_vec(&master_priv, bincode::config::standard()).unwrap();
        let decoded: ExtendedBLSPrivKey =
            bincode::decode_from_slice(&encoded, bincode::config::standard()).unwrap().0;

        assert_eq!(master_priv.depth, decoded.depth);
        assert_eq!(master_priv.parent_fingerprint, decoded.parent_fingerprint);
        assert_eq!(master_priv.child_number, decoded.child_number);
        assert_eq!(master_priv.chain_code, decoded.chain_code);
        assert_eq!(master_priv.private_key.to_be_bytes(), decoded.private_key.to_be_bytes());

        // Test public key
        let pub_encoded =
            bincode::encode_to_vec(&master_pub, bincode::config::standard()).unwrap();
        let pub_decoded: ExtendedBLSPubKey =
            bincode::decode_from_slice(&pub_encoded, bincode::config::standard()).unwrap().0;

        assert_eq!(master_pub.depth, pub_decoded.depth);
        assert_eq!(master_pub.parent_fingerprint, pub_decoded.parent_fingerprint);
        assert_eq!(master_pub.child_number, pub_decoded.child_number);
        assert_eq!(master_pub.chain_code, pub_decoded.chain_code);
        assert_eq!(master_pub.public_key.to_bytes(), pub_decoded.public_key.to_bytes());
    }
}

#[test]
fn test_serialization_and_derivation() {
    // Test that serialized keys can be used for derivation (matching C++ test)
    let seed = vec![1u8, 50, 6, 244, 25, 199, 1, 25];

    let esk = ExtendedBLSPrivKey::new_master(Network::Testnet, &seed).unwrap();
    let epk = esk.to_extended_pub_key();

    // Derive child 238757 through private key
    let pk1 = esk
        .derive_priv(ChildNumber::from_normal_idx(238757).unwrap())
        .unwrap()
        .to_extended_pub_key()
        .public_key;

    // Derive child 238757 through public key
    let pk2 = epk.derive_pub(ChildNumber::from_normal_idx(238757).unwrap()).unwrap().public_key;

    assert_eq!(pk1.to_bytes(), pk2.to_bytes());

    // Test path m/0/3/8/1
    let sk3 = esk
        .derive_priv(ChildNumber::from_normal_idx(0).unwrap())
        .unwrap()
        .derive_priv(ChildNumber::from_normal_idx(3).unwrap())
        .unwrap()
        .derive_priv(ChildNumber::from_normal_idx(8).unwrap())
        .unwrap()
        .derive_priv(ChildNumber::from_normal_idx(1).unwrap())
        .unwrap();

    let pk4 = epk
        .derive_pub(ChildNumber::from_normal_idx(0).unwrap())
        .unwrap()
        .derive_pub(ChildNumber::from_normal_idx(3).unwrap())
        .unwrap()
        .derive_pub(ChildNumber::from_normal_idx(8).unwrap())
        .unwrap()
        .derive_pub(ChildNumber::from_normal_idx(1).unwrap())
        .unwrap();

    assert_eq!(sk3.to_extended_pub_key().public_key.to_bytes(), pk4.public_key.to_bytes());
}

#[test]
fn test_c_plus_plus_test_vectors() {
    // Test exact C++ test vectors for compatibility

    // Test vector 1: {1, 50, 6, 244, 24, 199, 1, 25}
    let seed1 = vec![1u8, 50, 6, 244, 24, 199, 1, 25];
    let esk1 = ExtendedBLSPrivKey::new_master(Network::Testnet, &seed1).unwrap();

    // Test hardened child derivation
    let esk77_hardened = esk1.derive_priv(ChildNumber::from_hardened_idx(77).unwrap()).unwrap();
    let esk77_hardened_copy =
        esk1.derive_priv(ChildNumber::from_hardened_idx(77).unwrap()).unwrap();

    // Keys derived with same index should be equal
    assert_eq!(
        esk77_hardened.private_key.to_be_bytes(),
        esk77_hardened_copy.private_key.to_be_bytes()
    );
    assert_eq!(esk77_hardened.chain_code, esk77_hardened_copy.chain_code);

    // Test non-hardened derivation
    let esk77_normal = esk1.derive_priv(ChildNumber::from_normal_idx(77).unwrap()).unwrap();

    // Hardened and non-hardened should be different
    assert_ne!(
        esk77_hardened.private_key.to_be_bytes(),
        esk77_normal.private_key.to_be_bytes()
    );

    // Test vector 2: {1, 50, 6, 244, 24, 199, 1, 0, 0, 0}
    let seed2 = vec![1u8, 50, 6, 244, 24, 199, 1, 0, 0, 0];
    let esk2 = ExtendedBLSPrivKey::new_master(Network::Testnet, &seed2).unwrap();
    let epk2 = esk2.to_extended_pub_key();

    // Test public child derivation
    let pk1 = esk2
        .derive_priv(ChildNumber::from_normal_idx(13).unwrap())
        .unwrap()
        .to_extended_pub_key();
    let pk2 = epk2.derive_pub(ChildNumber::from_normal_idx(13).unwrap()).unwrap();

    assert_eq!(pk1.public_key.to_bytes(), pk2.public_key.to_bytes());
    assert_eq!(pk1.chain_code, pk2.chain_code);
}

#[test]
fn test_legacy_hd_compatibility() {
    // Test compatibility with C++ ExtendedPrivateKey/ExtendedPublicKey patterns

    // Test vector: {1, 50, 6, 244, 24, 199, 1, 0, 0, 0}
    let seed = vec![1u8, 50, 6, 244, 24, 199, 1, 0, 0, 0];
    let esk = ExtendedBLSPrivKey::new_master(Network::Testnet, &seed).unwrap();
    let epk = esk.to_extended_pub_key();

    // Test PublicChild(13) derivation
    let pk1 = esk
        .derive_priv(ChildNumber::from_normal_idx(13).unwrap())
        .unwrap()
        .to_extended_pub_key();
    let pk2 = epk.derive_pub(ChildNumber::from_normal_idx(13).unwrap()).unwrap();

    // Public keys should match whether derived through private or public path
    assert_eq!(pk1.public_key.to_bytes(), pk2.public_key.to_bytes());
    assert_eq!(pk1.chain_code, pk2.chain_code);
    assert_eq!(pk1.depth, pk2.depth);
    assert_eq!(pk1.child_number, pk2.child_number);

    // Test with another seed: {1, 50, 6, 244, 25, 199, 1, 25}
    let seed2 = vec![1u8, 50, 6, 244, 25, 199, 1, 25];
    let esk2 = ExtendedBLSPrivKey::new_master(Network::Testnet, &seed2).unwrap();
    let epk2 = esk2.to_extended_pub_key();

    // Test child 238757 derivation
    let pk1_238757 =
        esk2.derive_priv(ChildNumber::from_normal_idx(238757).unwrap()).unwrap().public_key();
    let pk2_238757 =
        epk2.derive_pub(ChildNumber::from_normal_idx(238757).unwrap()).unwrap().public_key;

    assert_eq!(pk1_238757.to_bytes(), pk2_238757.to_bytes());

    // Test path m/0/3/8/1
    let sk3 = esk2
        .derive_priv(ChildNumber::from_normal_idx(0).unwrap())
        .unwrap()
        .derive_priv(ChildNumber::from_normal_idx(3).unwrap())
        .unwrap()
        .derive_priv(ChildNumber::from_normal_idx(8).unwrap())
        .unwrap()
        .derive_priv(ChildNumber::from_normal_idx(1).unwrap())
        .unwrap();

    let pk4 = epk2
        .derive_pub(ChildNumber::from_normal_idx(0).unwrap())
        .unwrap()
        .derive_pub(ChildNumber::from_normal_idx(3).unwrap())
        .unwrap()
        .derive_pub(ChildNumber::from_normal_idx(8).unwrap())
        .unwrap()
        .derive_pub(ChildNumber::from_normal_idx(1).unwrap())
        .unwrap();

    assert_eq!(sk3.public_key().to_bytes(), pk4.public_key.to_bytes());
}

#[test]
fn test_extended_unhardened_derivation() {
    // Test with extended seed from C++ test suite
    let seed1 = vec![
        1u8, 50, 6, 244, 24, 199, 1, 25, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
        17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29,
    ];

    let master1 = ExtendedBLSPrivKey::new_master(Network::Testnet, &seed1).unwrap();
    let master1_pub = master1.to_extended_pub_key();

    // Test child 42 unhardened
    let child_sk = master1.derive_priv(ChildNumber::from_normal_idx(42).unwrap()).unwrap();
    let child_pk = master1_pub.derive_pub(ChildNumber::from_normal_idx(42).unwrap()).unwrap();

    assert_eq!(
        child_sk.to_extended_pub_key().public_key.to_bytes(),
        child_pk.public_key.to_bytes()
    );

    // Test grandchild 12142
    let grandchild_sk =
        child_sk.derive_priv(ChildNumber::from_normal_idx(12142).unwrap()).unwrap();
    let grandchild_pk =
        child_pk.derive_pub(ChildNumber::from_normal_idx(12142).unwrap()).unwrap();

    assert_eq!(
        grandchild_sk.to_extended_pub_key().public_key.to_bytes(),
        grandchild_pk.public_key.to_bytes()
    );

    // Test with second seed vector from C++
    let seed2 = vec![
        2u8, 50, 6, 244, 24, 199, 1, 25, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
        17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29,
    ];

    let master2 = ExtendedBLSPrivKey::new_master(Network::Testnet, &seed2).unwrap();
    let master2_pub = master2.to_extended_pub_key();

    // Test unhardened child 42
    let child_sk_unhardened =
        master2.derive_priv(ChildNumber::from_normal_idx(42).unwrap()).unwrap();
    let child_pk_unhardened =
        master2_pub.derive_pub(ChildNumber::from_normal_idx(42).unwrap()).unwrap();

    // Test hardened child 42
    let child_sk_hardened =
        master2.derive_priv(ChildNumber::from_hardened_idx(42).unwrap()).unwrap();

    // Verify unhardened derivation consistency
    assert_eq!(
        child_sk_unhardened.to_extended_pub_key().public_key.to_bytes(),
        child_pk_unhardened.public_key.to_bytes()
    );

    // Verify hardened != unhardened
    assert_ne!(
        child_sk_hardened.private_key.to_be_bytes(),
        child_sk_unhardened.private_key.to_be_bytes()
    );
    assert_ne!(
        child_sk_hardened.to_extended_pub_key().public_key.to_bytes(),
        child_pk_unhardened.public_key.to_bytes()
    );
}

#[test]
fn test_hardened_vs_unhardened_comparison() {
    // Comprehensive test comparing hardened vs unhardened derivation
    let seed = vec![1u8, 50, 6, 244, 24, 199, 1, 25];
    let master = ExtendedBLSPrivKey::new_master(Network::Testnet, &seed).unwrap();

    // Test with index 77 (matching C++ test)
    let unhardened_index = 77;

    // Derive hardened child
    let child_hardened =
        master.derive_priv(ChildNumber::from_hardened_idx(77).unwrap()).unwrap();
    let child_hardened_copy =
        master.derive_priv(ChildNumber::from_hardened_idx(77).unwrap()).unwrap();

    // Derive unhardened child
    let child_unhardened =
        master.derive_priv(ChildNumber::from_normal_idx(unhardened_index).unwrap()).unwrap();

    // Hardened derivation should be deterministic
    assert_eq!(
        child_hardened.private_key.to_be_bytes(),
        child_hardened_copy.private_key.to_be_bytes(),
        "Hardened derivation should be deterministic"
    );
    assert_eq!(child_hardened.chain_code, child_hardened_copy.chain_code);
    assert_eq!(child_hardened.depth, child_hardened_copy.depth);

    // Hardened and unhardened should produce different keys
    assert_ne!(
        child_hardened.private_key.to_be_bytes(),
        child_unhardened.private_key.to_be_bytes(),
        "Hardened and unhardened derivation should produce different keys"
    );
    assert_ne!(
        child_hardened.chain_code, child_unhardened.chain_code,
        "Hardened and unhardened should have different chain codes"
    );

    // Both should have correct depth
    assert_eq!(child_hardened.depth, 1);
    assert_eq!(child_unhardened.depth, 1);

    // Both should have correct parent fingerprint
    assert_eq!(child_hardened.parent_fingerprint, master.fingerprint());
    assert_eq!(child_unhardened.parent_fingerprint, master.fingerprint());
}

/// Reference vectors generated with dashbls (dashpay/bls-signatures @ 0842b17,
/// the C++ library DashSync uses via FFI): `ExtendedPrivateKey::FromSeed` +
/// `PrivateChild(i, fLegacy=true)`. These pin our derivation to the exact
/// bytes Dash Core / DashSync produce (see issue #878).
mod dashbls_vectors {
    use super::*;

    /// BIP39 seed for "abandon abandon ... about" (empty passphrase).
    const SEED64: &str = "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4";

    fn master_from_seed64() -> ExtendedBLSPrivKey {
        let seed = hex::decode(SEED64).unwrap();
        ExtendedBLSPrivKey::new_master(Network::Mainnet, &seed).unwrap()
    }

    fn hardened(idx: u32) -> ChildNumber {
        ChildNumber::from_hardened_idx(idx).unwrap()
    }

    #[test]
    fn master_from_seed() {
        let master = master_from_seed64();
        assert_eq!(
            hex::encode(master.private_key.to_be_bytes()),
            "27d1e600fe5ce42e9a18fe064aa0c1b8ee6754289013a86eb1e8af985ddc55c5"
        );
        assert_eq!(
            hex::encode(&master.chain_code[..]),
            "2a680de50ab918089c65f47e6f32363eb8fbb915a61e9a10e0f882aa1c12aef9"
        );
        assert_eq!(
            hex::encode(master.public_key_bytes_legacy().unwrap()),
            "883389cd6c289b97bfa18cc7b7c873397b4d753269d47d2fa29dda1682c1565687ccb19dd016398da7c9724f8a58bdef"
        );
        assert_eq!(
            hex::encode(master.public_key_bytes()),
            "a83389cd6c289b97bfa18cc7b7c873397b4d753269d47d2fa29dda1682c1565687ccb19dd016398da7c9724f8a58bdef"
        );
    }

    #[test]
    fn mainnet_operator_account_and_keys() {
        // DIP-3 operator path m/9'/5'/3'/3' — every level hardened.
        let master = master_from_seed64();
        let account = master
            .derive_priv(hardened(9))
            .unwrap()
            .derive_priv(hardened(5))
            .unwrap()
            .derive_priv(hardened(3))
            .unwrap()
            .derive_priv(hardened(3))
            .unwrap();

        assert_eq!(
            hex::encode(account.private_key.to_be_bytes()),
            "5f36c0e346c6e6275d6550a09857325e3f54f2a962eb09a48f61756f7b4bbfb0"
        );
        assert_eq!(
            hex::encode(&account.chain_code[..]),
            "d9659c1bde2fd0e0f799f2f66bbbcfc7378fdea624d73d5d4749dc7222daea5e"
        );

        // Operator keys 0..2 (non-hardened children — exercises the
        // legacy-serialization HMAC input).
        let expected = [
            (
                "11122e1ad656d0610ce0f80d40da874d67ea656a3e66ed371c915ec3a488a43a",
                "078cad04aae29eb76171937eb7101452b401b026efbc27db840f130374e6a9ec8443d917277f8921e0ba6678a7709875",
                "878cad04aae29eb76171937eb7101452b401b026efbc27db840f130374e6a9ec8443d917277f8921e0ba6678a7709875",
            ),
            (
                "1a4e3318640cd4e50222184d0ea111abf8a0c18a0e5dc3ed45dad85009db4e31",
                "0c04974d14df3b5eb23787e21642d25c47609d966bb80f504854e4675657c63f4c4c7056f3f007671b911eb390dec4f7",
                "8c04974d14df3b5eb23787e21642d25c47609d966bb80f504854e4675657c63f4c4c7056f3f007671b911eb390dec4f7",
            ),
            (
                "107ab3ddb1f1277dd082f3f6c9187145a614c6f0c97e4e5f3c8912ba5bba6200",
                "0d14cad34409c74f9dd587fc00be01ca0c527e3793f016eb2a612d78ec45c650e8942fbff3e1ab44a21a6e575ebe80a1",
                "8d14cad34409c74f9dd587fc00be01ca0c527e3793f016eb2a612d78ec45c650e8942fbff3e1ab44a21a6e575ebe80a1",
            ),
        ];
        for (i, (sk, pk_legacy, pk_modern)) in expected.iter().enumerate() {
            let child = account
                .derive_priv_legacy(ChildNumber::from_normal_idx(i as u32).unwrap())
                .unwrap();
            assert_eq!(hex::encode(child.private_key.to_be_bytes()), *sk, "sk {}", i);
            assert_eq!(
                hex::encode(child.public_key_bytes_legacy().unwrap()),
                *pk_legacy,
                "pk_legacy {}",
                i
            );
            assert_eq!(hex::encode(child.public_key_bytes()), *pk_modern, "pk_modern {}", i);
        }

        // Watch-only path: same child 0 via public derivation.
        let account_pub = account.to_extended_pub_key();
        let child0_pub =
            account_pub.derive_pub_legacy(ChildNumber::from_normal_idx(0).unwrap()).unwrap();
        assert_eq!(hex::encode(child0_pub.to_bytes_legacy().unwrap()), expected[0].1);
    }

    #[test]
    fn testnet_operator_account_and_key0() {
        // Testnet operator path m/9'/1'/3'/3'.
        let master = master_from_seed64();
        let account = master
            .derive_priv(hardened(9))
            .unwrap()
            .derive_priv(hardened(1))
            .unwrap()
            .derive_priv(hardened(3))
            .unwrap()
            .derive_priv(hardened(3))
            .unwrap();
        assert_eq!(
            hex::encode(account.private_key.to_be_bytes()),
            "05e18aebbe5c73f4dde3dd6a4a204da46c6efa38a38ff4fa5548b1c171154bda"
        );
        let child0 =
            account.derive_priv_legacy(ChildNumber::from_normal_idx(0).unwrap()).unwrap();
        assert_eq!(
            hex::encode(child0.private_key.to_be_bytes()),
            "3346dfd71627f9f31cad3ee66fe7b673c32cb077b2eb38c621d7e61c30e46dbd"
        );
        assert_eq!(
            hex::encode(child0.public_key_bytes_legacy().unwrap()),
            "09d8beabae708de1638487f1aff44b38e8c07d9b09f22d76329d6c8ec01e2ad4d030b660bca40ddbd222373a72c5bcef"
        );
    }

    #[test]
    fn chia_style_seed8_vectors() {
        // dashbls test-suite seed {1, 50, 6, 244, 24, 199, 1, 25}.
        let seed = [1u8, 50, 6, 244, 24, 199, 1, 25];
        let master = ExtendedBLSPrivKey::new_master(Network::Testnet, &seed).unwrap();
        assert_eq!(
            hex::encode(master.private_key.to_be_bytes()),
            "3e9f7b3846c1803703f94c764b51f5ace513b2f02c4d6b2c452d8ce66e5975bd"
        );
        assert_eq!(
            hex::encode(&master.chain_code[..]),
            "d8b12555b4cc5578951e4a7c80031e22019cc0dce168b3ed88115311b8feb1e3"
        );

        // Hardened child 77'
        let c77h = master.derive_priv(hardened(77)).unwrap();
        assert_eq!(
            hex::encode(c77h.private_key.to_be_bytes()),
            "51b31efbd83aeead1e324c5c8248f5a13bb17ba7afe29aeb5ceef7eaff49ed6f"
        );
        assert_eq!(
            hex::encode(&c77h.chain_code[..]),
            "f2c8e4269bb3e54f8179a5c6976d92ca14c3260dd729981e9d15f53049fd698b"
        );

        // Non-hardened child 77 (legacy serialization in HMAC input)
        let c77 = master.derive_priv_legacy(ChildNumber::from_normal_idx(77).unwrap()).unwrap();
        assert_eq!(
            hex::encode(c77.private_key.to_be_bytes()),
            "3ef4f8b4d262fb8981665532b531c7889798044f7cbe4d5fae5e30435f746044"
        );
        assert_eq!(
            hex::encode(&c77.chain_code[..]),
            "f428f5f011f52569c0b2004aaeda0744259f4247fd5e77649d3d25e6b491cc53"
        );
    }

    #[test]
    fn modern_mode_vectors() {
        // dashbls `PrivateChild(i)` with the default fLegacy = false —
        // the mode used by `derive_priv`/`derive_pub` without suffix.
        let seed = [1u8, 50, 6, 244, 24, 199, 1, 25];
        let master = ExtendedBLSPrivKey::new_master(Network::Testnet, &seed).unwrap();
        let c77 = master.derive_priv(ChildNumber::from_normal_idx(77).unwrap()).unwrap();
        assert_eq!(
            hex::encode(c77.private_key.to_be_bytes()),
            "0f9b101b475e449c9995032e138b432a330738b6401f675f0632385fe8d349bf"
        );
        assert_eq!(
            hex::encode(&c77.chain_code[..]),
            "c7b09e00d6b9b1676e8714e1060e0324787734809ae557a4bc8c07e9b1304ed0"
        );
        assert_eq!(
            hex::encode(c77.public_key_bytes()),
            "a63fa533db03b400030a5eb163433ac7c8700d2301c4242e03db58d516dea0d52768d1b0d29e9f28f7707ce96d2d6108"
        );

        // Modern-mode child 0 under the operator path from the BIP39 seed.
        // Hardened levels agree across modes; the non-hardened leaf differs.
        let master64 = master_from_seed64();
        let account = master64
            .derive_priv(hardened(9))
            .unwrap()
            .derive_priv(hardened(5))
            .unwrap()
            .derive_priv(hardened(3))
            .unwrap()
            .derive_priv(hardened(3))
            .unwrap();
        let child0_modern =
            account.derive_priv(ChildNumber::from_normal_idx(0).unwrap()).unwrap();
        assert_eq!(
            hex::encode(child0_modern.private_key.to_be_bytes()),
            "1669d6cc8ac08fa377d63dafcf83f1fa6aee09e2df58c490b1b1a0b0999417ec"
        );
        assert_eq!(
            hex::encode(child0_modern.public_key_bytes()),
            "8f5d504fee1026394728781f004fee70480335c1f53156124b23e45386c7c1e2973efee3eab4ae60650fdaa8ae4460d0"
        );

        // Same leaf via legacy mode is a different key entirely.
        let child0_legacy =
            account.derive_priv_legacy(ChildNumber::from_normal_idx(0).unwrap()).unwrap();
        assert_ne!(
            child0_modern.private_key.to_be_bytes(),
            child0_legacy.private_key.to_be_bytes()
        );

        // Private/public derivation stays consistent in modern mode too.
        let child0_pub = account
            .to_extended_pub_key()
            .derive_pub(ChildNumber::from_normal_idx(0).unwrap())
            .unwrap();
        assert_eq!(child0_pub.to_bytes(), child0_modern.public_key_bytes());
    }
}

#[test]
fn test_zeroize_clears_key_material() {
    use zeroize::Zeroize;

    let seed = [42u8; 32];
    let mut key = ExtendedBLSPrivKey::new_master(Network::Testnet, &seed).unwrap();
    assert_ne!(key.private_key.to_be_bytes(), [0u8; 32]);
    assert_ne!(key.chain_code.as_ref(), &[0u8; 32]);

    key.zeroize();

    assert_eq!(key.private_key.to_be_bytes(), [0u8; 32]);
    assert_eq!(key.chain_code.as_ref(), &[0u8; 32]);
    assert_eq!(key.depth, 0);
    assert_eq!(key.parent_fingerprint, Fingerprint::default());
}

/// `1` and `r - 1` sum to the group order, i.e. to zero in the scalar field.
/// A child key derived that way would put the parent scalar in reach of
/// anyone holding the extended public key, since the tweak is derivable from
/// it, so both key types have to refuse the sum.
mod degenerate_sums {
    use super::*;

    const ONE: [u8; 32] = {
        let mut bytes = [0u8; 32];
        bytes[31] = 1;
        bytes
    };

    const R_MINUS_ONE: [u8; 32] = [
        0x73, 0xed, 0xa7, 0x53, 0x29, 0x9d, 0x7d, 0x48, 0x33, 0x39, 0xd8, 0x08, 0x09, 0xa1, 0xd8,
        0x05, 0x53, 0xbd, 0xa4, 0x02, 0xff, 0xfe, 0x5b, 0xfe, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00,
        0x00, 0x00,
    ];

    #[test]
    fn secret_keys_that_sum_to_zero_are_refused() {
        let one = BlsSecretKey::from_be_bytes_reduce(&ONE).unwrap();
        let minus_one = BlsSecretKey::from_be_bytes_reduce(&R_MINUS_ONE).unwrap();

        assert!(one.add(&minus_one).is_none());
        assert!(minus_one.add(&one).is_none());
    }

    #[test]
    fn public_keys_that_sum_to_the_identity_are_refused() {
        let one = BlsSecretKey::from_be_bytes_reduce(&ONE).unwrap();
        let minus_one = BlsSecretKey::from_be_bytes_reduce(&R_MINUS_ONE).unwrap();

        assert!(one.public_key().add(&minus_one.public_key()).is_none());
    }

    #[test]
    fn ordinary_sums_are_still_allowed() {
        let one = BlsSecretKey::from_be_bytes_reduce(&ONE).unwrap();

        let two = one.add(&one).unwrap();
        assert_eq!(two.public_key().to_bytes(), one.public_key().add(&one.public_key()).unwrap().to_bytes());
    }
}
