//! Serialization for BLS accounts.

use crate::account::BLSAccount;

#[cfg(feature = "bls")]
impl BLSAccount {
    /// Serialize BLS account to bytes
    #[cfg(feature = "bincode")]
    pub fn to_bytes(&self) -> crate::Result<Vec<u8>> {
        bincode::encode_to_vec(self, bincode::config::standard())
            .map_err(|e| crate::error::Error::Serialization(e.to_string()))
    }

    /// Deserialize BLS account from bytes
    #[cfg(feature = "bincode")]
    pub fn from_bytes(data: &[u8]) -> crate::Result<Self> {
        bincode::decode_from_slice(data, bincode::config::standard())
            .map(|(account, _)| account)
            .map_err(|e| crate::error::Error::Serialization(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use crate::account::BLSAccount;

    #[test]
    #[cfg(all(feature = "bincode", feature = "bls"))]
    fn test_bls_serialization() {
        use crate::account::{account_type::StandardAccountType, AccountTrait, AccountType};
        use crate::derivation_bls_bip32::{ExtendedBLSPrivKey, ExtendedBLSPubKey};
        use crate::Network;

        // Create a valid BLS public key
        let seed = [42u8; 32];
        let bls_private = ExtendedBLSPrivKey::new_master(Network::Testnet, &seed)
            .expect("Failed to create BLS private key from seed");
        let bls_public = ExtendedBLSPubKey::from_private_key(&bls_private);
        let public_key_bytes = bls_public.to_bytes();

        let account = BLSAccount::from_public_key_bytes(
            None,
            AccountType::Standard {
                index: 0,
                standard_account_type: StandardAccountType::BIP44Account,
            },
            public_key_bytes,
            Network::Testnet,
        )
        .expect("Failed to create BLS account from public key bytes");

        let serialized = account.to_bytes().expect("Failed to serialize BLS account");
        let deserialized =
            BLSAccount::from_bytes(&serialized).expect("Failed to deserialize BLS account");

        assert_eq!(account.index(), deserialized.index());
        assert_eq!(account.account_type, deserialized.account_type);
        assert_eq!(account.network, deserialized.network);
        assert_eq!(account.is_watch_only, deserialized.is_watch_only);
    }
}
