//! Serialization for extended BLS keys.

use dashcore::blsful::SerializationFormat;
use dashcore::blsful::{Bls12381G2Impl, PublicKey as BlsPublicKey, SecretKey as BlsSecretKey};
use dashcore::Network;
#[cfg(feature = "serde")]
use serde::Deserialize;

use crate::bip32::{ChainCode, ChildNumber, Fingerprint};
use crate::bls::hd::{ExtendedBLSPrivKey, ExtendedBLSPubKey};

// Manual serde implementations for ExtendedBLSPrivKey
#[cfg(feature = "serde")]
impl serde::Serialize for ExtendedBLSPrivKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("ExtendedBLSPrivKey", 6)?;
        state.serialize_field("network", &self.network)?;
        state.serialize_field("depth", &self.depth)?;
        state.serialize_field("parent_fingerprint", &self.parent_fingerprint)?;
        state.serialize_field("child_number", &self.child_number)?;
        state.serialize_field("private_key", &self.private_key.to_be_bytes())?;
        state.serialize_field("chain_code", &self.chain_code)?;
        state.end()
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for ExtendedBLSPrivKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Helper {
            network: Network,
            depth: u8,
            parent_fingerprint: Fingerprint,
            child_number: ChildNumber,
            private_key: [u8; 32],
            chain_code: ChainCode,
        }

        let helper = Helper::deserialize(deserializer)?;
        let private_key = BlsSecretKey::<Bls12381G2Impl>::from_be_bytes(&helper.private_key)
            .into_option()
            .ok_or_else(|| serde::de::Error::custom("Invalid BLS private key"))?;

        Ok(ExtendedBLSPrivKey {
            network: helper.network,
            depth: helper.depth,
            parent_fingerprint: helper.parent_fingerprint,
            child_number: helper.child_number,
            private_key,
            chain_code: helper.chain_code,
        })
    }
}

// Manual serde implementations for ExtendedBLSPubKey
#[cfg(feature = "serde")]
impl serde::Serialize for ExtendedBLSPubKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("ExtendedBLSPubKey", 6)?;
        state.serialize_field("network", &self.network)?;
        state.serialize_field("depth", &self.depth)?;
        state.serialize_field("parent_fingerprint", &self.parent_fingerprint)?;
        state.serialize_field("child_number", &self.child_number)?;
        state.serialize_field("public_key", &self.public_key.to_bytes())?;
        state.serialize_field("chain_code", &self.chain_code)?;
        state.end()
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for ExtendedBLSPubKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Helper {
            network: Network,
            depth: u8,
            parent_fingerprint: Fingerprint,
            child_number: ChildNumber,
            public_key: Vec<u8>,
            chain_code: ChainCode,
        }

        let helper = Helper::deserialize(deserializer)?;
        let public_key = BlsPublicKey::<Bls12381G2Impl>::from_bytes_with_mode(
            &helper.public_key,
            SerializationFormat::Modern,
        )
        .map_err(|e| serde::de::Error::custom(format!("Invalid BLS public key: {}", e)))?;

        Ok(ExtendedBLSPubKey {
            network: helper.network,
            depth: helper.depth,
            parent_fingerprint: helper.parent_fingerprint,
            child_number: helper.child_number,
            public_key,
            chain_code: helper.chain_code,
        })
    }
}

// Manual bincode implementations for ExtendedBLSPrivKey
#[cfg(feature = "bincode")]
impl bincode::Encode for ExtendedBLSPrivKey {
    fn encode<E: bincode::enc::Encoder>(
        &self,
        encoder: &mut E,
    ) -> Result<(), bincode::error::EncodeError> {
        self.network.encode(encoder)?;
        self.depth.encode(encoder)?;
        self.parent_fingerprint.encode(encoder)?;
        self.child_number.encode(encoder)?;
        // Encode private key as bytes
        let private_key_bytes = self.private_key.to_be_bytes();
        private_key_bytes.encode(encoder)?;
        self.chain_code.encode(encoder)?;
        Ok(())
    }
}

#[cfg(feature = "bincode")]
impl<C> bincode::Decode<C> for ExtendedBLSPrivKey {
    fn decode<D: bincode::de::Decoder<Context = C>>(
        decoder: &mut D,
    ) -> Result<Self, bincode::error::DecodeError> {
        let network = Network::decode(decoder)?;
        let depth = u8::decode(decoder)?;
        let parent_fingerprint = Fingerprint::decode(decoder)?;
        let child_number = ChildNumber::decode(decoder)?;
        let private_key_bytes: [u8; 32] = <[u8; 32]>::decode(decoder)?;
        let private_key = BlsSecretKey::<Bls12381G2Impl>::from_be_bytes(&private_key_bytes)
            .into_option()
            .ok_or_else(|| {
                bincode::error::DecodeError::OtherString("Invalid BLS private key".to_string())
            })?;
        let chain_code = ChainCode::decode(decoder)?;

        Ok(ExtendedBLSPrivKey {
            network,
            depth,
            parent_fingerprint,
            child_number,
            private_key,
            chain_code,
        })
    }
}

#[cfg(feature = "bincode")]
impl<'de, C> bincode::BorrowDecode<'de, C> for ExtendedBLSPrivKey {
    fn borrow_decode<D: bincode::de::BorrowDecoder<'de, Context = C>>(
        decoder: &mut D,
    ) -> Result<Self, bincode::error::DecodeError> {
        <Self as bincode::Decode<C>>::decode(decoder)
    }
}

// Manual bincode implementations for ExtendedBLSPubKey
#[cfg(feature = "bincode")]
impl bincode::Encode for ExtendedBLSPubKey {
    fn encode<E: bincode::enc::Encoder>(
        &self,
        encoder: &mut E,
    ) -> Result<(), bincode::error::EncodeError> {
        self.network.encode(encoder)?;
        self.depth.encode(encoder)?;
        self.parent_fingerprint.encode(encoder)?;
        self.child_number.encode(encoder)?;
        // Encode public key as bytes
        let public_key_bytes = self.public_key.to_bytes();
        public_key_bytes.encode(encoder)?;
        self.chain_code.encode(encoder)?;
        Ok(())
    }
}

#[cfg(feature = "bincode")]
impl<C> bincode::Decode<C> for ExtendedBLSPubKey {
    fn decode<D: bincode::de::Decoder<Context = C>>(
        decoder: &mut D,
    ) -> Result<Self, bincode::error::DecodeError> {
        let network = Network::decode(decoder)?;
        let depth = u8::decode(decoder)?;
        let parent_fingerprint = Fingerprint::decode(decoder)?;
        let child_number = ChildNumber::decode(decoder)?;
        let public_key_bytes: Vec<u8> = Vec::<u8>::decode(decoder)?;
        let public_key = BlsPublicKey::<Bls12381G2Impl>::from_bytes_with_mode(
            &public_key_bytes,
            SerializationFormat::Modern,
        )
        .map_err(|e| {
            bincode::error::DecodeError::OtherString(format!("Invalid BLS public key: {}", e))
        })?;
        let chain_code = ChainCode::decode(decoder)?;

        Ok(ExtendedBLSPubKey {
            network,
            depth,
            parent_fingerprint,
            child_number,
            public_key,
            chain_code,
        })
    }
}

#[cfg(feature = "bincode")]
impl<'de, C> bincode::BorrowDecode<'de, C> for ExtendedBLSPubKey {
    fn borrow_decode<D: bincode::de::BorrowDecoder<'de, Context = C>>(
        decoder: &mut D,
    ) -> Result<Self, bincode::error::DecodeError> {
        <Self as bincode::Decode<C>>::decode(decoder)
    }
}
