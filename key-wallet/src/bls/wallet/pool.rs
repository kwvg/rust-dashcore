//! Provider operator keys held in an address pool.

use crate::bip32::DerivationPath;
use crate::bls::hd::{BlsDerivationMode, BlsPublicKey, ExtendedBLSPrivKey, ExtendedBLSPubKey};
use crate::error::{Error, Result};
use crate::managed_account::address_pool::{self, AddressPool, DerivedKey, PublicKeyType};

/// Derive the operator key at `path` from an extended secret key.
pub(crate) fn derive_secret(xprv: &ExtendedBLSPrivKey, path: &DerivationPath) -> Result<DerivedKey> {
    // BLS HD derivation using the proper BIP32-like derivation
    // Legacy mode: BLS pools exist only for provider operator keys,
    // which dashbls/DashSync derive with fLegacy = true.
    let mut derived = xprv.clone();
    for child_num in path.as_ref() {
        derived = derived.derive_priv_legacy(*child_num).map_err(|e| {
            Error::InvalidParameter(format!("BLS derivation error: {:?}", e))
        })?;
    }
    Ok(DerivedKey::BLS(derived.public_key_bytes().to_vec()))
}

/// Derive the operator key at `path` from an extended public key.
pub(crate) fn derive_public(xpub: &ExtendedBLSPubKey, path: &DerivationPath) -> Result<DerivedKey> {
    // BLS public key derivation for non-hardened paths
    let mut derived = xpub.clone();
    for child_num in path.as_ref() {
        if child_num.is_hardened() {
            return Err(Error::InvalidParameter(
                "Cannot derive hardened child from BLS public key".into(),
            ));
        }
        derived = derived.derive_pub_legacy(*child_num).map_err(|e| {
            Error::InvalidParameter(format!("BLS public derivation error: {:?}", e))
        })?;
    }
    Ok(DerivedKey::BLS(derived.to_bytes().to_vec()))
}

/// Take the next unused operator key from `addresses`.
pub(crate) fn next_operator_key(
    addresses: &mut AddressPool,
    account_xpub: Option<ExtendedBLSPubKey>,
    add_to_state: bool,
) -> core::result::Result<BlsPublicKey, &'static str> {
    let key_source = match account_xpub {
        Some(xpub) => address_pool::KeySource::BLSPublic(xpub),
        None => address_pool::KeySource::NoKeySource,
    };

    let info = addresses
        .next_unused_with_info(&key_source, add_to_state)
        .map_err(|_| "Failed to get next unused address")?;

    let Some(PublicKeyType::BLS(pub_key_bytes)) = info.public_key else {
        return Err("Expected BLS public key but got different key type");
    };

    addresses.mark_index_used(info.index);

    let public_key = BlsPublicKey::from_bytes_with_mode(&pub_key_bytes, BlsDerivationMode::Modern)
        .map_err(|_| "Failed to deserialize BLS public key")?;

    Ok(public_key)
}
