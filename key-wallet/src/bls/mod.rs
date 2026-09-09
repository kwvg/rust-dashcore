//! BLS12-381 support.
//!
//! [`hd`] holds the BIP32-like key derivation scheme for BLS12-381;
//! [`wallet`] holds the account and address pool layers built on it.

pub mod hd;
pub mod wallet;
