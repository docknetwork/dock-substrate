use crate::util::{Bytes32, Bytes33};
use codec::{Decode, Encode, MaxEncodedLen};
use sp_core::{ed25519, sr25519};

use super::signatures::{sign_with_secp256k1, SigValue};

/// An abstraction for a public key. Abstracts the type and value of the public key where the value is a
/// byte array
#[derive(Encode, Decode, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, MaxEncodedLen)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(scale_info_derive::TypeInfo)]
#[scale_info(omit_prefix)]
pub enum PublicKey {
    /// Public key for Sr25519 is 32 bytes
    Sr25519(Bytes32),
    /// Public key for Ed25519 is 32 bytes
    Ed25519(Bytes32),
    /// Compressed public key for Secp256k1 is 33 bytes
    Secp256k1(Bytes33),
    /// Compressed X25519 public key, 32 bytes. This key is not used for signing
    X25519(Bytes32),
}

impl From<ed25519::Public> for PublicKey {
    fn from(ed25519::Public(pubkey): ed25519::Public) -> Self {
        PublicKey::ed25519(pubkey)
    }
}

impl From<sr25519::Public> for PublicKey {
    fn from(sr25519::Public(pubkey): sr25519::Public) -> Self {
        PublicKey::sr25519(pubkey)
    }
}

impl From<libsecp256k1::PublicKey> for PublicKey {
    fn from(pubkey: libsecp256k1::PublicKey) -> Self {
        PublicKey::Secp256k1(pubkey.serialize_compressed().into())
    }
}

impl PublicKey {
    pub const fn can_sign(&self) -> bool {
        !matches!(self, PublicKey::X25519(_))
    }

    pub const fn sr25519(bytes: [u8; 32]) -> Self {
        PublicKey::Sr25519(Bytes32(bytes))
    }

    pub const fn ed25519(bytes: [u8; 32]) -> Self {
        PublicKey::Ed25519(Bytes32(bytes))
    }

    pub const fn secp256k1(bytes: [u8; 33]) -> Self {
        PublicKey::Secp256k1(Bytes33(bytes))
    }

    pub const fn x25519(bytes: [u8; 32]) -> Self {
        PublicKey::X25519(Bytes32(bytes))
    }

    pub fn as_slice(&self) -> &[u8] {
        match self {
            Self::Sr25519(bytes) => &bytes[..],
            Self::Ed25519(bytes) => &bytes[..],
            Self::Secp256k1(bytes) => &bytes[..],
            Self::X25519(bytes) => &bytes[..],
        }
    }
}

pub fn get_secp256k1_keypair(
    seed: &[u8; libsecp256k1::util::SECRET_KEY_SIZE],
) -> (libsecp256k1::SecretKey, PublicKey) {
    let sk = libsecp256k1::SecretKey::parse(seed).unwrap();
    let pk = libsecp256k1::PublicKey::from_secret_key(&sk).serialize_compressed();
    (sk, PublicKey::Secp256k1(pk.into()))
}

pub fn get_secp256k1_keypair_struct(
    seed: &[u8; libsecp256k1::util::SECRET_KEY_SIZE],
) -> Secp256k1Keypair {
    let sk = libsecp256k1::SecretKey::parse(seed).unwrap();
    let pk = libsecp256k1::PublicKey::from_secret_key(&sk);

    Secp256k1Keypair { sk, pk }
}

#[derive(Debug, Clone)]
pub struct Secp256k1Keypair {
    pub sk: libsecp256k1::SecretKey,
    pub pk: libsecp256k1::PublicKey,
}

impl Secp256k1Keypair {
    pub fn sign(&self, msg: &[u8]) -> SigValue {
        sign_with_secp256k1(msg, &self.sk)
    }

    pub fn public(&self) -> libsecp256k1::PublicKey {
        self.pk
    }
}
