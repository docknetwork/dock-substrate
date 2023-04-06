use crate::util::{Bytes32, Bytes33, Bytes64, Bytes65};
use codec::{Decode, Encode};
use frame_support::dispatch::Weight;
use sha2::{Digest, Sha256};
use sp_core::{ed25519, sr25519, Pair};
use sp_runtime::traits::Verify;
use sp_std::convert::TryInto;

/// An abstraction for a public key. Abstracts the type and value of the public key where the value is a
/// byte array
#[derive(Encode, Decode, Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
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
        PublicKey::Secp256k1(Bytes33 {
            value: pubkey.serialize_compressed(),
        })
    }
}

/// An abstraction for a signature.
#[derive(Encode, Decode, scale_info_derive::TypeInfo, Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[scale_info(omit_prefix)]
pub enum SigValue {
    /// Signature for Sr25519 is 64 bytes
    Sr25519(Bytes64),
    /// Signature for Ed25519 is 64 bytes
    Ed25519(Bytes64),
    /// Signature for Secp256k1 is 65 bytes
    Secp256k1(Bytes65),
}

impl PublicKey {
    pub const fn can_sign(&self) -> bool {
        match self {
            PublicKey::X25519(_) => false,
            _ => true,
        }
    }

    pub const fn sr25519(bytes: [u8; 32]) -> Self {
        PublicKey::Sr25519(Bytes32 { value: bytes })
    }

    pub const fn ed25519(bytes: [u8; 32]) -> Self {
        PublicKey::Ed25519(Bytes32 { value: bytes })
    }

    pub const fn secp256k1(bytes: [u8; 33]) -> Self {
        PublicKey::Secp256k1(Bytes33 { value: bytes })
    }

    pub const fn x25519(bytes: [u8; 32]) -> Self {
        PublicKey::X25519(Bytes32 { value: bytes })
    }

    pub fn as_slice(&self) -> &[u8] {
        match self {
            Self::Sr25519(bytes) => &bytes.value[..],
            Self::Ed25519(bytes) => &bytes.value[..],
            Self::Secp256k1(bytes) => &bytes.value[..],
            Self::X25519(bytes) => &bytes.value[..],
        }
    }
}

impl From<ed25519::Signature> for SigValue {
    fn from(ed25519::Signature(sig): ed25519::Signature) -> Self {
        SigValue::Ed25519(sig.into())
    }
}

impl From<sr25519::Signature> for SigValue {
    fn from(sr25519::Signature(sig): sr25519::Signature) -> Self {
        SigValue::Sr25519(sig.into())
    }
}

impl SigValue {
    /// Try to get reference to the bytes if its a Sr25519 signature. Return error if its not.
    pub fn as_sr25519_sig_bytes(&self) -> Result<&[u8], ()> {
        match self {
            SigValue::Sr25519(bytes) => Ok(bytes.as_bytes()),
            _ => Err(()),
        }
    }

    /// Try to get reference to the bytes if its a Ed25519 signature. Return error if its not.
    pub fn as_ed25519_sig_bytes(&self) -> Result<&[u8], ()> {
        match self {
            SigValue::Ed25519(bytes) => Ok(bytes.as_bytes()),
            _ => Err(()),
        }
    }

    /// Try to get reference to the bytes if its a Secp256k1 signature. Return error if its not.
    pub fn as_secp256k1_sig_bytes(&self) -> Result<&[u8], ()> {
        match self {
            SigValue::Secp256k1(bytes) => Ok(bytes.as_bytes()),
            _ => Err(()),
        }
    }

    /// Get weight for signature verification.
    /// Considers the type of signature. Disregards message size as messages are hashed giving the
    /// same output size and hashing itself is very cheap. The extrinsic using it might decide to
    /// consider adding some weight proportional to the message size.
    pub fn weight(&self) -> Weight {
        match self {
            SigValue::Sr25519(_) => SR25519_WEIGHT,
            SigValue::Ed25519(_) => ED25519_WEIGHT,
            SigValue::Secp256k1(_) => SECP256K1_WEIGHT,
        }
    }

    pub fn verify(&self, message: &[u8], public_key: &PublicKey) -> Result<bool, ()> {
        macro_rules! verify {
            ( $message:ident, $sig_bytes:ident, $pk_bytes:ident, $sig_type:expr, $pk_type:expr ) => {{
                let signature = $sig_type($sig_bytes.value);
                let pk = $pk_type($pk_bytes.value);
                signature.verify($message, &pk)
            }};
        }
        let result = match (public_key, self) {
            (PublicKey::Sr25519(pk_bytes), SigValue::Sr25519(sig_bytes)) => {
                verify!(
                    message,
                    sig_bytes,
                    pk_bytes,
                    sr25519::Signature,
                    sr25519::Public
                )
            }
            (PublicKey::Ed25519(pk_bytes), SigValue::Ed25519(sig_bytes)) => {
                verify!(
                    message,
                    sig_bytes,
                    pk_bytes,
                    ed25519::Signature,
                    ed25519::Public
                )
            }
            (PublicKey::Secp256k1(pk_bytes), SigValue::Secp256k1(sig_bytes)) => {
                let hash = Sha256::digest(message).try_into().unwrap();
                let m = libsecp256k1::Message::parse(&hash);
                let sig = libsecp256k1::Signature::parse_overflowing(
                    sig_bytes.value[0..64].try_into().unwrap(),
                );
                let p = libsecp256k1::PublicKey::parse_compressed(&pk_bytes.value).unwrap();
                libsecp256k1::verify(&m, &sig, &p)
            }
            _ => {
                return Err(());
            }
        };
        Ok(result)
    }

    pub fn sr25519(msg: &[u8], pair: &sr25519::Pair) -> Self {
        SigValue::Sr25519(Bytes64 {
            value: pair.sign(msg).0,
        })
    }

    pub fn ed25519(msg: &[u8], pair: &ed25519::Pair) -> Self {
        SigValue::Ed25519(Bytes64 {
            value: pair.sign(msg).0,
        })
    }

    pub fn secp256k1(msg: &[u8], sk: &libsecp256k1::SecretKey) -> Self {
        sign_with_secp256k1(msg, sk)
    }
}

// Weight for Sr25519 sig verification
pub const SR25519_WEIGHT: Weight = Weight::from_ref_time(140_000_000);
// Weight for Ed25519 sig verification
pub const ED25519_WEIGHT: Weight = Weight::from_ref_time(152_000_000);
// Weight for ecdsa using secp256k1 sig verification
pub const SECP256K1_WEIGHT: Weight = Weight::from_ref_time(456_000_000);

// XXX: Substrate UI can't parse them. Maybe later versions will fix it.
/*
/// Size of a Sr25519 public key in bytes.
pub const Sr25519_PK_BYTE_SIZE: usize = 32;
/// Size of a Ed25519 public key in bytes.
pub const Ed25519_PK_BYTE_SIZE: usize = 32;

#[derive(Encode, Decode, scale_info_derive::TypeInfo, Debug, Clone, PartialEq, Eq)]
pub enum PublicKey {
    Sr25519([u8; 32]),
    Ed25519([u8; 32])
}*/

/*#[derive(Encode, Decode, scale_info_derive::TypeInfo, Debug, Clone, PartialEq, Eq)]
pub enum PublicKey {
    Sr25519(Bytes32),
    Ed25519(Bytes32)
}
*/

pub fn get_secp256k1_keypair(
    seed: &[u8; libsecp256k1::util::SECRET_KEY_SIZE],
) -> (libsecp256k1::SecretKey, PublicKey) {
    let sk = libsecp256k1::SecretKey::parse(seed).unwrap();
    let pk = libsecp256k1::PublicKey::from_secret_key(&sk).serialize_compressed();
    (sk, PublicKey::Secp256k1(Bytes33 { value: pk }))
}

pub fn get_secp256k1_keypair_1(
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
        let hash = Sha256::digest(msg).try_into().unwrap();
        let m = libsecp256k1::Message::parse(&hash);
        let sig = libsecp256k1::sign(&m, &self.sk);
        let mut sig_bytes: [u8; 65] = [0; 65];
        sig_bytes[0..64].copy_from_slice(&sig.0.serialize()[..]);
        sig_bytes[64] = sig.1.serialize();

        SigValue::Secp256k1(Bytes65 { value: sig_bytes })
    }

    pub fn public(&self) -> libsecp256k1::PublicKey {
        self.pk
    }
}

pub fn sign_with_secp256k1(msg: &[u8], sk: &libsecp256k1::SecretKey) -> SigValue {
    let hash = Sha256::digest(msg).try_into().unwrap();
    let m = libsecp256k1::Message::parse(&hash);
    let sig = libsecp256k1::sign(&m, sk);
    let mut sig_bytes: [u8; 65] = [0; 65];
    sig_bytes[0..64].copy_from_slice(&sig.0.serialize()[..]);
    sig_bytes[64] = sig.1.serialize();
    SigValue::Secp256k1(Bytes65 { value: sig_bytes })
}

#[cfg(test)]
mod tests {
    use super::*;
    use sp_core::Pair;

    #[test]
    fn signature_verification() {
        // Check that the signature should be wrapped in correct variant of enum `SigValue`.
        // Trying to wrap a Sr25519 signature in a SigValue::Ed25519 should fail.
        // Trying to wrap a Ed25519 signature in a SigValue::Sr25519 should fail.
        let msg = vec![26u8; 350];

        // The macro checks that a signature verification only passes when sig wrapped in `$correct_sig_type`
        // but fails when wrapped in `$incorrect_sig_type`
        macro_rules! check_sig_verification {
            ( $module:ident, $pk_type:expr, $correct_sig_type:expr, $incorrect_sig_type:expr ) => {{
                let (pair, _, _) = $module::Pair::generate_with_phrase(None);
                let pk_bytes = pair.public().0;
                let pk = $pk_type(Bytes32 { value: pk_bytes });
                assert!(pk.can_sign());
                let sig_bytes = pair.sign(&msg).0;
                let correct_sig = $correct_sig_type(Bytes64 { value: sig_bytes });

                // Valid signature wrapped in a correct type works
                assert!(correct_sig.verify(&msg, &pk).unwrap());

                // Valid signature wrapped in an incorrect type does not work
                let incorrect_sig = $incorrect_sig_type(Bytes64 { value: sig_bytes });
                assert!(incorrect_sig.verify(&msg, &pk).is_err())
            }};
        }

        check_sig_verification!(
            sr25519,
            PublicKey::Sr25519,
            SigValue::Sr25519,
            SigValue::Ed25519
        );
        check_sig_verification!(
            ed25519,
            PublicKey::Ed25519,
            SigValue::Ed25519,
            SigValue::Sr25519
        );

        let (sk, pk) = get_secp256k1_keypair(&[1; 32]);
        assert!(pk.can_sign());
        let correct_sig = sign_with_secp256k1(&msg, &sk);
        let incorrect_sig = SigValue::Ed25519(Bytes64 { value: [10; 64] });
        assert!(correct_sig.verify(&msg, &pk).unwrap());
        assert!(incorrect_sig.verify(&msg, &pk).is_err());
    }
}
