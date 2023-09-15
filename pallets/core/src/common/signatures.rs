use super::keys::PublicKey;
use crate::util::{Bytes64, Bytes65};
use codec::{Decode, Encode, MaxEncodedLen};
use frame_support::dispatch::Weight;
use sha2::{Digest, Sha256};
use sp_core::{ed25519, sr25519, Pair};
use sp_runtime::traits::Verify;
use sp_std::convert::TryInto;

/// An abstraction for a signature.
#[derive(
    Encode, Decode, scale_info_derive::TypeInfo, Debug, Clone, PartialEq, Eq, MaxEncodedLen,
)]
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerificationError {
    IncompatibleKey(PublicKey, SigValue),
}

impl SigValue {
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

    pub fn verify(
        &self,
        message: &[u8],
        public_key: &PublicKey,
    ) -> Result<bool, VerificationError> {
        macro_rules! verify {
            ( $message:ident, $sig_bytes:ident, $pk_bytes:ident, $sig_type:expr, $pk_type:expr ) => {{
                let signature = $sig_type(**$sig_bytes);
                let pk = $pk_type(**$pk_bytes);
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
                    sig_bytes[..][0..64].try_into().unwrap(),
                );
                let p = libsecp256k1::PublicKey::parse_compressed(pk_bytes).unwrap();
                libsecp256k1::verify(&m, &sig, &p)
            }
            _ => Err(VerificationError::IncompatibleKey(
                public_key.clone(),
                self.clone(),
            ))?,
        };

        Ok(result)
    }

    pub fn sr25519(msg: &[u8], pair: &sr25519::Pair) -> Self {
        SigValue::Sr25519(pair.sign(msg).0.into())
    }

    pub fn ed25519(msg: &[u8], pair: &ed25519::Pair) -> Self {
        SigValue::Ed25519(pair.sign(msg).0.into())
    }

    pub fn secp256k1(msg: &[u8], sk: &libsecp256k1::SecretKey) -> Self {
        sign_with_secp256k1(msg, sk)
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

// Weight for Sr25519 sig verification
pub const SR25519_WEIGHT: Weight = Weight::from_ref_time(140_000_000);
// Weight for Ed25519 sig verification
pub const ED25519_WEIGHT: Weight = Weight::from_ref_time(152_000_000);
// Weight for ecdsa using secp256k1 sig verification
pub const SECP256K1_WEIGHT: Weight = Weight::from_ref_time(456_000_000);

pub fn sign_with_secp256k1(msg: &[u8], sk: &libsecp256k1::SecretKey) -> SigValue {
    let hash = Sha256::digest(msg).try_into().unwrap();
    let m = libsecp256k1::Message::parse(&hash);
    let sig = libsecp256k1::sign(&m, sk);
    let mut sig_bytes: [u8; 65] = [0; 65];
    sig_bytes[0..64].copy_from_slice(&sig.0.serialize()[..]);
    sig_bytes[64] = sig.1.serialize();
    SigValue::Secp256k1(sig_bytes.into())
}

#[cfg(test)]
mod tests {
    use crate::common::get_secp256k1_keypair;

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
                let pk = $pk_type(pk_bytes.into());
                assert!(pk.can_sign());
                let sig_bytes = pair.sign(&msg).0;
                let correct_sig = $correct_sig_type(sig_bytes.into());

                // Valid signature wrapped in a correct type works
                assert!(correct_sig.verify(&msg, &pk).unwrap());

                // Valid signature wrapped in an incorrect type does not work
                let incorrect_sig = $incorrect_sig_type(sig_bytes.into());
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
        let incorrect_sig = SigValue::Ed25519([10; 64].into());
        assert!(correct_sig.verify(&msg, &pk).unwrap());
        assert!(incorrect_sig.verify(&msg, &pk).is_err());
    }
}
