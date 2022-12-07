use super::super::*;
use crate::{keys_and_sigs::SigValue, ToStateChange};

#[derive(Encode, Decode, Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[derive(scale_info_derive::TypeInfo)]
#[scale_info(omit_prefix)]
#[scale_info(skip_type_params(D))]
#[codec(mel_bound())]
pub struct DidSignature<D: Into<Did>> {
    /// The DID that created this signature
    pub did: D,
    /// The key-id of above DID used to verify the signature
    pub key_id: IncId,
    /// The actual signature
    pub sig: SigValue,
}

impl<D: Into<Did>> DidSignature<D> {
    pub fn new(did: impl Into<D>, key_id: impl Into<IncId>, sig: impl Into<SigValue>) -> Self {
        Self {
            did: did.into(),
            key_id: key_id.into(),
            sig: sig.into(),
        }
    }

    pub fn verify<T: Config + Debug>(
        &self,
        message: &[u8],
        public_key: &PublicKey,
    ) -> Result<bool, Error<T>> {
        self.sig
            .verify(message, public_key)
            .map_err(|_| Error::<T>::IncompatSigPubkey)
    }

    /// This is just the weight to verify the signature. It does not include weight to read the DID or the key.
    pub fn weight(&self) -> Weight {
        self.sig.weight()
    }
}

impl<T: Config + Debug> Module<T> {
    /// Verifies a `DidSignature` created by `signer` only if `signer` is a controller of `did` and has an
    /// appropriate key. To update a DID (add/remove keys, add/remove controllers), the updater must be a
    /// controller of the DID and must have a key with `CAPABILITY_INVOCATION` verification relationship
    pub fn verify_sig_from_controller<A>(
        action: &A,
        sig: &DidSignature<Controller>,
    ) -> Result<bool, Error<T>>
    where
        A: Action<T> + ToStateChange<T>,
        A::Target: Into<Did>,
    {
        Self::ensure_controller(&action.target().into(), &sig.did)?;
        let signer_pubkey = Self::control_key(&sig.did, sig.key_id)?;
        let encoded_state_change = action.to_state_change().encode();

        sig.verify::<T>(&encoded_state_change, &signer_pubkey)
    }

    /// Verifies that `did`'s key with id `key_id` can either authenticate or control otherwise returns an error.
    /// Then provided signature will be verified against the supplied public key and `true` returned for a valid signature.
    pub fn verify_sig_from_auth_or_control_key<Sc, D>(
        state_change: &Sc,
        sig: &DidSignature<D>,
    ) -> Result<bool, Error<T>>
    where
        D: Into<Did> + Copy,
        Sc: ToStateChange<T>,
    {
        let signer_pubkey = Self::auth_or_control_key(&sig.did.into(), sig.key_id)?;
        let encoded_state_change = state_change.to_state_change().encode();

        sig.verify::<T>(&encoded_state_change, &signer_pubkey)
    }
}
