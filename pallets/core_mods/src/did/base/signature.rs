use super::super::*;
use crate::keys_and_sigs::SigValue;

#[derive(Encode, Decode, Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct DidSignature {
    /// The DID that created this signature
    pub did: Controller,
    /// The key-id of above DID used to verify the signature
    pub key_id: IncId,
    /// The actual signature
    pub sig: SigValue,
}

impl DidSignature {
    pub fn verify<T: Trait + Debug>(
        &self,
        message: &[u8],
        public_key: &PublicKey,
    ) -> Result<bool, Error<T>> {
        self.sig
            .verify(message, public_key)
            .map_err(|_| Error::<T>::IncompatSigPubkey)
    }
}

impl<T: Trait + Debug> Module<T> {
    /// Verify a `DidSignature` created by `signer` only if `signer` is a controller of `did` and has an
    /// appropriate key. To update a DID (add/remove keys, add/remove controllers), the updater must be a
    /// controller of the DID and must have a key with `CAPABILITY_INVOCATION` verification relationship
    pub fn verify_sig_from_controller<A>(action: &A, sig: &DidSignature) -> Result<bool, Error<T>>
    where
        A: Action<T, Target = Did>,
    {
        Self::ensure_controller(&action.target(), &sig.did)?;
        let signer_pubkey = Self::control_key(&sig.did, sig.key_id)?;

        sig.verify::<T>(&action.to_state_change().encode(), &signer_pubkey)
    }
}
