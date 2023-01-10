use super::*;
use crate::{deposit_indexed_event, impl_wrapper};

/// DID controller.
#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq, Copy, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[derive(scale_info_derive::TypeInfo)]
#[scale_info(omit_prefix)]
pub struct Controller(pub Did);

impl_wrapper!(Controller(Did), for rand use Did(rand::random()), with tests as controller_tests);

impl<T: Config + Debug> Module<T> {
    pub(crate) fn add_controllers_(
        AddControllers {
            did, controllers, ..
        }: AddControllers<T>,
        OnChainDidDetails {
            active_controllers, ..
        }: &mut OnChainDidDetails,
    ) -> Result<(), Error<T>> {
        for ctrl in &controllers {
            if Self::is_controller(&did, ctrl) {
                fail!(Error::<T>::ControllerIsAlreadyAdded)
            }
        }

        for ctrl in &controllers {
            DidControllers::insert(&did, &ctrl, ());
            *active_controllers += 1;
        }

        deposit_indexed_event!(DidControllersAdded(did));
        Ok(())
    }

    pub(crate) fn remove_controllers_(
        RemoveControllers {
            did, controllers, ..
        }: RemoveControllers<T>,
        OnChainDidDetails {
            active_controllers, ..
        }: &mut OnChainDidDetails,
    ) -> Result<(), Error<T>> {
        for controller_did in &controllers {
            if !Self::is_controller(&did, controller_did) {
                fail!(Error::<T>::NoControllerForDid)
            }
        }

        for controller_did in &controllers {
            DidControllers::remove(&did, controller_did);
            *active_controllers -= 1;
        }

        deposit_indexed_event!(DidControllersRemoved(did));
        Ok(())
    }

    /// Throws an error if `controller` is not the controller of `controlled`
    pub fn ensure_controller(controlled: &Did, controller: &Controller) -> Result<(), Error<T>> {
        if !Self::is_controller(controlled, controller) {
            fail!(Error::<T>::OnlyControllerCanUpdate)
        }
        Ok(())
    }

    /// Returns true if given `controlled` DID is controlled by the `controller` DID.
    pub fn is_controller(controlled: &Did, controller: &Controller) -> bool {
        Self::bound_controller(controlled, controller).is_some()
    }

    /// Returns true if DID controls itself, else false.
    pub fn is_self_controlled(did: &Did) -> bool {
        Self::is_controller(did, &Controller(*did))
    }
}
