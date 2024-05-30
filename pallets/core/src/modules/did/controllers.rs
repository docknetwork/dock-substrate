use super::*;
use crate::{common::AuthorizeTarget, deposit_indexed_event, impl_wrapper};

/// `DID`'s controller.
#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq, Copy, Ord, PartialOrd, MaxEncodedLen)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[derive(scale_info_derive::TypeInfo)]
#[scale_info(omit_prefix)]
pub struct Controller(pub DidOrDidMethodKey);

impl_wrapper!(Controller(DidOrDidMethodKey));

impl Controller {
    fn ensure_controller_for<T: Config>(&self, controlled: &Did) -> Result<(), Error<T>> {
        ensure!(
            Pallet::<T>::is_controller(controlled, self),
            Error::<T>::OnlyControllerCanUpdate
        );

        Ok(())
    }
}

impl AuthorizeTarget<Did, DidKey> for Controller {
    fn ensure_authorizes_target<T, A>(
        &self,
        key: &DidKey,
        action: &A,
        _: Option<&<Did as Associated<T>>::Value>,
    ) -> DispatchResult
    where
        T: crate::did::Config,
        A: Action<Target = Did>,
    {
        ensure!(
            key.can_control(),
            Error::<T>::InsufficientVerificationRelationship
        );
        self.ensure_controller_for::<T>(&action.target())?;

        Ok(())
    }
}

impl AuthorizeTarget<Did, DidMethodKey> for Controller {
    fn ensure_authorizes_target<T, A>(
        &self,
        _: &DidMethodKey,
        action: &A,
        _: Option<&<Did as Associated<T>>::Value>,
    ) -> DispatchResult
    where
        T: crate::did::Config,
        A: Action<Target = Did>,
    {
        self.ensure_controller_for::<T>(&action.target())?;

        Ok(())
    }
}

impl<T: Config> Pallet<T> {
    pub(crate) fn add_controllers_(
        AddControllers {
            did, controllers, ..
        }: AddControllers<T>,
        OnChainDidDetails {
            active_controllers, ..
        }: &mut OnChainDidDetails,
    ) -> DispatchResult {
        for ctrl in &controllers {
            ensure!(
                !Self::is_controller(&did, ctrl),
                Error::<T>::ControllerIsAlreadyAdded
            )
        }

        for ctrl in &controllers {
            DidControllers::<T>::insert(did, ctrl, ());
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
    ) -> DispatchResult {
        for controller_did in &controllers {
            ensure!(
                Self::is_controller(&did, controller_did),
                Error::<T>::NoControllerForDid
            )
        }

        for controller_did in &controllers {
            DidControllers::<T>::remove(did, controller_did);
            *active_controllers -= 1;
        }

        deposit_indexed_event!(DidControllersRemoved(did));
        Ok(())
    }

    /// Throws an error if `controller` is not the controller of `controlled`
    pub fn ensure_controller(controlled: &Did, controller: &Controller) -> Result<(), Error<T>> {
        ensure!(
            Self::is_controller(controlled, controller),
            Error::<T>::OnlyControllerCanUpdate
        );

        Ok(())
    }

    /// Returns true if given `controlled` DID is controlled by the `controller` DID.
    pub fn is_controller(controlled: &Did, controller: &Controller) -> bool {
        Self::bound_controller(controlled, controller).is_some()
    }

    /// Returns true if DID controls itself, else false.
    pub fn is_self_controlled(did: &Did) -> bool {
        Self::is_controller(did, &Controller((*did).into()))
    }
}
