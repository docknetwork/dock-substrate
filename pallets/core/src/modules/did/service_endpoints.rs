use super::*;
use crate::{
    common::Limits, deposit_indexed_event, impl_bits_conversion, impl_wrapper,
    impl_wrapper_type_info,
};
use codec::{Decode, Encode, MaxEncodedLen};
use sp_runtime::BoundedVec;

/// `DID`'s service endpoint.
#[derive(
    Encode, Decode, CloneNoBound, PartialEqNoBound, EqNoBound, DebugNoBound, MaxEncodedLen,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[cfg_attr(
    feature = "serde",
    serde(bound(serialize = "T: Sized", deserialize = "T: Sized"))
)]
#[derive(scale_info_derive::TypeInfo)]
#[scale_info(skip_type_params(T))]
#[scale_info(omit_prefix)]
pub struct ServiceEndpoint<T: Limits> {
    pub types: ServiceEndpointType,
    pub origins: BoundedVec<ServiceEndpointOrigin<T>, T::MaxDidServiceEndpointOrigins>,
}

/// `DID`'s service endpoint id.
#[derive(
    Encode, Decode, CloneNoBound, PartialEqNoBound, EqNoBound, DebugNoBound, MaxEncodedLen,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[cfg_attr(
    feature = "serde",
    serde(bound(serialize = "T: Sized", deserialize = "T: Sized"))
)]
#[derive(scale_info_derive::TypeInfo)]
#[scale_info(skip_type_params(T))]
#[scale_info(omit_prefix)]
pub struct ServiceEndpointId<T: Limits>(pub BoundedBytes<T::MaxDidServiceEndpointIdSize>);

impl_wrapper!(ServiceEndpointId<T: Limits>(BoundedBytes<T::MaxDidServiceEndpointIdSize>));

/// `DID`'s service endpoint origin.
#[derive(
    Encode, Decode, CloneNoBound, PartialEqNoBound, EqNoBound, DebugNoBound, MaxEncodedLen,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[cfg_attr(
    feature = "serde",
    serde(bound(serialize = "T: Sized", deserialize = "T: Sized"))
)]
#[derive(scale_info_derive::TypeInfo)]
#[scale_info(skip_type_params(T))]
#[scale_info(omit_prefix)]
pub struct ServiceEndpointOrigin<T: Limits>(pub BoundedBytes<T::MaxDidServiceEndpointOriginSize>);

impl_wrapper!(ServiceEndpointOrigin<T: Limits>(BoundedBytes<T::MaxDidServiceEndpointOriginSize>));

bitflags::bitflags! {
    /// Different service endpoint types specified in the DID spec here https://www.w3.org/TR/did-core/#services
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    #[cfg_attr(feature = "serde", serde(try_from = "u16", into = "u16"))]
    pub struct ServiceEndpointType: u16 {
        /// No service endpoint set.
        const NONE = 0;
        const LINKED_DOMAINS = 0b0001;
    }
}

impl_bits_conversion! { ServiceEndpointType from u16 }
impl_wrapper_type_info! { ServiceEndpointType(u16) }

impl<T: Limits> ServiceEndpoint<T> {
    pub fn is_valid(&self) -> bool {
        !self.types.is_empty()
            && !self.origins.is_empty()
            && !self.origins.iter().any(|origin| origin.is_empty())
    }
}

impl<T: Config> Pallet<T> {
    pub(crate) fn add_service_endpoint_(
        AddServiceEndpoint {
            did, id, endpoint, ..
        }: AddServiceEndpoint<T>,
        _: &mut OnChainDidDetails,
    ) -> DispatchResult {
        ensure!(!id.is_empty(), Error::<T>::InvalidServiceEndpoint);
        ensure!(endpoint.is_valid(), Error::<T>::InvalidServiceEndpoint);
        ensure!(
            Self::did_service_endpoints(did, &id).is_none(),
            Error::<T>::ServiceEndpointAlreadyExists
        );

        DidServiceEndpoints::<T>::insert(did, id, endpoint);

        deposit_indexed_event!(DidServiceEndpointAdded(did));
        Ok(())
    }

    pub(crate) fn remove_service_endpoint_(
        RemoveServiceEndpoint { did, id, .. }: RemoveServiceEndpoint<T>,
        _: &mut OnChainDidDetails,
    ) -> DispatchResult {
        ensure!(!id.is_empty(), Error::<T>::InvalidServiceEndpoint);
        ensure!(
            Self::did_service_endpoints(did, &id).is_some(),
            Error::<T>::ServiceEndpointDoesNotExist
        );

        DidServiceEndpoints::<T>::remove(did, id);

        deposit_indexed_event!(DidServiceEndpointRemoved(did));
        Ok(())
    }
}
