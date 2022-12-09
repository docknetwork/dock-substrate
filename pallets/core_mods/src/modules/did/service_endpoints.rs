use super::*;
use crate::{
    deposit_indexed_event, impl_bits_conversion, impl_wrapper_type_info, util::WrappedBytes,
};
use codec::{Decode, Encode};
use core::fmt::Debug;

#[derive(Encode, Decode, Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[derive(scale_info_derive::TypeInfo)]
#[scale_info(omit_prefix)]
pub struct ServiceEndpoint {
    pub types: ServiceEndpointType,
    pub origins: Vec<WrappedBytes>,
}

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

impl ServiceEndpoint {
    pub fn is_valid(&self, max_origins: usize, max_origin_length: usize) -> bool {
        !self.types.is_empty()
            && !self.origins.is_empty()
            && self.origins.len() <= max_origins
            && !self
                .origins
                .iter()
                .any(|o| o.is_empty() || o.len() > max_origin_length)
    }
}

impl<T: Config> Module<T>
where
    T: Debug,
{
    pub(crate) fn add_service_endpoint_(
        AddServiceEndpoint {
            did, id, endpoint, ..
        }: AddServiceEndpoint<T>,
        _: &mut OnChainDidDetails,
    ) -> Result<(), Error<T>> {
        ensure!(!id.is_empty(), Error::<T>::InvalidServiceEndpoint);
        ensure!(
            T::MaxServiceEndpointIdSize::get() as usize >= id.len(),
            Error::<T>::InvalidServiceEndpoint
        );
        ensure!(
            endpoint.is_valid(
                T::MaxServiceEndpointOrigins::get() as usize,
                T::MaxServiceEndpointOriginSize::get() as usize
            ),
            Error::<T>::InvalidServiceEndpoint
        );

        if Self::did_service_endpoints(&did, &id).is_some() {
            fail!(Error::<T>::ServiceEndpointAlreadyExists)
        }
        DidServiceEndpoints::insert(did, id, endpoint);

        deposit_indexed_event!(DidServiceEndpointAdded(did));
        Ok(())
    }

    pub(crate) fn remove_service_endpoint_(
        RemoveServiceEndpoint { did, id, .. }: RemoveServiceEndpoint<T>,
        _: &mut OnChainDidDetails,
    ) -> Result<(), Error<T>> {
        ensure!(!id.is_empty(), Error::<T>::InvalidServiceEndpoint);

        if Self::did_service_endpoints(&did, &id).is_none() {
            fail!(Error::<T>::ServiceEndpointDoesNotExist)
        }
        DidServiceEndpoints::remove(did, id);

        deposit_indexed_event!(DidServiceEndpointRemoved(did));
        Ok(())
    }
}
