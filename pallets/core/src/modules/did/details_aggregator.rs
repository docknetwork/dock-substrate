use super::{service_endpoints::ServiceEndpointId, *};
use crate::{
    attest::{self, Attestation, Attester},
    common::TypesAndLimits,
    impl_bits_conversion, impl_wrapper_type_info,
};

/// Aggregated details for the given DID.
#[derive(Encode, Decode, DebugNoBound, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[cfg_attr(
    feature = "serde",
    serde(bound(serialize = "T: Sized", deserialize = "T: Sized"))
)]
#[derive(scale_info_derive::TypeInfo)]
#[scale_info(skip_type_params(T))]
#[scale_info(omit_prefix)]
pub struct AggregatedDidDetailsResponse<T: TypesAndLimits> {
    did: Did,
    details: StoredDidDetails<T>,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    keys: Option<Vec<DidKeyWithId>>,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    controllers: Option<Vec<Controller>>,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    service_endpoints: Option<Vec<ServiceEndpointWithId<T>>>,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    attestation: Option<Attestation<T>>,
}

/// `DidKey` with its identifier.
#[derive(Encode, Decode, scale_info_derive::TypeInfo, Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[scale_info(omit_prefix)]
pub struct DidKeyWithId {
    id: IncId,
    key: DidKey,
}

/// `ServiceEndpoint` with its identifier.
#[derive(Encode, Decode, scale_info_derive::TypeInfo, DebugNoBound, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[cfg_attr(
    feature = "serde",
    serde(bound(serialize = "T: Sized", deserialize = "T: Sized"))
)]
#[scale_info(skip_type_params(T))]
#[scale_info(omit_prefix)]
pub struct ServiceEndpointWithId<T: Limits> {
    id: ServiceEndpointId<T>,
    endpoint: ServiceEndpoint<T>,
}

impl<T: TypesAndLimits> AggregatedDidDetailsResponse<T> {
    /// Constructs new `DID` response using supplied arguments.
    pub fn new<CI, KI, SI>(
        did: Did,
        details: StoredDidDetails<T>,
        keys: Option<KI>,
        controllers: Option<CI>,
        service_endpoints: Option<SI>,
        attestation: Option<Attestation<T>>,
    ) -> Self
    where
        KI: IntoIterator<Item = (IncId, DidKey)>,
        CI: IntoIterator<Item = Controller>,
        SI: IntoIterator<Item = (ServiceEndpointId<T>, ServiceEndpoint<T>)>,
    {
        Self {
            did,
            details,
            controllers: controllers.map(|controllers| controllers.into_iter().collect()),
            keys: keys.map(|keys| {
                keys.into_iter()
                    .map(|(id, key)| DidKeyWithId { id, key })
                    .collect()
            }),
            service_endpoints: service_endpoints.map(|endpoints| {
                endpoints
                    .into_iter()
                    .map(|(id, endpoint)| ServiceEndpointWithId { id, endpoint })
                    .collect()
            }),
            attestation,
        }
    }
}

bitflags::bitflags! {
    /// Information requested for DID. The default option includes only basic DID details.
    #[derive(Default)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    #[cfg_attr(feature = "serde", serde(try_from = "u8", into = "u8"))]
    pub struct AggregatedDidDetailsRequestParams: u8 {
        /// Just basic DID details.
        const BASIC = 0;
        /// Include keys for the DID.
        const KEYS = 0b0001;
        /// Include controllers for the DID.
        const CONTROLLERS = 0b0010;
        /// Include service endpoints for the DID.
        const SERVICE_ENDPOINTS = 0b0100;
        /// Include attestation for the DID.
        const ATTESTATION = 0b1000;
        /// Include full DID information (keys, controllers, service endpoints and attestation).
        const FULL = 0b1111;
    }
}

impl_bits_conversion! { AggregatedDidDetailsRequestParams from u8 }
impl_wrapper_type_info! { AggregatedDidDetailsRequestParams(u8) }

impl<T: attest::Config> Pallet<T> {
    /// Request aggregated DID details containing specified information.
    pub fn aggregate_did_details(
        did: &Did,
        params: AggregatedDidDetailsRequestParams,
    ) -> Option<AggregatedDidDetailsResponse<T>> {
        let details = Self::did(did)?;
        let keys = params
            .intersects(AggregatedDidDetailsRequestParams::KEYS)
            .then(|| DidKeys::<T>::iter_prefix(did));
        let controllers = params
            .intersects(AggregatedDidDetailsRequestParams::CONTROLLERS)
            .then(|| DidControllers::<T>::iter_prefix(did).map(|(did, ())| did));
        let service_endpoints = params
            .intersects(AggregatedDidDetailsRequestParams::SERVICE_ENDPOINTS)
            .then(|| DidServiceEndpoints::<T>::iter_prefix(did));
        let attestation = params
            .intersects(AggregatedDidDetailsRequestParams::ATTESTATION)
            .then(|| <attest::Pallet<T>>::attestation(Attester(*did)));

        Some(AggregatedDidDetailsResponse::new(
            *did,
            details,
            keys,
            controllers,
            service_endpoints,
            attestation,
        ))
    }
}
