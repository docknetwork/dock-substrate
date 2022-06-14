use super::*;

/// Aggregated details for the given DID.
#[derive(Encode, Decode, Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[cfg_attr(
    feature = "serde",
    serde(bound(serialize = "T: Sized", deserialize = "T: Sized"))
)]
pub struct AggregatedDidDetailsResponse<T: Trait> {
    did: Did,
    #[cfg_attr(feature = "serde", serde(flatten))]
    details: DidDetailStorage<T>,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    keys: Option<Vec<DidKeyWithId>>,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    controllers: Option<Vec<Controller>>,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    service_endpoints: Option<Vec<ServiceEndpointWithId>>,
}

/// `DidKey` with its unique identifier.
#[derive(Encode, Decode, Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct DidKeyWithId {
    id: IncId,
    key: DidKey,
}

/// `ServiceEndpoint` with its unique identifier.
#[derive(Encode, Decode, Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct ServiceEndpointWithId {
    id: WrappedBytes,
    endpoint: ServiceEndpoint,
}

impl<T: Trait> AggregatedDidDetailsResponse<T> {
    /// Constructs new `DID` response using supplied arguments.
    pub fn new<CI, KI, SI>(
        did: Did,
        details: DidDetailStorage<T>,
        keys: Option<KI>,
        controllers: Option<CI>,
        service_endpoints: Option<SI>,
    ) -> Self
    where
        KI: IntoIterator<Item = (IncId, DidKey)>,
        CI: IntoIterator<Item = Controller>,
        SI: IntoIterator<Item = (WrappedBytes, ServiceEndpoint)>,
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
        }
    }
}

bitflags::bitflags! {
    #[derive(Encode, Decode)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    #[cfg_attr(feature = "serde", serde(try_from = "u8", into = "u8"))]
    /// Information requested for DID. The default option includes full DID information (keys, controllers and service endpoints).
    pub struct AggregatedDidDetailsRequestParams: u8 {
        /// Just basic DID details.
        const BASIC = 0;
        /// Include keys for the DID.
        const KEYS = 0b001;
        /// Include controllers for the DID.
        const CONTROLLERS = 0b010;
        /// Include service endpoints for the DID.
        const SERVICE_ENDPOINTS = 0b100;
        /// Include full DID information (keys, controllers and service endpoints).
        const FULL = 0b111;
    }
}

impl_bits_conversion! { AggregatedDidDetailsRequestParams, u8 }

impl Default for AggregatedDidDetailsRequestParams {
    fn default() -> Self {
        Self::FULL
    }
}

impl<T: Trait + Debug> Module<T> {
    /// Request aggregated DID details containing specified information.
    pub fn aggregate_did_details(
        did: &Did,
        params: AggregatedDidDetailsRequestParams,
    ) -> Option<AggregatedDidDetailsResponse<T>> {
        let details = Self::did(did)?;
        let keys = params
            .intersects(AggregatedDidDetailsRequestParams::KEYS)
            .then(|| DidKeys::iter_prefix(did));
        let controllers = params
            .intersects(AggregatedDidDetailsRequestParams::CONTROLLERS)
            .then(|| DidControllers::iter_prefix(did).map(|(did, ())| did));
        let service_endpoints = params
            .intersects(AggregatedDidDetailsRequestParams::SERVICE_ENDPOINTS)
            .then(|| DidServiceEndpoints::iter_prefix(did));

        Some(AggregatedDidDetailsResponse::new(
            *did,
            details,
            keys,
            controllers,
            service_endpoints,
        ))
    }
}
