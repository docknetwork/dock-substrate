use core::marker::PhantomData;

pub mod authorization;
pub mod keys;
pub mod limits;
pub mod policy;
pub mod signatures;
pub mod signed_action;
pub mod state_change;
pub mod storage_version;
pub mod types;

pub use authorization::*;
pub use keys::*;
pub use limits::*;
pub use policy::*;
pub use signatures::*;
pub use signed_action::*;
pub use state_change::*;
pub use storage_version::*;
pub use types::*;

/// All associated types and size limits for the encodable data structures used by the `dock-core`.
pub trait TypesAndLimits: Types + Limits {}
impl<T: Types + Limits> TypesAndLimits for T {}

/// Combines two different types - first implementing `Types` and second implementing `Limits`
/// to form a single type implementing both.
#[derive(Clone, Eq, PartialEq, Default)]
pub struct CombineTypesAndLimits<T: Types, L: Limits = ()>(PhantomData<(T, L)>);

impl<T: Types, L: Limits> Types for CombineTypesAndLimits<T, L> {
    type BlockNumber = T::BlockNumber;
    type AccountId = T::AccountId;
}

impl<T: Types, L: Limits> Limits for CombineTypesAndLimits<T, L> {
    type MaxAccumulatorLabelSize = L::MaxAccumulatorLabelSize;
    type MaxAccumulatorParamsSize = L::MaxAccumulatorParamsSize;
    type MaxAccumulatorPublicKeySize = L::MaxAccumulatorPublicKeySize;
    type MaxAccumulatorAccumulatedSize = L::MaxAccumulatorAccumulatedSize;

    type MaxDidDocRefSize = L::MaxDidDocRefSize;
    type MaxDidServiceEndpointIdSize = L::MaxDidServiceEndpointIdSize;
    type MaxDidServiceEndpointOrigins = L::MaxDidServiceEndpointOrigins;
    type MaxDidServiceEndpointOriginSize = L::MaxDidServiceEndpointOriginSize;

    type MaxStatusListCredentialSize = L::MaxStatusListCredentialSize;
    type MinStatusListCredentialSize = L::MinStatusListCredentialSize;

    type MaxIriSize = L::MaxIriSize;

    type MaxBlobSize = L::MaxBlobSize;

    type MaxOffchainParamsLabelSize = L::MaxOffchainParamsLabelSize;
    type MaxOffchainParamsBytesSize = L::MaxOffchainParamsBytesSize;

    type MaxBBSPublicKeySize = L::MaxBBSPublicKeySize;
    type MaxBBSPlusPublicKeySize = L::MaxBBSPlusPublicKeySize;
    type MaxPSPublicKeySize = L::MaxPSPublicKeySize;
    type MaxBBDT16PublicKeySize = L::MaxBBDT16PublicKeySize;

    type MaxMasterMembers = L::MaxMasterMembers;
    type MaxPolicyControllers = L::MaxPolicyControllers;

    type MaxIssuerPriceCurrencySymbolSize = L::MaxMasterMembers;
    type MaxIssuersPerSchema = L::MaxIssuersPerSchema;
    type MaxVerifiersPerSchema = L::MaxVerifiersPerSchema;
    type MaxIssuerPriceCurrencies = L::MaxIssuerPriceCurrencies;
    type MaxTrustRegistryNameSize = L::MaxTrustRegistryNameSize;
    type MaxConvenerRegistries = L::MaxConvenerRegistries;
    type MaxDelegatedIssuers = L::MaxDelegatedIssuers;
    type MaxSchemasPerIssuer = L::MaxSchemasPerIssuer;
    type MaxSchemasPerVerifier = L::MaxSchemasPerVerifier;
    type MaxSchemasPerRegistry = L::MaxSchemasPerRegistry;
    type MaxRegistriesPerIssuer = L::MaxRegistriesPerIssuer;
    type MaxRegistriesPerVerifier = L::MaxRegistriesPerVerifier;
    type MaxTrustRegistryGovFrameworkSize = L::MaxTrustRegistryGovFrameworkSize;
    type MaxParticipantsPerRegistry = L::MaxParticipantsPerRegistry;
    type MaxRegistryParticipantOrgNameSize = L::MaxRegistryParticipantOrgNameSize;
    type MaxRegistryParticipantLogoSize = L::MaxRegistryParticipantLogoSize;
    type MaxRegistryParticipantDescriptionSize = L::MaxRegistryParticipantDescriptionSize;
}
