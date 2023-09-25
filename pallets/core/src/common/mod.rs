use core::marker::PhantomData;

pub mod keys;
pub mod limits;
pub mod policy;
pub mod signatures;
pub mod state_change;
pub mod storage_version;
pub mod types;

pub use keys::*;
pub use limits::*;
pub use policy::*;
pub use signatures::*;
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

    type MaxMasterMembers = L::MaxMasterMembers;
    type MaxPolicyControllers = L::MaxPolicyControllers;
}
