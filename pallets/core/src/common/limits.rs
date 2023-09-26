use frame_support::traits::{ConstU32, Get};

/// All size limits for the `dock-core` encodable data structures.
pub trait Limits: Clone + Eq {
    /// Maximum size of the label
    type MaxAccumulatorLabelSize: Get<u32> + Send + Sync + 'static;
    /// Maximum byte size of the parameters. This depends only on the chosen elliptic curve.
    type MaxAccumulatorParamsSize: Get<u32> + Send + Sync + 'static;
    /// Maximum byte size of the public key. This depends only on the chosen elliptic curve.
    type MaxAccumulatorPublicKeySize: Get<u32> + Send + Sync + 'static;
    /// Maximum byte size of the accumulated value which is just one group element (not the number of members)
    type MaxAccumulatorAccumulatedSize: Get<u32> + Send + Sync + 'static;

    /// Maximum byte size of reference to off-chain DID Doc.
    type MaxDidDocRefSize: Get<u32> + Send + Sync + 'static;
    /// Maximum byte size of service endpoint's `id` field
    type MaxDidServiceEndpointIdSize: Get<u32> + Send + Sync + 'static;
    /// Maximum number of service endpoint's `origin`
    type MaxDidServiceEndpointOrigins: Get<u32> + Send + Sync + 'static;
    /// Maximum byte size of service endpoint's `origin`
    type MaxDidServiceEndpointOriginSize: Get<u32> + Send + Sync + 'static;

    /// `StatusListCredential`s with size larger than this won't be accepted.
    type MaxStatusListCredentialSize: Get<u32> + Send + Sync + 'static;
    /// `StatusListCredential`s with size less than this won't be accepted.
    type MinStatusListCredentialSize: Get<u32> + Send + Sync + 'static;

    /// Max byte size of the `Iri`.
    type MaxIriSize: Get<u32> + Send + Sync + 'static;

    /// Max byte size of the `Blob`.
    type MaxBlobSize: Get<u32> + Send + Sync + 'static;

    /// Max byte size of the offchain params label.
    type MaxOffchainParamsLabelSize: Get<u32> + Send + Sync + 'static;
    /// Max byte size of the offchain params bytes.
    type MaxOffchainParamsBytesSize: Get<u32> + Send + Sync + 'static;

    /// Maximum byte size of the `BBS` (fixed size) public key. This depends only on the chosen elliptic curve.
    type MaxBBSPublicKeySize: Get<u32> + Send + Sync + 'static;
    /// Maximum byte size of the `BBS+` (fixed size) public key. This depends only on the chosen elliptic curve.
    type MaxBBSPlusPublicKeySize: Get<u32> + Send + Sync + 'static;
    /// Maximum byte size of the `PS` public key. This depends on the chosen elliptic curve and the number
    /// of messages that can be signed.
    type MaxPSPublicKeySize: Get<u32> + Send + Sync + 'static;

    /// Max amount of master members per a single `Membership`.
    type MaxMasterMembers: Get<u32> + Send + Sync + 'static;
    /// Max amount of the controller `DID`s per a single `Policy`.
    type MaxPolicyControllers: Get<u32> + Send + Sync + 'static;
}

type NoLimit = ConstU32<{ u32::MAX }>;
type Zero = ConstU32<0>;

/// `Limits` without any limits.
impl Limits for () {
    type MaxAccumulatorLabelSize = NoLimit;
    type MaxAccumulatorParamsSize = NoLimit;
    type MaxAccumulatorPublicKeySize = NoLimit;
    type MaxAccumulatorAccumulatedSize = NoLimit;

    type MaxDidDocRefSize = NoLimit;
    type MaxDidServiceEndpointIdSize = NoLimit;
    type MaxDidServiceEndpointOrigins = NoLimit;
    type MaxDidServiceEndpointOriginSize = NoLimit;

    type MaxStatusListCredentialSize = NoLimit;
    type MinStatusListCredentialSize = Zero;

    type MaxIriSize = NoLimit;

    type MaxBlobSize = NoLimit;

    type MaxOffchainParamsLabelSize = NoLimit;
    type MaxOffchainParamsBytesSize = NoLimit;

    type MaxBBSPublicKeySize = NoLimit;
    type MaxBBSPlusPublicKeySize = NoLimit;
    type MaxPSPublicKeySize = NoLimit;

    type MaxMasterMembers = NoLimit;
    type MaxPolicyControllers = NoLimit;
}
