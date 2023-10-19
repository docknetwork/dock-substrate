use frame_support::traits::{ConstU32, Get};

pub trait Size: Get<u32> + Send + Sync + 'static {}
impl<T: Get<u32> + Send + Sync + 'static> Size for T {}

/// All size limits for the `dock-core` encodable data structures.
pub trait Limits: Clone + Eq {
    /// Maximum size of the label
    type MaxAccumulatorLabelSize: Size;
    /// Maximum byte size of the parameters. This depends only on the chosen elliptic curve.
    type MaxAccumulatorParamsSize: Size;
    /// Maximum byte size of the public key. This depends only on the chosen elliptic curve.
    type MaxAccumulatorPublicKeySize: Size;
    /// Maximum byte size of the accumulated value which is just one group element (not the number of members)
    type MaxAccumulatorAccumulatedSize: Size;

    /// Maximum byte size of reference to off-chain DID Doc.
    type MaxDidDocRefSize: Size;
    /// Maximum byte size of service endpoint's `id` field
    type MaxDidServiceEndpointIdSize: Size;
    /// Maximum number of service endpoint's `origin`
    type MaxDidServiceEndpointOrigins: Size;
    /// Maximum byte size of service endpoint's `origin`
    type MaxDidServiceEndpointOriginSize: Size;

    /// `StatusListCredential`s with size larger than this won't be accepted.
    type MaxStatusListCredentialSize: Size;
    /// `StatusListCredential`s with size less than this won't be accepted.
    type MinStatusListCredentialSize: Size;

    /// Max byte size of the `Iri`.
    type MaxIriSize: Size;

    /// Max byte size of the `Blob`.
    type MaxBlobSize: Size;

    /// Max byte size of the offchain params label.
    type MaxOffchainParamsLabelSize: Size;
    /// Max byte size of the offchain params bytes.
    type MaxOffchainParamsBytesSize: Size;

    /// Maximum byte size of the `BBS` (fixed size) public key. This depends only on the chosen elliptic curve.
    type MaxBBSPublicKeySize: Size;
    /// Maximum byte size of the `BBS+` (fixed size) public key. This depends only on the chosen elliptic curve.
    type MaxBBSPlusPublicKeySize: Size;
    /// Maximum byte size of the `PS` public key. This depends on the chosen elliptic curve and the number
    /// of messages that can be signed.
    type MaxPSPublicKeySize: Size;

    /// Max amount of master members per a single `Membership`.
    type MaxMasterMembers: Size;
    /// Max amount of the controller `DID`s per a single `Policy`.
    type MaxPolicyControllers: Size;

    type MaxIssuerPriceCurrencySymbolSize: Size;
    type MaxIssuersPerSchemaSize: Size;
    type MaxVerifiersPerSchemaSize: Size;
    type MaxIssuerPricesSize: Size;
    type MaxTrustRegistryNameSize: Size;
    type MaxConvenerRegistries: Size;
    type MaxDelegatedIssuersSize: Size;
    type MaxSchemasPerIssuer: Size;
    type MaxSchemasPerVerifier: Size;
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

    type MaxIssuerPriceCurrencySymbolSize = NoLimit;
    type MaxIssuersPerSchemaSize = NoLimit;
    type MaxVerifiersPerSchemaSize = NoLimit;
    type MaxIssuerPricesSize = NoLimit;
    type MaxTrustRegistryNameSize = NoLimit;
    type MaxConvenerRegistries = NoLimit;
    type MaxDelegatedIssuersSize = NoLimit;
    type MaxSchemasPerIssuer = NoLimit;
    type MaxSchemasPerVerifier = NoLimit;
}
