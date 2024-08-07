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
    /// Maximum byte size of the `BBDT16` (fixed size) public key. This depends only on the chosen elliptic curve.
    type MaxBBDT16PublicKeySize: Size;
    /// Maximum byte size of the `PS` public key. This depends on the chosen elliptic curve and the number
    /// of messages that can be signed.
    type MaxPSPublicKeySize: Size;

    /// Max amount of master members per a single `Membership`.
    type MaxMasterMembers: Size;
    /// Max amount of the controller `DID`s per a single `Policy`.
    type MaxPolicyControllers: Size;

    type MaxIssuerPriceCurrencySymbolSize: Size;
    /// Max no of issuers that can issue for a particular schema
    type MaxIssuersPerSchema: Size;
    /// Max no of verifiers that can verify (credential) for a particular schema
    type MaxVerifiersPerSchema: Size;
    /// Max no of currencies an issuer can set the price in for a particular schema
    type MaxIssuerPriceCurrencies: Size;
    /// Max size of the trust registry name.
    type MaxTrustRegistryNameSize: Size;
    /// Max no of the trust registries per a single convener.
    type MaxConvenerRegistries: Size;
    /// Max no of delegated issuers a particular issuer can have
    type MaxDelegatedIssuers: Size;
    /// Max no of schemas that a particular issuer can issue for
    type MaxSchemasPerIssuer: Size;
    /// Max no of schemas that a particular verifier can verify (credential) for
    type MaxSchemasPerVerifier: Size;
    /// Max no of registries per a single issuer.
    type MaxRegistriesPerIssuer: Size;
    /// Max no of registries per a single verifier.
    type MaxRegistriesPerVerifier: Size;
    /// Max government framework size for the trust registry.
    type MaxTrustRegistryGovFrameworkSize: Size;
    /// Max no of schemas per registry.
    type MaxSchemasPerRegistry: Size;
    /// Max no of participants per a single registry.
    type MaxParticipantsPerRegistry: Size;
    /// Max size of the `TrustRegistry` participant's org name.
    type MaxRegistryParticipantOrgNameSize: Size;
    /// Max size of the `TrustRegistry` participant's description.
    type MaxRegistryParticipantDescriptionSize: Size;
    /// Max size of the `TrustRegistry` participant's logo.
    type MaxRegistryParticipantLogoSize: Size;
}

type Zero = ConstU32<0>;
type NoLimit = ConstU32<{ u32::MAX }>;

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
    type MaxBBDT16PublicKeySize = NoLimit;
    type MaxPSPublicKeySize = NoLimit;

    type MaxMasterMembers = NoLimit;
    type MaxPolicyControllers = NoLimit;

    type MaxIssuerPriceCurrencySymbolSize = NoLimit;
    type MaxIssuersPerSchema = NoLimit;
    type MaxVerifiersPerSchema = NoLimit;
    type MaxIssuerPriceCurrencies = NoLimit;
    type MaxTrustRegistryNameSize = NoLimit;
    type MaxConvenerRegistries = NoLimit;
    type MaxDelegatedIssuers = NoLimit;
    type MaxSchemasPerIssuer = NoLimit;
    type MaxSchemasPerVerifier = NoLimit;
    type MaxTrustRegistryGovFrameworkSize = NoLimit;
    type MaxRegistriesPerIssuer = NoLimit;
    type MaxRegistriesPerVerifier = NoLimit;
    type MaxSchemasPerRegistry = NoLimit;
    type MaxParticipantsPerRegistry = NoLimit;
    type MaxRegistryParticipantOrgNameSize = NoLimit;
    type MaxRegistryParticipantDescriptionSize = NoLimit;
    type MaxRegistryParticipantLogoSize = NoLimit;
}
