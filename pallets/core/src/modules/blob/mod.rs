//! Generic immutable single-owner storage.

use crate::{
    common::{signatures::ForSigType, AuthorizeTarget, Types},
    did::{self, DidKey, DidMethodKey, DidOrDidMethodKey, DidOrDidMethodKeySignature},
    util::{ActionWithNonce, BoundedBytes, Bytes},
};
use codec::{Decode, Encode, MaxEncodedLen};
use sp_std::fmt::Debug;

use frame_support::{
    dispatch::DispatchResult, ensure, weights::Weight, CloneNoBound, DebugNoBound, EqNoBound,
    PartialEqNoBound,
};
use sp_std::prelude::*;
use weights::*;

pub use pallet::*;

#[cfg(feature = "runtime-benchmarks")]
mod benchmarks;
#[cfg(test)]
mod tests;
mod weights;

/// Owner of a Blob.
#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq, Copy, Ord, PartialOrd, MaxEncodedLen)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[derive(scale_info_derive::TypeInfo)]
#[scale_info(omit_prefix)]
pub struct BlobOwner(pub DidOrDidMethodKey);

impl AuthorizeTarget<(), DidKey> for BlobOwner {}
impl AuthorizeTarget<(), DidMethodKey> for BlobOwner {}

crate::impl_wrapper!(BlobOwner(DidOrDidMethodKey));

/// Size of the blob id in bytes
pub const ID_BYTE_SIZE: usize = 32;

/// The unique name for a blob.
pub type BlobId = [u8; ID_BYTE_SIZE];

/// When a new blob is being registered, the following object is sent.
#[derive(Encode, Decode, CloneNoBound, PartialEqNoBound, DebugNoBound, EqNoBound)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[derive(scale_info_derive::TypeInfo)]
#[scale_info(omit_prefix)]
pub struct Blob {
    pub id: BlobId,
    pub blob: Bytes,
}

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
pub struct AddBlob<T: Types> {
    pub blob: Blob,
    pub nonce: T::BlockNumber,
}

crate::impl_action_with_nonce! {
    AddBlob for (): with 1 as len, () as target
}

#[frame_support::pallet]
pub mod pallet {
    use super::*;
    use frame_support::pallet_prelude::*;
    use frame_system::pallet_prelude::*;

    #[pallet::config]
    pub trait Config: frame_system::Config + did::Config {}

    /// Error for the blob module.
    #[pallet::error]
    pub enum Error<T> {
        /// There is already a blob with same id
        BlobAlreadyExists,
        /// There is no such DID registered
        DidDoesNotExist,
        TooBig,
    }

    #[pallet::pallet]
    #[pallet::generate_store(pub(super) trait Store)]
    pub struct Pallet<T>(_);

    #[pallet::storage]
    #[pallet::getter(fn blob)]
    pub type Blobs<T: Config> =
        StorageMap<_, Blake2_128Concat, BlobId, (BlobOwner, BoundedBytes<T::MaxBlobSize>)>;

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// Create a new immutable blob.
        #[pallet::weight(SubstrateWeight::<T>::new(add_blob, signature))]
        pub fn new(
            origin: OriginFor<T>,
            add_blob: AddBlob<T>,
            signature: DidOrDidMethodKeySignature<BlobOwner>,
        ) -> DispatchResult {
            ensure_signed(origin)?;

            add_blob.signed(signature).execute(Self::new_)
        }
    }

    #[pallet::hooks]
    impl<T: Config> Hooks<T::BlockNumber> for Pallet<T> {
        fn on_runtime_upgrade() -> Weight {
            macro_rules! blob {
                (owner $owner: literal, id $blob_id: literal, blob $blob: expr) => {
                    (
                        BlobOwner(crate::did::Did(hex_literal::hex!($owner)).into()),
                        hex_literal::hex!($blob_id),
                        BoundedBytes::<T::MaxBlobSize>::try_from(Bytes::from_iter($blob)).unwrap(),
                    )
                };
            }

            let blobs = vec![
                // https://dock.subscan.io/extrinsic/16343839-1
                // https://fe.dock.io/#/explorer/query/16343839
                blob! {
                  owner "60cba0b4b01894f8892fc7e039c680529f3d5a06a808a7de19da8ff08a0feb6c",
                  id "4b93545c49a2926da675b8ec161619b21c3c749d5129d1feb5a6bfbd72206adb",
                  blob r#"{"$schema":"http://json-schema.org/draft-07/schema#","additionalProperties":false,"description":"A representation of a Patient Identity credential","name":"Patient Identity","properties":{"email":{"description":"The email of the credential holder.","title":"Subject Email","type":"string"},"hospital":{"description":"The name of the hospital.","title":"Hospital","type":"string"},"name":{"description":"The name of the credential holder.","title":"Subject Name","type":"string"},"patientNo":{"description":"The patient number of the credential holder.","title":"Patient Number","type":"string"}},"required":["name","hospital"],"type":"object"}"#.bytes()
                },
                // https://dock.subscan.io/extrinsic/9225187-1
                // https://fe.dock.io/#/explorer/query/9225187
                blob! {
                  owner "51c4085357eb32355611bca7febca2118b5844c111b53460c60bb969b502bbfc",
                  id "fd0f46b4864b5df40aeb77166b948cf6818a4a044391a74b42ec3db9bab8da2c",
                  blob r#"{"$schema":"http://json-schema.org/draft-07/schema#","additionalProperties":false,"description":"A custom schema for dock","name":"Dock Certificate","properties":{"id":{"description":"A unique identifier of the credential holder, could also be their DID.","title":"Subject ID","type":"string"},"name":{"description":"The name of the subject","title":"Subject Name","type":"string"},"title":{"description":"The title of this credential","title":"Credential Title","type":"string"}},"required":["name","title"],"type":"object"}"#.bytes()
                },
                // https://dock.subscan.io/extrinsic/9428039-1
                // https://fe.dock.io/#/explorer/query/9428039
                blob! {
                  owner "8f470ec1064283b096979773dd93bb9cb8f76db706a7e9540b236a68d47765ed",
                  id "05870f01f77046bb617ee44fe1bbcb4759b9cf8212423ed8a6514c0f63f65f02",
                  blob r#"{"$schema":"http://json-schema.org/draft-07/schema#","additionalProperties":false,"description":"A custom schema for sevenmile certificate of completion","name":"Sevenmile Certificate Of Completion","properties":{"campus":{"default":"NSC Balgowlah Boys Campus","description":"The campus to be printed on the credential","title":"Subject Campus","type":"string"},"credentialName":{"default":"Enterprise in the Community","description":"The name or title of the credential","title":"Credential Name","type":"string"},"id":{"description":"A unique identifier of the credential holder, could also be their DID.","title":"Subject ID","type":"string"},"name":{"description":"The name of the person who this credential is issued to","title":"Subject Name","type":"string"}},"required":["name","campus"],"type":"object"}"#.bytes()
                },
                // https://dock.subscan.io/extrinsic/16343793-1
                // https://fe.dock.io/#/explorer/query/16343793
                blob! {
                  owner "60cba0b4b01894f8892fc7e039c680529f3d5a06a808a7de19da8ff08a0feb6c",
                  id "1ec853b67fa0e0ac19e0e77bbbdd8d2a185133a27e8a9adffadf234524487e17",
                  blob r#"{"$schema":"http://json-schema.org/draft-07/schema#","additionalProperties":false,"description":"A representation of a KYC credential","name":"KYC","properties":{"email":{"description":"The email of the credential holder.","title":"Subject Email","type":"string"},"exchange":{"description":"The name of the exchange.","title":"Exchange Name","type":"string"},"name":{"description":"The name of the credential holder.","title":"Subject Name","type":"string"}},"required":["name","exchange"],"type":"object"}"#.bytes()
                },
                // https://dock.subscan.io/extrinsic/22400439-1
                // https://fe.dock.io/#/explorer/query/22400439
                blob! {
                  owner "6bc098cf67ad6012385969918fbd3743036b3f0d9e22e6afb41486692fac90b4",
                  id "3440c622f7d0a1f5e6d6cb9af3d785389ec01f3f62d90fa3dc97ff595f192c70",
                  blob r#"{"$schema":"http://json-schema.org/draft-07/schema#","additionalProperties":false,"description":"A random secret to authenticate on pruvo.eu","issuer":"did:dock:5EVzCD4huzMey7V5UZhUoWc2qqddZ4MTtP6QVbgLrVaTv4Gi","name":"pruvo-eu-login","properties":{"domain":{"type":"string"},"secret":{"type":"string"}},"required":["secret","domain"]}"#.bytes()
                },
                // https://dock.subscan.io/extrinsic/7618483-1
                // https://fe.dock.io/#/explorer/query/7618483
                blob! {
                  owner "fdf3907d86b6a3288836b339d417616424c09f19611b59262140f067848452d4",
                  id "ffa9a55d40c0609f1754a96c97620e16073a4f956c8b17be46d8a0e81bb7cff3",
                  blob r#"{"$schema":"http://json-schema.org/draft-07/schema#","additionalProperties":false,"description":"Dock Schema Example","name":"Untitled","properties":{"alumniOf":{"type":"string"},"emailAddress":{"format":"email","type":"string"},"id":{"type":"string"}},"required":["emailAddress","alumniOf"],"type":"object"}"#.bytes()
                },
                // https://dock.subscan.io/extrinsic/9225129-1
                // https://fe.dock.io/#/explorer/query/9225129
                blob! {
                  owner "ab6152e32bfe9b7f0b11c3003fd13ae9e598d986250cf2ea1f64cf07fed8e48c",
                  id "f2ea2c617d7af5cb6f6199754eeac169162e755e0f20285ab9178e42bbf6d95c",
                  blob r#"{"$schema":"http://json-schema.org/draft-07/schema#","additionalProperties":false,"description":"A custom schema for dock","name":"Dock Certificate","properties":{"id":{"description":"A unique identifier of the credential holder, could also be their DID.","title":"Subject ID","type":"string"},"name":{"description":"The name of the subject","title":"Subject Name","type":"string"},"title":{"description":"The title of this credential","title":"Credential Title","type":"string"}},"required":["name","title"],"type":"object"}"#.bytes()
                },
                // https://dock.subscan.io/extrinsic/13764130-1
                // https://fe.dock.io/#/explorer/query/13764130
                blob! {
                  owner "60cba0b4b01894f8892fc7e039c680529f3d5a06a808a7de19da8ff08a0feb6c",
                  id "74d4151819cfd8b3d4b2905c2e6243934f753f79fec4e75e80ff4c718d82caef",
                  blob hex_literal::hex!("7b2224736368656d61223a22687474703a2f2f6a736f6e2d736368656d612e6f72672f64726166742d30372f736368656d6123222c226164646974696f6e616c50726f70657274696573223a66616c73652c226465736372697074696f6e223a22556e6e616d656420446f636b20536368656d61222c226e616d65223a2242696c6c204f66204c6164696e67222c2270726f70657274696573223a7b226164646974696f6e616c496e666f726d6174696f6e223a7b227469746c65223a224164646974696f6e616c20496e666f726d6174696f6e222c2274797065223a22737472696e67227d2c226164646974696f6e616c4e6f746966795061727479223a7b227469746c65223a224164646974696f6e616c204e6f74696679205061727479222c2274797065223a22737472696e67227d2c22617574686f72697a65645369676e61746f72794e616d65223a7b227469746c65223a224e616d65206f6620417574686f72697a6564205369676e61746f7279222c2274797065223a22737472696e67227d2c22626f6c4e756d626572223a7b227469746c65223a2242696c6c206f66204c6164696e67204e756d626572222c2274797065223a22737472696e67227d2c2263617272696572223a7b22646570656e64656e63696573223a7b7d2c2270726f70657274696573223a7b2261646472657373223a7b227469746c65223a2243617272696572e28099732041646472657373222c2274797065223a22737472696e67227d2c22636f6d70616e795461784944223a7b227469746c65223a2243617272696572e280997320436f6d70616e7920546178204944222c2274797065223a22737472696e67227d2c22656d61696c223a7b227469746c65223a2243617272696572e280997320456d61696c2041646472657373222c2274797065223a22737472696e67227d2c226e616d65223a7b227469746c65223a2243617272696572e2809973204e616d65222c2274797065223a22737472696e67227d2c22706572736f6e4f66436f6e74616374223a7b227469746c65223a2243617272696572e280997320506572736f6e206f6620436f6e74616374222c2274797065223a22737472696e67227d2c2270686f6e654e756d626572223a7b227469746c65223a2243617272696572e28099732050686f6e65204e756d626572222c2274797065223a22737472696e67227d7d2c227265717569726564223a5b5d2c227469746c65223a2243617272696572222c2274797065223a226f626a656374227d2c22636172726965725265666572656e6365223a7b227469746c65223a2243617272696572e2809973205265666572656e6365222c2274797065223a22737472696e67227d2c22636f6e7369676d656e74546f74616c4d6561737572656d656e74734d32223a7b227469746c65223a22436f6e7369676e6d656e7420546f74616c204d6561737572656d656e747320286d3229222c2274797065223a226e756d626572227d2c22636f6e7369676e6565223a7b22646570656e64656e63696573223a7b7d2c2270726f70657274696573223a7b2261646472657373223a7b227469746c65223a22436f6e7369676e6565e28099732041646472657373222c2274797065223a22737472696e67227d2c22636f6d70616e795461784944223a7b227469746c65223a22436f6e7369676e6565e280997320436f6d70616e7920546178204944222c2274797065223a22737472696e67227d2c22656d61696c223a7b227469746c65223a22436f6e7369676e6565e280997320456d61696c2041646472657373222c2274797065223a22737472696e67227d2c226e616d65223a7b227469746c65223a22436f6e7369676e6565e2809973204e616d65222c2274797065223a22737472696e67227d2c22706572736f6e4f66436f6e74616374223a7b227469746c65223a22436f6e7369676e6565e280997320506572736f6e206f6620436f6e74616374222c2274797065223a22737472696e67227d2c2270686f6e654e756d626572223a7b227469746c65223a22436f6e7369676e6565e28099732050686f6e65204e756d626572222c2274797065223a22737472696e67227d7d2c227265717569726564223a5b5d2c227469746c65223a22436f6e7369676e6565222c2274797065223a226f626a656374227d2c22636f6e7369676e6d656e745265666572656e6365223a7b227469746c65223a22556e6971756520436f6e7369676e6d656e74205265666572656e6365222c2274797065223a22737472696e67227d2c22636f6e7369676e6d656e74546f74616c47726f7373576569676874223a7b227469746c65223a22436f6e7369676e6d656e7420546f74616c2047726f737320576569676874222c2274797065223a226e756d626572227d2c22636f6e7369676e6d656e74546f74616c4e6574576569676874223a7b227469746c65223a22436f6e7369676e6d656e7420546f74616c204e657420576569676874222c2274797065223a226e756d626572227d2c22636f6e7461696e65724e756d62657273223a7b227469746c65223a22436f6e7461696e6572204e756d62657273222c2274797065223a22737472696e67227d2c226465736372697074696f6e4f66476f6f6473223a7b227469746c65223a224465736372697074696f6e206f6620476f6f6473222c2274797065223a22737472696e67227d2c2266696e616c44657374696e6174696f6e223a7b227469746c65223a2246696e616c2044657374696e6174696f6e222c2274797065223a22737472696e67227d2c226672656967687443686172676573223a7b227469746c65223a22467265696768742043686172676573222c2274797065223a22737472696e67227d2c2267726f73735765696768744b47223a7b227469746c65223a2247726f73732057656967687420284b6729222c2274797065223a226e756d626572227d2c22696e636f7465726d7332303230223a7b227469746c65223a22496e636f7465726d732032303230222c2274797065223a22737472696e67227d2c226b696e644e756d6265724f665061636b61676573223a7b227469746c65223a224b696e642026204e756d626572206f66205061636b61676573222c2274797065223a22737472696e67227d2c226d61726b73416e644e756d62657273223a7b227469746c65223a224d61726b732026204e756d62657273222c2274797065223a22737472696e67227d2c226d6561737572656d656e74734d32223a7b227469746c65223a224d6561737572656d656e747320286d3229222c2274797065223a226e756d626572227d2c226e65745765696768744b47223a7b227469746c65223a224e65742057656967687420284b6729222c2274797065223a226e756d626572227d2c226e6f746966795061727479223a7b227469746c65223a224e6f7469667920506172747920286966206e6f7420636f6e7369676e656529222c2274797065223a22737472696e67227d2c226e756d6265724f664f726967696e616c424f4c223a7b227469746c65223a224e756d626572206f66206f726967696e616c2042696c6c73206f66204c6164696e67222c2274797065223a226e756d626572227d2c2270617961626c654174223a7b227469746c65223a2250617961626c65206174222c2274797065223a22737472696e67227d2c22706c6163654f6644656c6976657279223a7b227469746c65223a22506c616365206f662044656c6976657279222c2274797065223a22737472696e67227d2c22706c6163654f664973737565223a7b227469746c65223a22506c616365206f66204973737565222c2274797065223a22737472696e67227d2c22706c6163654f6652656365697074223a7b227469746c65223a22506c616365206f662052656365697074222c2274797065223a22737472696e67227d2c22706f72744f66446973636861726765223a7b227469746c65223a22506f7274206f6620446973636861726765222c2274797065223a22737472696e67227d2c22706f72744f664c6f6164696e67223a7b227469746c65223a22506f7274206f66204c6f6164696e67222c2274797065223a22737472696e67227d2c2270726543617272696167654279223a7b227469746c65223a225072652d4361727269616765204279222c2274797065223a22737472696e67227d2c227365616c4e756d62657273223a7b227469746c65223a225365616c204e756d62657273222c2274797065223a22737472696e67227d2c22736869707065644f6e426f61726444617465223a7b22666f726d6174223a2264617465222c227469746c65223a2253686970706564206f6e20426f6172642044617465222c2274797065223a22737472696e67227d2c2273686970706572223a7b22646570656e64656e63696573223a7b7d2c2270726f70657274696573223a7b2261646472657373223a7b227469746c65223a2253686970706572e28099732041646472657373222c2274797065223a22737472696e67227d2c22636f6d70616e795461784944223a7b227469746c65223a2253686970706572e280997320436f6d70616e7920546178204944222c2274797065223a22737472696e67227d2c22656d61696c41646472657373223a7b227469746c65223a2253686970706572e280997320456d61696c2041646472657373222c2274797065223a22737472696e67227d2c226e616d65223a7b227469746c65223a2253686970706572e2809973204e616d65222c2274797065223a22737472696e67227d2c22706572736f6e4f66436f6e74616374223a7b227469746c65223a2253686970706572e280997320506572736f6e206f6620436f6e74616374222c2274797065223a22737472696e67227d2c2270686f6e654e756d626572223a7b227469746c65223a2253686970706572e28099732050686f6e65204e756d626572222c2274797065223a22737472696e67227d7d2c227265717569726564223a5b5d2c227469746c65223a2253686970706572222c2274797065223a226f626a656374227d2c22736869707065725265666572656e6365223a7b227469746c65223a2253686970706572e2809973205265666572656e6365222c2274797065223a22737472696e67227d2c227369676e61746f7279436f6d70616e79223a7b227469746c65223a225369676e61746f727920436f6d70616e79222c2274797065223a22737472696e67227d2c227369676e6174757265223a7b227469746c65223a225369676e6174757265222c2274797065223a22737472696e67227d2c2273697a65416e6454797065223a7b227469746c65223a2253697a652f54797065222c2274797065223a22737472696e67227d2c22746869735061676547726f7373576569676874223a7b227469746c65223a22546f74616c205468697320506167652047726f737320576569676874222c2274797065223a226e756d626572227d2c2274686973506167654d6561737572656d656e74734d32223a7b227469746c65223a22546f74616c20546869732050616765204d6561737572656d656e747320286d3229222c2274797065223a226e756d626572227d2c22746f6373223a7b227469746c65223a225465726d7320616e6420436f6e646974696f6e73222c2274797065223a22737472696e67227d2c22746f74616c4e6574576569676874223a7b227469746c65223a22546f74616c204e657420576569676874222c2274797065223a226e756d626572227d2c22746f74616c556e697473576f726473223a7b227469746c65223a22546f74616c204e756d626572206f6620436f6e7461696e657273206f72206f74686572207061636b61676573206f7220756e6974732028696e20776f72647329222c2274797065223a22737472696e67227d2c2276657373656c4f724169726372616674223a7b227469746c65223a2256657373656c202f204169726372616674222c2274797065223a22737472696e67227d2c22766f796167654e756d626572223a7b227469746c65223a22566f79616765204e756d626572222c2274797065223a22737472696e67227d7d2c227265717569726564223a5b5d2c2274797065223a226f626a656374227d").to_vec()
                },
                // https://dock.subscan.io/extrinsic/13764161-1
                // https://fe.dock.io/#/explorer/query/13764161
                blob! {
                  owner "60cba0b4b01894f8892fc7e039c680529f3d5a06a808a7de19da8ff08a0feb6c",
                  id "3b7ba810400f6f03fd89437492a7a8b23cde23c0022750d91cf5755634946dac",
                  blob r#"{"$schema":"http://json-schema.org/draft-07/schema#","additionalProperties":false,"description":"Unnamed Dock Schema","name":"Commercial Invoice Schema","properties":{"additionalInfo":{"title":"Additional Info","type":"string"},"bank":{"dependencies":{},"properties":{"accountName":{"title":"Account Name","type":"string"},"accountNumber":{"title":"Account Number","type":"number"},"achRoutingNumber":{"title":"ACH Routing Number","type":"number"},"bankAddress":{"title":"Bank Address","type":"string"},"bankName":{"title":"Bank Name","type":"string"},"fedwireRoutingNumber":{"title":"Fedwire Routing Number","type":"number"},"iban":{"title":"IBAN","type":"string"},"swiftCode":{"title":"SWIFT Code","type":"string"}},"required":[],"title":"Bank","type":"object"},"billOfLadingNumber":{"title":"Bill of Lading Number","type":"string"},"buyer":{"dependencies":{},"properties":{"address":{"title":"Address","type":"string"},"companyTaxId":{"title":"Company Tax ID","type":"number"},"emailAddress":{"title":"Email Address","type":"string"},"name":{"title":"Name","type":"string"},"personOfContact":{"title":"Person of Contact","type":"string"},"phoneNumber":{"title":"Phone Number","type":"number"}},"required":[],"title":"Buyer","type":"object"},"buyerReference":{"title":"Buyer Reference","type":"string"},"consignee":{"dependencies":{},"properties":{"address":{"title":"Address","type":"string"},"companyTaxId":{"title":"Company Tax ID","type":"number"},"emailAddress":{"title":"Email Address","type":"string"},"name":{"title":"Name","type":"string"},"personOfContact":{"title":"Person of Contact","type":"string"},"phoneNumber":{"title":"Phone Number","type":"number"}},"required":[],"title":"Consignee","type":"object"},"consignmentTotalAmount":{"title":"Consignment Total Amount","type":"number"},"consignmentUnitQtTotal":{"title":"Consignment Unit Quantity Total","type":"number"},"countryFinalDestination":{"title":"Country of Final Destination","type":"string"},"countryOriginGoods":{"title":"Country of Origin of Goods","type":"string"},"currency":{"title":"Currency","type":"string"},"dateOfDeparture":{"format":"date","title":"Date of Departure","type":"string"},"finalDestination":{"title":"Final Destination","type":"string"},"incoterms2020":{"title":"Incoterms 2020","type":"string"},"invoiceDate":{"format":"date","title":"Invoice Date","type":"string"},"invoiceNumber":{"title":"Invoice Number","type":"number"},"letterOfCreditNumber":{"title":"Letter of Credit Number","type":"string"},"marineCoverPolicyNumber":{"title":"Marine Cover Policy Number","type":"string"},"methodOfDispatch":{"title":"Method of Dispatch","type":"string"},"nameOfAuthorizedSignatory":{"title":"Name of Authorized Signatory","type":"string"},"portOfDischarge":{"title":"Port of Discharge","type":"string"},"portOfLoading":{"title":"Port of Loading","type":"string"},"product1":{"dependencies":{},"properties":{"amount":{"title":"Amount","type":"number"},"code":{"title":"Code","type":"string"},"descriptionOfGoods":{"title":"Description of Goods","type":"string"},"hsCode":{"title":"HS Code","type":"number"},"priceUnit":{"title":"Price Unit","type":"number"},"unitQuantity":{"title":"Unit Quantity","type":"number"},"unitType":{"title":"Unit Type","type":"string"}},"required":[],"title":"Product 1","type":"object"},"product2":{"dependencies":{},"properties":{"amount":{"title":"Amount","type":"number"},"code":{"title":"Code","type":"string"},"descriptionOfGoods":{"title":"Description of Goods","type":"string"},"hsCode":{"title":"HS Code","type":"number"},"priceUnit":{"title":"Price Unit","type":"number"},"unitQuantity":{"title":"Unit Quantity","type":"number"},"unitType":{"title":"Unit Type","type":"string"}},"required":[],"title":"Product 2","type":"object"},"product3":{"dependencies":{},"properties":{"amount":{"title":"Amount","type":"number"},"code":{"title":"Code","type":"string"},"descriptionOfGoods":{"title":"Description of Goods","type":"string"},"hsCode":{"title":"HS Code","type":"number"},"priceUnit":{"title":"Price Unit","type":"number"},"unitQuantity":{"title":"Unit Quantity","type":"number"},"unitType":{"title":"Unit Type","type":"string"}},"required":[],"title":"Product 3","type":"object"},"reference":{"title":"Reference","type":"string"},"shipper":{"dependencies":{},"properties":{"address":{"title":"Shipper Address","type":"string"},"companyTaxId":{"title":"Company Tax ID","type":"number"},"emailAddress":{"title":"Email Address","type":"string"},"name":{"title":"Shipper Name","type":"string"},"personOfContact":{"title":"Person of Contact","type":"string"},"phoneNumber":{"title":"Phone Number","type":"number"}},"required":[],"title":"Shipper","type":"object"},"signatoryCompany":{"title":"Signatory Company","type":"string"},"signature":{"title":"Signature","type":"string"},"termsMethodOfPayment":{"title":"Terms / Method of Payment","type":"string"},"totalAmount":{"title":"Total Amount","type":"string"},"totalUnitQuantity":{"title":"Total Unit Quantity","type":"number"},"typeOfShipment":{"title":"Type of Shipment","type":"string"},"vesselAircraft":{"title":"Vessel / Aircraft","type":"string"},"voyageNumber":{"title":"Voyage Number","type":"string"}},"required":[],"type":"object"}"#.bytes()
                },
                // https://dock.subscan.io/extrinsic/7158058-1
                // https://fe.dock.io/#/explorer/query/7158058
                blob! {
                  owner "8f470ec1064283b096979773dd93bb9cb8f76db706a7e9540b236a68d47765ed",
                  id "e307aa9cccf0bb1dab5c581771c32efd59651a1096c7b2ce253ef738aad7427e",
                  blob r#"{"$schema":"http://json-schema.org/draft-07/schema#","additionalProperties":false,"description":"A custom schema for sevenmile","name":"Sevenmile Certificate","properties":{"campus":{"default":"NSC Balgowlah Boys Campus","description":"The campus to be printed on the credential","title":"Subject Campus","type":"string"},"credentialName":{"default":"Certificate for Enterprise in the Community Facilitator","description":"The name or title of the credential","title":"Credential Name","type":"string"},"id":{"description":"A unique identifier of the credential holder, could also be their DID.","title":"Subject ID","type":"string"},"name":{"description":"The name of the person who this credential is issued to","title":"Subject Name","type":"string"}},"required":["name","campus"],"type":"object"}"#.bytes()
                },
                blob! {
                  owner "fea9d8300168c371106da6d0cae083c9737fd67f535eb8cb050d8deb74006f74",
                  id "d1a648b8e87dd1d272136b68bd13fb0a7113d1611b2cad4a808f9d959f8728fa",
                  blob r#"{"$schema":"http://json-schema.org/draft-07/schema#","additionalProperties":false,"description":"Dock Schema Example 2","properties":{"alumniOf":{"type":"string"},"emailAddress":{"format":"email","type":"string"},"id":{"type":"string"}},"required":["emailAddress","alumniOf"],"type":"object"}"#.bytes()
                },
                blob! {
                  owner "1e1e89ddaf0040a50c8ba4cd2a075c48404864e6ffbcf099bb410067e0e293c8",
                  id "ffa5f53aaaccd5adbafbaf05efd62fd6d466e14255095100b98abf2a40174a40",
                  blob r#"{"$schema":"http://json-schema.org/draft-07/schema#","additionalProperties":false,"description":"Dock Schema Example","properties":{"alumniOf":{"type":"string"},"emailAddress":{"format":"email","type":"string"},"id":{"type":"string"}},"required":["emailAddress","alumniOf"],"type":"object"}"#.bytes()
                },
                // https://dock.subscan.io/extrinsic/13763147-1
                // https://fe.dock.io/#/explorer/query/13763147
                blob! {
                  owner "60cba0b4b01894f8892fc7e039c680529f3d5a06a808a7de19da8ff08a0feb6c",
                  id "2d69009b80404d4f0332c86a506f2f55af1fceca6d692353ef33d65157feeda6",
                  blob hex_literal::hex!("7b2224736368656d61223a22687474703a2f2f6a736f6e2d736368656d612e6f72672f64726166742d30372f736368656d6123222c226164646974696f6e616c50726f70657274696573223a66616c73652c226465736372697074696f6e223a22556e6e616d656420446f636b20536368656d61222c226e616d65223a2242696c6c204f66204c6164696e67222c2270726f70657274696573223a7b226164646974696f6e616c496e666f726d6174696f6e223a7b227469746c65223a224164646974696f6e616c20496e666f726d6174696f6e222c2274797065223a22737472696e67227d2c226164646974696f6e616c4e6f746966795061727479223a7b227469746c65223a224164646974696f6e616c204e6f74696679205061727479222c2274797065223a22737472696e67227d2c22617574686f72697a65645369676e61746f72794e616d65223a7b227469746c65223a224e616d65206f6620417574686f72697a6564205369676e61746f7279222c2274797065223a22737472696e67227d2c22626f6c4e756d626572223a7b227469746c65223a2242696c6c206f66204c6164696e67204e756d626572222c2274797065223a22737472696e67227d2c2263617272696572223a7b22646570656e64656e63696573223a7b7d2c2270726f70657274696573223a7b2261646472657373223a7b227469746c65223a2243617272696572e28099732041646472657373222c2274797065223a22737472696e67227d2c22636f6d70616e795461784944223a7b227469746c65223a2243617272696572e280997320436f6d70616e7920546178204944222c2274797065223a22737472696e67227d2c22656d61696c223a7b227469746c65223a2243617272696572e280997320456d61696c2041646472657373222c2274797065223a22737472696e67227d2c226e616d65223a7b227469746c65223a2243617272696572e2809973204e616d65222c2274797065223a22737472696e67227d2c22706572736f6e4f66436f6e74616374223a7b227469746c65223a2243617272696572e280997320506572736f6e206f6620436f6e74616374222c2274797065223a22737472696e67227d2c2270686f6e654e756d626572223a7b227469746c65223a2243617272696572e28099732050686f6e65204e756d626572222c2274797065223a22737472696e67227d7d2c227265717569726564223a5b5d2c227469746c65223a2243617272696572222c2274797065223a226f626a656374227d2c22636172726965725265666572656e6365223a7b227469746c65223a2243617272696572e2809973205265666572656e6365222c2274797065223a22737472696e67227d2c22636f6e7369676d656e74546f74616c4d6561737572656d656e74734d32223a7b227469746c65223a22436f6e7369676e6d656e7420546f74616c204d6561737572656d656e747320286d3229222c2274797065223a226e756d626572227d2c22636f6e7369676e6565223a7b22646570656e64656e63696573223a7b7d2c2270726f70657274696573223a7b2261646472657373223a7b227469746c65223a22436f6e7369676e6565e28099732041646472657373222c2274797065223a22737472696e67227d2c22636f6d70616e795461784944223a7b227469746c65223a22436f6e7369676e6565e280997320436f6d70616e7920546178204944222c2274797065223a22737472696e67227d2c22656d61696c223a7b227469746c65223a22436f6e7369676e6565e280997320456d61696c2041646472657373222c2274797065223a22737472696e67227d2c226e616d65223a7b227469746c65223a22436f6e7369676e6565e2809973204e616d65222c2274797065223a22737472696e67227d2c22706572736f6e4f66436f6e74616374223a7b227469746c65223a22436f6e7369676e6565e280997320506572736f6e206f6620436f6e74616374222c2274797065223a22737472696e67227d2c2270686f6e654e756d626572223a7b227469746c65223a22436f6e7369676e6565e28099732050686f6e65204e756d626572222c2274797065223a22737472696e67227d7d2c227265717569726564223a5b5d2c227469746c65223a22436f6e7369676e6565222c2274797065223a226f626a656374227d2c22636f6e7369676e6d656e745265666572656e6365223a7b227469746c65223a22556e6971756520436f6e7369676e6d656e74205265666572656e6365222c2274797065223a22737472696e67227d2c22636f6e7369676e6d656e74546f74616c47726f7373576569676874223a7b227469746c65223a22436f6e7369676e6d656e7420546f74616c2047726f737320576569676874222c2274797065223a226e756d626572227d2c22636f6e7369676e6d656e74546f74616c4e6574576569676874223a7b227469746c65223a22436f6e7369676e6d656e7420546f74616c204e657420576569676874222c2274797065223a226e756d626572227d2c22636f6e7461696e65724e756d62657273223a7b227469746c65223a22436f6e7461696e6572204e756d62657273222c2274797065223a22737472696e67227d2c226465736372697074696f6e4f66476f6f6473223a7b227469746c65223a224465736372697074696f6e206f6620476f6f6473222c2274797065223a22737472696e67227d2c2266696e616c44657374696e6174696f6e223a7b227469746c65223a2246696e616c2044657374696e6174696f6e222c2274797065223a22737472696e67227d2c226672656967687443686172676573223a7b227469746c65223a22467265696768742043686172676573222c2274797065223a22737472696e67227d2c2267726f73735765696768744b47223a7b227469746c65223a2247726f73732057656967687420284b6729222c2274797065223a226e756d626572227d2c22696e636f7465726d7332303230223a7b227469746c65223a22496e636f7465726d732032303230222c2274797065223a22737472696e67227d2c226b696e644e756d6265724f665061636b61676573223a7b227469746c65223a224b696e642026204e756d626572206f66205061636b61676573222c2274797065223a22737472696e67227d2c226d61726b73416e644e756d62657273223a7b227469746c65223a224d61726b732026204e756d62657273222c2274797065223a22737472696e67227d2c226d6561737572656d656e74734d32223a7b227469746c65223a224d6561737572656d656e747320286d3229222c2274797065223a226e756d626572227d2c226e65745765696768744b47223a7b227469746c65223a224e65742057656967687420284b6729222c2274797065223a226e756d626572227d2c226e6f746966795061727479223a7b227469746c65223a224e6f7469667920506172747920286966206e6f7420636f6e7369676e656529222c2274797065223a22737472696e67227d2c226e756d6265724f664f726967696e616c424f4c223a7b227469746c65223a224e756d626572206f66206f726967696e616c2042696c6c73206f66204c6164696e67222c2274797065223a226e756d626572227d2c2270617961626c654174223a7b227469746c65223a2250617961626c65206174222c2274797065223a22737472696e67227d2c22706c6163654f6644656c6976657279223a7b227469746c65223a22506c616365206f662044656c6976657279222c2274797065223a22737472696e67227d2c22706c6163654f664973737565223a7b227469746c65223a22506c616365206f66204973737565222c2274797065223a22737472696e67227d2c22706c6163654f6652656365697074223a7b227469746c65223a22506c616365206f662052656365697074222c2274797065223a22737472696e67227d2c22706f72744f66446973636861726765223a7b227469746c65223a22506f7274206f6620446973636861726765222c2274797065223a22737472696e67227d2c22706f72744f664c6f6164696e67223a7b227469746c65223a22506f7274206f66204c6f6164696e67222c2274797065223a22737472696e67227d2c2270726543617272696167654279223a7b227469746c65223a225072652d4361727269616765204279222c2274797065223a22737472696e67227d2c227365616c4e756d62657273223a7b227469746c65223a225365616c204e756d62657273222c2274797065223a22737472696e67227d2c22736869707065644f6e426f61726444617465223a7b22666f726d6174223a2264617465222c227469746c65223a2253686970706564206f6e20426f6172642044617465222c2274797065223a22737472696e67227d2c2273686970706572223a7b22646570656e64656e63696573223a7b7d2c2270726f70657274696573223a7b2261646472657373223a7b227469746c65223a2253686970706572e28099732041646472657373222c2274797065223a22737472696e67227d2c22636f6d70616e795461784944223a7b227469746c65223a2253686970706572e280997320436f6d70616e7920546178204944222c2274797065223a22737472696e67227d2c22656d61696c41646472657373223a7b227469746c65223a2253686970706572e280997320456d61696c2041646472657373222c2274797065223a22737472696e67227d2c226e616d65223a7b227469746c65223a2253686970706572e2809973204e616d65222c2274797065223a22737472696e67227d2c22706572736f6e4f66436f6e74616374223a7b227469746c65223a2253686970706572e280997320506572736f6e206f6620436f6e74616374222c2274797065223a22737472696e67227d2c2270686f6e654e756d626572223a7b227469746c65223a2253686970706572e28099732050686f6e65204e756d626572222c2274797065223a22737472696e67227d7d2c227265717569726564223a5b5d2c227469746c65223a2253686970706572222c2274797065223a226f626a656374227d2c22736869707065725265666572656e6365223a7b227469746c65223a2253686970706572e2809973205265666572656e6365222c2274797065223a22737472696e67227d2c227369676e61746f7279436f6d70616e79223a7b227469746c65223a225369676e61746f727920436f6d70616e79222c2274797065223a22737472696e67227d2c227369676e6174757265223a7b227469746c65223a225369676e6174757265222c2274797065223a22737472696e67227d2c2273697a65416e6454797065223a7b227469746c65223a2253697a652f54797065222c2274797065223a22737472696e67227d2c22746869735061676547726f7373576569676874223a7b227469746c65223a22546f74616c205468697320506167652047726f737320576569676874222c2274797065223a226e756d626572227d2c2274686973506167654d6561737572656d656e74734d32223a7b227469746c65223a22546f74616c20546869732050616765204d6561737572656d656e747320286d3229222c2274797065223a226e756d626572227d2c22746f6373223a7b227469746c65223a225465726d7320616e6420436f6e646974696f6e73222c2274797065223a22737472696e67227d2c22746f74616c4e6574576569676874223a7b227469746c65223a22546f74616c204e657420576569676874222c2274797065223a226e756d626572227d2c22746f74616c556e697473576f726473223a7b227469746c65223a22546f74616c204e756d626572206f6620436f6e7461696e657273206f72206f74686572207061636b61676573206f7220756e6974732028696e20776f72647329222c2274797065223a22737472696e67227d2c2276657373656c4f724169726372616674223a7b227469746c65223a2256657373656c202f204169726372616674222c2274797065223a22737472696e67227d2c22766f796167654e756d626572223a7b227469746c65223a22566f79616765204e756d626572222c2274797065223a22737472696e67227d7d2c227265717569726564223a5b5d2c2274797065223a226f626a656374227d").to_vec()
                },
                blob! {
                  owner "bd8d454361e520ef54b905f973e892fd919b98f9cae92ed3fbca93e61bf43658",
                  id "ef157b53ff5dbda2ccef4a11e642a69c449aeec68c5d7891102f1fef9091d299",
                  blob r#"{"$schema":"http://json-schema.org/draft-07/schema#","additionalProperties":false,"description":"Dock Schema Example","properties":{"alumniOf":{"type":"string"},"emailAddress":{"format":"email","type":"string"},"id":{"type":"string"}},"required":["emailAddress","alumniOf"],"type":"object"}"#.bytes()
                },
                blob! {
                  owner "412952aae14b0af520e1529c77ab66a05440524372b870a70643860acbcc4306",
                  id "5623e498d93eeaf8feb89be8496730eb79c8f4bccc78b0f309c5dcf4af4caaa4",
                  blob r#"{"$schema":"http://json-schema.org/draft-07/schema#","additionalProperties":false,"description":"Dock Schema Example","properties":{"alumniOf":{"type":"string"},"emailAddress":{"format":"email","type":"string"},"id":{"type":"string"}},"required":["emailAddress","alumniOf"],"type":"object"}"#.bytes()
                },
                // https://dock.subscan.io/extrinsic/9230264-1
                // https://fe.dock.io/#/explorer/query/9230264
                blob! {
                  owner "60cba0b4b01894f8892fc7e039c680529f3d5a06a808a7de19da8ff08a0feb6c",
                  id "4eb4c7229ddf4b76ecef482e701e85485fa0d050c49a9e07227ed6bc4bd20c82",
                  blob r#"{"$schema":"http://json-schema.org/draft-07/schema#","additionalProperties":false,"description":"A custom schema for dock","name":"Dock Certificate","properties":{"id":{"description":"A unique identifier of the credential holder, could also be their DID.","title":"Subject ID","type":"string"},"name":{"description":"The name of the subject","title":"Subject Name","type":"string"},"title":{"description":"The title of this credential","title":"Credential Title","type":"string"}},"required":["name","title"],"type":"object"}"#.bytes()
                },
                // https://dock.subscan.io/extrinsic/16343842-1
                // https://fe.dock.io/#/explorer/query/16343842
                blob! {
                  owner "60cba0b4b01894f8892fc7e039c680529f3d5a06a808a7de19da8ff08a0feb6c",
                  id "49505c5296b13b41897096fd31b4d616cfce5521934612de9c93e1d09bc742f1",
                  blob r#"{"$schema":"http://json-schema.org/draft-07/schema#","additionalProperties":false,"description":"A representation of a Fire Safety Certification credential","name":"Fire Safety Certification","properties":{"email":{"description":"The email of the credential holder.","title":"Subject Email","type":"string"},"facility":{"description":"The name of the training facility.","title":"Training Facility","type":"string"},"name":{"description":"The name of the credential holder.","title":"Subject Name","type":"string"}},"required":["name","facility"],"type":"object"}"#.bytes()
                },
                // https://dock.subscan.io/extrinsic/22785767-1
                // https://fe.dock.io/#/explorer/query/22785767
                blob! {
                  owner "6bc098cf67ad6012385969918fbd3743036b3f0d9e22e6afb41486692fac90b4",
                  id "336c756c36388284b93a9c0fe21cc6a71e30bcb48ddb9db9f2539f1612bd613d",
                  blob r#"{"$schema":"http://json-schema.org/draft-07/schema#","additionalProperties":false,"description":"Login schema for portal.pruvo.eu","issuer":"did:dock:5EVzCD4huzMey7V5UZhUoWc2qqddZ4MTtP6QVbgLrVaTv4Gi","name":"login_portal_provo_eu","properties":{"domain":{"type":"string"},"secret":{"type":"string"}},"required":["secret","domain"]}"#.bytes()
                },
                // https://dock.subscan.io/extrinsic/9178025-2
                // https://fe.dock.io/#/explorer/query/9178025
                blob! {
                  owner "ce155605f6f36d192a1cf6222f974c615e9c8113d5d186c4356380413be8bb32",
                  id "18b1c9f7af931e0e7ded3c6328fef807121285c799d3accfb7bb7871de8135e1",
                  blob r#"{"$schema":"http://json-schema.org/draft-07/schema#","additionalProperties":false,"description":"A custom schema for dock","name":"Dock Certificate","properties":{"id":{"description":"A unique identifier of the credential holder, could also be their DID.","title":"Subject ID","type":"string"},"name":{"description":"The name of the subject","title":"Subject Name","type":"string"},"title":{"description":"The title of this credential","title":"Credential Title","type":"string"}},"required":["name","title"],"type":"object"}"#.bytes()
                },
                // https://dock.subscan.io/extrinsic/7618587-1
                // https://fe.dock.io/#/explorer/query/7618587
                blob! {
                  owner "fdf3907d86b6a3288836b339d417616424c09f19611b59262140f067848452d4",
                  id "af057e155c6e7c0772136e6a9918e2511e42b4847d7913bc5429bfd2d98e643b",
                  blob r#"{"$schema":"http://json-schema.org/draft-07/schema#","additionalProperties":false,"description":"A custom schema for sevenmile","name":"Sevenmile Certificate","properties":{"campus":{"default":"NSC Balgowlah Boys Campus","description":"The campus to be printed on the credential","title":"Subject Campus","type":"string"},"credentialName":{"default":"Certificate for Enterprise in the Community Facilitator","description":"The name or title of the credential","title":"Credential Name","type":"string"},"id":{"description":"A unique identifier of the credential holder, could also be their DID.","title":"Subject ID","type":"string"},"name":{"description":"The name of the person who this credential is issued to","title":"Subject Name","type":"string"}},"required":["name","campus"],"type":"object"}"#.bytes()
                },
                // https://dock.subscan.io/extrinsic/9546264-1
                // https://fe.dock.io/#/explorer/query/9546264
                blob! {
                  owner "3faa027b91c8ed6176db450ffc3308ad91bd6f68b3d9c290657dae20734483e8",
                  id "2bb4d69c2c24f6da2c5b658ef57bc808ab56b65cd2f371cbc16ff1cb15b860a7",
                  blob r#"{"$schema":"http://json-schema.org/draft-07/schema#","additionalProperties":false,"description":"A custom schema for gravity","name":"Gravity Certificate","properties":{"certificateNo":{"description":"The certificate no to be printed on the credential","title":"Certificate Number","type":"string"},"credentialName":{"default":"Gravity Certificate","description":"The name or title of the credential","title":"Credential Name","type":"string"},"fullName":{"description":"The name of the person who this credential is issued to","title":"Subject Full Name","type":"string"},"id":{"description":"A unique identifier of the credential holder, could also be their DID.","title":"Subject ID","type":"string"},"qualification":{"description":"The qualification to be printed on the credential","title":"Qualification","type":"string"}},"required":["id","certificateNo","fullName","qualification"],"type":"object"}"#.bytes()
                },
                blob! {
                  owner "93228cfe0bb8beb69ce81498bc763954002bf019d130297f20c4bda5d6f38f25",
                  id "c4be9940f75d07830750207059184cfeae1a36fc89327376588b0baab0dfad76",
                  blob r#"{"$schema":"http://json-schema.org/draft-07/schema#","additionalProperties":false,"description":"Dock Schema Example","properties":{"alumniOf":{"type":"string"},"emailAddress":{"format":"email","type":"string"},"id":{"type":"string"}},"required":["emailAddress","alumniOf"],"type":"object"}"#.bytes()
                },
                // https://dock.subscan.io/extrinsic/10037416-1
                // https://fe.dock.io/#/explorer/query/10037416
                blob! {
                  owner "2aea84c56f62527b5882531ea8af7ce93dff2daa120cce06c6b5101a217c3e68",
                  id "250c3f374dab10d409b359feb9adfcc4a91fa1fb0f64200c96ee80c10dda35cb",
                  blob r#"{"$schema":"http://json-schema.org/draft-07/schema#","additionalProperties":false,"description":"A custom schema for gravity","name":"Gravity Certificate","properties":{"certificateNo":{"description":"The certificate no to be printed on the credential","title":"Certificate Number","type":"string"},"credentialName":{"default":"Gravity Certificate","description":"The name or title of the credential","title":"Credential Name","type":"string"},"fullName":{"description":"The name of the person who this credential is issued to","title":"Subject Full Name","type":"string"},"id":{"description":"A unique identifier of the credential holder, could also be their DID.","title":"Subject ID","type":"string"},"qualification":{"description":"The qualification to be printed on the credential","title":"Qualification","type":"string"}},"required":["id","certificateNo","fullName","qualification"],"type":"object"}"#.bytes()
                },
                blob! {
                  owner "483fc667eb8a63f8e040bb91cd23f6c650fb668d0152390a026620d05c5168ed",
                  id "e1420661c333988c024f0a4bd3ea4ed0e75773247a369419acdaa67447c22ca4",
                  blob r#"{"$schema":"http://json-schema.org/draft-07/schema#","additionalProperties":false,"description":"Dock Schema Example","properties":{"alumniOf":{"type":"string"},"emailAddress":{"format":"email","type":"string"},"id":{"type":"string"}},"required":["emailAddress","alumniOf"],"type":"object"}"#.bytes()
                },
                // https://dock.subscan.io/extrinsic/13544603-1
                // https://fe.dock.io/#/explorer/query/13544603
                blob! {
                  owner "60cba0b4b01894f8892fc7e039c680529f3d5a06a808a7de19da8ff08a0feb6c",
                  id "00a20ae93cf7878ab79633ca94211dbb9a91b8d489c33b44404891d448010202",
                  blob hex_literal::hex!("7b2224736368656d61223a22687474703a2f2f6a736f6e2d736368656d612e6f72672f64726166742d30372f736368656d6123222c226164646974696f6e616c50726f70657274696573223a66616c73652c226465736372697074696f6e223a22556e6e616d656420446f636b20536368656d61222c226e616d65223a2242696c6c204f66204c6164696e67222c2270726f70657274696573223a7b226164646974696f6e616c496e666f726d6174696f6e223a7b227469746c65223a224164646974696f6e616c20496e666f726d6174696f6e222c2274797065223a22737472696e67227d2c226164646974696f6e616c4e6f746966795061727479223a7b227469746c65223a224164646974696f6e616c204e6f74696679205061727479222c2274797065223a22737472696e67227d2c22617574686f72697a65645369676e61746f72794e616d65223a7b227469746c65223a224e616d65206f6620417574686f72697a6564205369676e61746f7279222c2274797065223a22737472696e67227d2c22626f6c4e756d626572223a7b227469746c65223a2242696c6c206f66204c6164696e67204e756d626572222c2274797065223a22737472696e67227d2c2263617272696572223a7b22646570656e64656e63696573223a7b7d2c2270726f70657274696573223a7b2261646472657373223a7b227469746c65223a2243617272696572e28099732041646472657373222c2274797065223a22737472696e67227d2c22636f6d70616e795461784944223a7b227469746c65223a2243617272696572e280997320436f6d70616e7920546178204944222c2274797065223a22737472696e67227d2c22656d61696c223a7b227469746c65223a2243617272696572e280997320456d61696c2041646472657373222c2274797065223a22737472696e67227d2c226e616d65223a7b227469746c65223a2243617272696572e2809973204e616d65222c2274797065223a22737472696e67227d2c22706572736f6e4f66436f6e74616374223a7b227469746c65223a2243617272696572e280997320506572736f6e206f6620436f6e74616374222c2274797065223a22737472696e67227d2c2270686f6e654e756d626572223a7b227469746c65223a2243617272696572e28099732050686f6e65204e756d626572222c2274797065223a22737472696e67227d7d2c227265717569726564223a5b5d2c227469746c65223a2243617272696572222c2274797065223a226f626a656374227d2c22636172726965725265666572656e6365223a7b227469746c65223a2243617272696572e2809973205265666572656e6365222c2274797065223a22737472696e67227d2c22636f6e7369676d656e74546f74616c4d6561737572656d656e74734d32223a7b227469746c65223a22436f6e7369676e6d656e7420546f74616c204d6561737572656d656e747320286d3229222c2274797065223a226e756d626572227d2c22636f6e7369676e6565223a7b22646570656e64656e63696573223a7b7d2c2270726f70657274696573223a7b2261646472657373223a7b227469746c65223a22436f6e7369676e6565e28099732041646472657373222c2274797065223a22737472696e67227d2c22636f6d70616e795461784944223a7b227469746c65223a22436f6e7369676e6565e280997320436f6d70616e7920546178204944222c2274797065223a22737472696e67227d2c22656d61696c223a7b227469746c65223a22436f6e7369676e6565e280997320456d61696c2041646472657373222c2274797065223a22737472696e67227d2c226e616d65223a7b227469746c65223a22436f6e7369676e6565e2809973204e616d65222c2274797065223a22737472696e67227d2c22706572736f6e4f66436f6e74616374223a7b227469746c65223a22436f6e7369676e6565e280997320506572736f6e206f6620436f6e74616374222c2274797065223a22737472696e67227d2c2270686f6e654e756d626572223a7b227469746c65223a22436f6e7369676e6565e28099732050686f6e65204e756d626572222c2274797065223a22737472696e67227d7d2c227265717569726564223a5b5d2c227469746c65223a22436f6e7369676e6565222c2274797065223a226f626a656374227d2c22636f6e7369676e6d656e745265666572656e6365223a7b227469746c65223a22556e6971756520436f6e7369676e6d656e74205265666572656e6365222c2274797065223a22737472696e67227d2c22636f6e7369676e6d656e74546f74616c47726f7373576569676874223a7b227469746c65223a22436f6e7369676e6d656e7420546f74616c2047726f737320576569676874222c2274797065223a226e756d626572227d2c22636f6e7461696e65724e756d62657273223a7b227469746c65223a22436f6e7461696e6572204e756d62657273222c2274797065223a22737472696e67227d2c226465736372697074696f6e4f66476f6f6473223a7b227469746c65223a224465736372697074696f6e206f6620476f6f6473222c2274797065223a22737472696e67227d2c2266696e616c44657374696e6174696f6e223a7b227469746c65223a2246696e616c2044657374696e6174696f6e222c2274797065223a22737472696e67227d2c226672656967687443686172676573223a7b227469746c65223a22467265696768742043686172676573222c2274797065223a22737472696e67227d2c2267726f73735765696768744b47223a7b227469746c65223a2247726f73732057656967687420284b6729222c2274797065223a226e756d626572227d2c22696e636f7465726d7332303230223a7b227469746c65223a22496e636f7465726d732032303230222c2274797065223a22737472696e67227d2c226b696e644e756d6265724f665061636b61676573223a7b227469746c65223a224b696e642026204e756d626572206f66205061636b61676573222c2274797065223a22737472696e67227d2c226d61726b73416e644e756d62657273223a7b227469746c65223a224d61726b732026204e756d62657273222c2274797065223a22737472696e67227d2c226d6561737572656d656e74734d32223a7b227469746c65223a224d6561737572656d656e747320286d3229222c2274797065223a226e756d626572227d2c226e65745765696768744b47223a7b227469746c65223a224e65742057656967687420284b6729222c2274797065223a226e756d626572227d2c226e6f746966795061727479223a7b227469746c65223a224e6f7469667920506172747920286966206e6f7420636f6e7369676e656529222c2274797065223a22737472696e67227d2c226e756d6265724f664f726967696e616c424f4c223a7b227469746c65223a224e756d626572206f66206f726967696e616c2042696c6c73206f66204c6164696e67222c2274797065223a226e756d626572227d2c2270617961626c654174223a7b227469746c65223a2250617961626c65206174222c2274797065223a22737472696e67227d2c22706c6163654f6644656c6976657279223a7b227469746c65223a22506c616365206f662044656c6976657279222c2274797065223a22737472696e67227d2c22706c6163654f664973737565223a7b227469746c65223a22506c616365206f66204973737565222c2274797065223a22737472696e67227d2c22706c6163654f6652656365697074223a7b227469746c65223a22506c616365206f662052656365697074222c2274797065223a22737472696e67227d2c22706f72744f66446973636861726765223a7b227469746c65223a22506f7274206f6620446973636861726765222c2274797065223a22737472696e67227d2c22706f72744f664c6f6164696e67223a7b227469746c65223a22506f7274206f66204c6f6164696e67222c2274797065223a22737472696e67227d2c2270726543617272696167654279223a7b227469746c65223a225072652d4361727269616765204279222c2274797065223a22737472696e67227d2c227365616c4e756d62657273223a7b227469746c65223a225365616c204e756d62657273222c2274797065223a22737472696e67227d2c22736869707065644f6e426f61726444617465223a7b22666f726d6174223a2264617465222c227469746c65223a2253686970706564206f6e20426f6172642044617465222c2274797065223a22737472696e67227d2c2273686970706572223a7b22646570656e64656e63696573223a7b7d2c2270726f70657274696573223a7b2261646472657373223a7b227469746c65223a2253686970706572e28099732041646472657373222c2274797065223a22737472696e67227d2c22636f6d70616e795461784944223a7b227469746c65223a2253686970706572e280997320436f6d70616e7920546178204944222c2274797065223a22737472696e67227d2c22656d61696c41646472657373223a7b227469746c65223a2253686970706572e280997320456d61696c2041646472657373222c2274797065223a22737472696e67227d2c226e616d65223a7b227469746c65223a2253686970706572e2809973204e616d65222c2274797065223a22737472696e67227d2c22706572736f6e4f66436f6e74616374223a7b227469746c65223a2253686970706572e280997320506572736f6e206f6620436f6e74616374222c2274797065223a22737472696e67227d2c2270686f6e654e756d626572223a7b227469746c65223a2253686970706572e28099732050686f6e65204e756d626572222c2274797065223a22737472696e67227d7d2c227265717569726564223a5b5d2c227469746c65223a2253686970706572222c2274797065223a226f626a656374227d2c22736869707065725265666572656e6365223a7b227469746c65223a2253686970706572e2809973205265666572656e6365222c2274797065223a22737472696e67227d2c227369676e61746f7279436f6d70616e79223a7b227469746c65223a225369676e61746f727920436f6d70616e79222c2274797065223a22737472696e67227d2c227369676e6174757265223a7b227469746c65223a225369676e6174757265222c2274797065223a22737472696e67227d2c2273697a65416e6454797065223a7b227469746c65223a2253697a652f54797065222c2274797065223a22737472696e67227d2c22746869735061676547726f7373576569676874223a7b227469746c65223a22546f74616c205468697320506167652047726f737320576569676874222c2274797065223a226e756d626572227d2c2274686973506167654d6561737572656d656e74734d32223a7b227469746c65223a22546f74616c20546869732050616765204d6561737572656d656e747320286d3229222c2274797065223a226e756d626572227d2c22746f6373223a7b227469746c65223a225465726d7320616e6420436f6e646974696f6e73222c2274797065223a22737472696e67227d2c22746f74616c556e697473576f726473223a7b227469746c65223a22546f74616c204e756d626572206f6620436f6e7461696e657273206f72206f74686572207061636b61676573206f7220756e6974732028696e20776f72647329222c2274797065223a22737472696e67227d2c2276657373656c4f724169726372616674223a7b227469746c65223a2256657373656c202f204169726372616674222c2274797065223a22737472696e67227d2c22766f796167654e756d626572223a7b227469746c65223a22566f79616765204e756d626572222c2274797065223a22737472696e67227d7d2c227265717569726564223a5b5d2c2274797065223a226f626a656374227d").to_vec()
                },
                blob! {
                  owner "c04b333dcd114b7cca3815a817635690b50285928314b192899767c402d5df14",
                  id "5393f6a54e6c499760d0399bbe46d9a32156ecde789863513e2355503ab268cc",
                  blob r#"{"$schema":"http://json-schema.org/draft-07/schema#","additionalProperties":false,"description":"Dock Schema Example","properties":{"alumniOf":{"type":"string"},"emailAddress":{"format":"email","type":"string"},"id":{"type":"string"}},"required":["emailAddress","alumniOf"],"type":"object"}"#.bytes()
                },
                blob! {
                  owner "a8b5dd57a50abec2783fb7d4d84259a1db5b272fb7f5567977c2f14ca9ef742c",
                  id "c0b1b4c048475bb2be931294a83265160fb00134c63c5efbf797c23c0087abcf",
                  blob r#"{"$schema":"http://json-schema.org/draft-07/schema#","additionalProperties":false,"description":"Dock Schema Example","properties":{"alumniOf":{"type":"string"},"emailAddress":{"format":"email","type":"string"},"id":{"type":"string"}},"required":["emailAddress","alumniOf"],"type":"object"}"#.bytes()
                },
                // https://dock.subscan.io/extrinsic/13536119-1
                // https://fe.dock.io/#/explorer/query/13536119
                blob! {
                  owner "3faa027b91c8ed6176db450ffc3308ad91bd6f68b3d9c290657dae20734483e8",
                  id "337ac11c0aa81888d429f0ae9056a95f64b8408787436d5a2c04448dd7cb2acf",
                  blob r#"{"$schema":"http://json-schema.org/draft-07/schema#","additionalProperties":false,"description":"Dock Schema Example","name":"Untitled","properties":{"alumniOf":{"type":"string"},"emailAddress":{"type":"string"},"id":{"type":"string"}},"required":["emailAddress","alumniOf"],"type":"object"}"#.bytes()
                },
                // https://dock.subscan.io/extrinsic/12071213-1
                // https://fe.dock.io/#/explorer/query/12071213
                blob! {
                  owner "5e6bb13c4d5173ef4fb869b84f15f82543771b378825e7f0692fbdab30cd29d3",
                  id "8ccdc0bfcaa22a35dcf14e30ede9de13de918aa066712e96345a7771d50da5e6",
                  blob r#"{"$schema":"http://json-schema.org/draft-07/schema#","additionalProperties":false,"description":"A custom schema for gravity","name":"Gravity Certificate","properties":{"certificateNo":{"description":"The certificate no to be printed on the credential","title":"Certificate Number","type":"string"},"credentialName":{"default":"Gravity Certificate","description":"The name or title of the credential","title":"Credential Name","type":"string"},"fullName":{"description":"The name of the person who this credential is issued to","title":"Subject Full Name","type":"string"},"id":{"description":"A unique identifier of the credential holder, could also be their DID.","title":"Subject ID","type":"string"},"qualification":{"description":"The qualification to be printed on the credential","title":"Qualification Field","type":"string"},"qualificationThree":{"description":"The qualification (3) to be printed on the credential","title":"Qualification Field 3","type":"string"},"qualificationTwo":{"description":"The qualification (2) to be printed on the credential","title":"Qualification Field 2","type":"string"}},"required":["id","certificateNo","fullName","qualification"],"type":"object"}"#.bytes()
                },
            ];

            let writes = blobs.len() as u64;
            for (blob_owner, id, blob) in blobs {
                Blobs::<T>::insert(id, (blob_owner, blob));
            }

            T::DbWeight::get().writes(writes)
        }
    }

    impl<T: Config> Pallet<T> {
        fn new_(
            AddBlob { blob, .. }: AddBlob<T>,
            (): &mut (),
            signer: BlobOwner,
        ) -> DispatchResult {
            let blob_bytes: BoundedBytes<T::MaxBlobSize> =
                blob.blob.try_into().map_err(|_| Error::<T>::TooBig)?;

            // check
            ensure!(
                !Blobs::<T>::contains_key(blob.id),
                Error::<T>::BlobAlreadyExists
            );

            // execute
            Blobs::<T>::insert(blob.id, (signer, blob_bytes));

            Ok(())
        }
    }
}

impl<T: Config> SubstrateWeight<T> {
    #[allow(clippy::new_ret_no_self)]
    fn new(
        AddBlob { blob, .. }: &AddBlob<T>,
        sig: &DidOrDidMethodKeySignature<BlobOwner>,
    ) -> Weight {
        sig.weight_for_sig_type::<T>(
            || Self::new_sr25519(blob.blob.len() as u32),
            || Self::new_ed25519(blob.blob.len() as u32),
            || Self::new_secp256k1(blob.blob.len() as u32),
        )
    }
}
