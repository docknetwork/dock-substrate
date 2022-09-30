use crate::{
    did::*,
    test_common::*,
    util::{IncId, WithNonce},
    StorageVersion,
};
use codec::{Decode, Encode};
use evm::executor::PrecompileOutput;
use frame_support::{StorageDoubleMap, StorageMap};
use pallet_evm::{ExitError, ExitSucceed, Precompile};
use sp_core::{H160, U256};

use pallet_evm_precompile_storage_reader::{
    meta_storage_reader::{
        input::MetaStorageReaderInput as Input,
        key::{DoubleMapKey, MapKey, NoKey},
        Error, MetaStorageReader,
    },
    output::RawStorageValue,
    params::Params,
};

pallet_evm_precompile_storage_reader::impl_pallet_storage_metadata_provider!(
    for Test:
        "DIDModule" => DIDModule
);

#[derive(Eq, PartialEq, Debug)]
enum ErrorWrapper {
    Execution(ExitError),
    Decoding(codec::Error),
}

impl From<ExitError> for ErrorWrapper {
    fn from(err: ExitError) -> Self {
        Self::Execution(err)
    }
}

impl From<codec::Error> for ErrorWrapper {
    fn from(err: codec::Error) -> Self {
        Self::Decoding(err)
    }
}

static DUMMY_CTX: &'static evm::Context = &evm::Context {
    address: H160([0; 20]),
    caller: H160([0; 20]),
    apparent_value: U256([32; 4]),
};

macro_rules! assert_decoded_eq {
    ($expr: expr, $val: expr) => {{
        assert_eq!(
            $expr.map_err(ErrorWrapper::Execution).and_then(
                |PrecompileOutput {
                     output,
                     exit_status,
                     ..
                 }| {
                    assert_eq!(exit_status, ExitSucceed::Returned);

                    let raw = RawStorageValue::decode_from_bytes(&output[..]);
                    raw.into_item()
                        .map(|bytes| {
                            Decode::decode(&mut &bytes[..]).map_err(ErrorWrapper::Decoding)
                        })
                        .transpose()
                }
            ),
            $val
        );
    }};
}

#[test]
fn invalid_input() {
    ext().execute_with(|| {
        let input = Input::new("Pallet", "Version", NoKey, Params::None);
        assert_decoded_eq!(
            MetaStorageReader::<Test>::execute(&input.encode(), Some(10_000_000), DUMMY_CTX),
            Err::<Option<StoredDidDetails<Test>>, _>(
                ExitError::from(Error::PalletStorageEntryNotFound).into()
            )
        );

        let input = Input::new("DIDModule", "Field", NoKey, Params::None);
        assert_decoded_eq!(
            MetaStorageReader::<Test>::execute(&input.encode(), Some(10_000_000), DUMMY_CTX),
            Err::<Option<StoredDidDetails<Test>>, _>(
                ExitError::from(Error::PalletStorageEntryNotFound).into()
            )
        );

        let input = Input::new("DIDModule", "DidControllers", NoKey, Params::None);
        assert_decoded_eq!(
            MetaStorageReader::<Test>::execute(&input.encode(), Some(10_000_000), DUMMY_CTX),
            Err::<Option<StoredDidDetails<Test>>, _>(ExitError::from(Error::InvalidKey).into())
        );

        let did = Did([2u8; 32]);
        let details: StoredDidDetails<Test> =
            WithNonce::new_with_nonce(OnChainDidDetails::new(IncId::from(1u32), 2, 3), 5).into();
        Dids::insert(did, &details);

        let input = Input::new("DIDModule", "Dids", MapKey::new(did), Params::None);
        assert_decoded_eq!(
            MetaStorageReader::<Test>::execute(&input.encode(), Some(10_000_000), DUMMY_CTX),
            Err::<Option<Did>, _>(
                codec::Error::from("Not enough data to fill buffer")
                    .chain("Could not decode `Did.0`")
                    .into()
            )
        );
    })
}

#[test]
fn entity_access() {
    ext().execute_with(|| {
        let input = Input::new("DIDModule", "Version", NoKey, Params::None);

        assert_decoded_eq!(
            MetaStorageReader::<Test>::execute(&input.encode(), Some(10_000_000), DUMMY_CTX),
            Ok(Some(StorageVersion::SingleKey))
        );
    })
}

#[test]
fn map_access() {
    ext().execute_with(|| {
        let did = Did([2u8; 32]);
        let details: StoredDidDetails<Test> =
            WithNonce::new_with_nonce(OnChainDidDetails::new(IncId::from(1u32), 2, 3), 5).into();

        Dids::insert(did, &details);

        let input = Input::new("DIDModule", "Dids", MapKey::new(did), Params::None);
        assert_decoded_eq!(
            MetaStorageReader::<Test>::execute(&input.encode(), Some(10_000_000), DUMMY_CTX),
            Ok(Some(details.clone()))
        );

        let non_existent_did = Did([3u8; 32]);
        assert_decoded_eq!(
            MetaStorageReader::<Test>::execute(
                &input
                    .with_replaced_key(MapKey::new(non_existent_did))
                    .encode(),
                Some(10_000_000),
                DUMMY_CTX
            ),
            Ok(None::<()>)
        );
    })
}

#[test]
fn double_map_access() {
    ext().execute_with(|| {
        let did = Did([3u8; 32]);
        let controller = Controller(Did([4u8; 32]));

        DidControllers::insert(did, controller, ());

        let input = Input::new(
            "DIDModule",
            "DidControllers",
            DoubleMapKey::new(did, controller),
            Params::None,
        );
        assert_decoded_eq!(
            MetaStorageReader::<Test>::execute(&input.encode(), Some(10_000_000), DUMMY_CTX),
            Ok(Some(()))
        );

        let non_existent_did = Did([5u8; 32]);
        assert_decoded_eq!(
            MetaStorageReader::<Test>::execute(
                &input
                    .with_replaced_key(DoubleMapKey::new(non_existent_did, controller))
                    .encode(),
                Some(10_000_000),
                DUMMY_CTX
            ),
            Ok(None::<()>)
        );

        let non_existent_controller = Controller(Did([6u8; 32]));
        assert_decoded_eq!(
            MetaStorageReader::<Test>::execute(
                &input
                    .with_replaced_key(DoubleMapKey::new(did, non_existent_controller))
                    .encode(),
                Some(10_000_000),
                DUMMY_CTX
            ),
            Ok(None::<()>)
        );
    })
}
