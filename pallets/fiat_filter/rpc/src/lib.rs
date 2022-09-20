use jsonrpsee::{
    core::{async_trait, Error as JsonRpseeError, RpcResult},
    proc_macros::rpc,
    types::{error::CallError, ErrorObject},
};
use sp_api::ProvideRuntimeApi;
use sp_blockchain::HeaderBackend;
use sp_core::Bytes;
use sp_runtime::{
    codec::{Codec, Decode},
    generic::BlockId,
    traits::{Block as BlockT, MaybeDisplay},
};
use std::sync::Arc;

pub use fiat_filter_rpc_runtime_api::FiatFeeRuntimeApi;

#[rpc(client, server)]
pub trait FiatFeeApi<BlockHash, Balance> {
    /// Accepts a scale-encoded extrinsic, returns fee in µDOCK as Balance (u64)
    #[method(name = "fiat_filter_getCallFeeDock")]
    async fn get_call_fee_dock(
        &self,
        encoded_xt: Bytes,
        at: Option<BlockHash>,
    ) -> RpcResult<Balance>;
}

/// Error type of this RPC api.
#[derive(Debug, thiserror::Error)]
pub enum FiatFeeRpcError {
    /// The transaction was not decodable.
    #[error("Failed to decode request")]
    DecodeError(String),
    /// The call to runtime failed.
    #[error("Runtime error")]
    RuntimeError(String),
    /// The call succeeded but the function called returned an error
    #[error("Failed getting fee in DOCK")]
    GetCallFeeDock(String),
}

impl From<FiatFeeRpcError> for i32 {
    fn from(e: FiatFeeRpcError) -> i32 {
        match e {
            FiatFeeRpcError::RuntimeError(_) => 1,
            FiatFeeRpcError::DecodeError(_) => 2,
            FiatFeeRpcError::GetCallFeeDock(_) => 3,
        }
    }
}

impl From<FiatFeeRpcError> for JsonRpseeError {
    fn from(error: FiatFeeRpcError) -> Self {
        let msg = error.to_string();
        let data = match &error {
            FiatFeeRpcError::DecodeError(data)
            | FiatFeeRpcError::RuntimeError(data)
            | FiatFeeRpcError::GetCallFeeDock(data) => data,
        }
        .clone();

        JsonRpseeError::Call(CallError::Custom(ErrorObject::owned(
            error.into(),
            msg,
            Some(data),
        )))
    }
}

/// A struct that implements the FiatFeeApi
pub struct FiatFee<Client, Block> {
    client: Arc<Client>,
    _marker_block: std::marker::PhantomData<Block>,
}
impl<Client, Block> FiatFee<Client, Block> {
    pub fn new(client: Arc<Client>) -> Self {
        Self {
            client,
            _marker_block: Default::default(),
        }
    }
}

#[async_trait]
impl<Client, Block, Balance> FiatFeeApiServer<<Block as BlockT>::Hash, Balance>
    for FiatFee<Client, Block>
where
    Block: BlockT,
    Client: Send + Sync + 'static + ProvideRuntimeApi<Block> + HeaderBackend<Block>,
    Client::Api: FiatFeeRuntimeApi<Block, Balance>,
    Balance: Codec + MaybeDisplay,
{
    async fn get_call_fee_dock(
        &self,
        encoded_xt: Bytes,
        at: Option<<Block as BlockT>::Hash>,
    ) -> RpcResult<Balance> {
        let api = self.client.runtime_api();
        let at = BlockId::hash(at.unwrap_or_else(||
            // If the block hash is not supplied, assume the latest/best block
            self.client.info().best_hash));

        // decode extrinsic
        let uxt: Block::Extrinsic = Decode::decode(&mut &*encoded_xt)
            .map_err(|err| err.to_string())
            .map_err(FiatFeeRpcError::DecodeError)?;

        // call runtime api method get_call_fee_dock()
        api.get_call_fee_dock(&at, uxt)
            .map_err(|err| err.to_string())
            .map_err(FiatFeeRpcError::RuntimeError)?
            .map_err(|err| format!("{:?}", err))
            .map_err(FiatFeeRpcError::GetCallFeeDock)
            .map_err(Into::into)
    }
}
