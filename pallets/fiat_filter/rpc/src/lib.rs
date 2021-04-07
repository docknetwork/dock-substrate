use jsonrpc_core::{Error as RpcError, ErrorCode, Result};
use jsonrpc_derive::rpc;
use sp_api::ProvideRuntimeApi;
use sp_blockchain::HeaderBackend;
use sp_core::Bytes;
use sp_runtime::codec::{Codec, Decode};
use sp_runtime::generic::BlockId;
use sp_runtime::traits::{Block as BlockT, MaybeDisplay};
use std::sync::Arc;

pub use fiat_filter_rpc_runtime_api::FiatFeeRuntimeApi;

#[rpc]
pub trait FiatFeeApi<Balance> {
    /// Accepts a scale-encoded extrinsic, returns fee in µDOCK as Balance (u64)
    #[rpc(name = "fiat_filter_getCallFeeDock")]
    fn get_call_fee_dock(&self, encoded_xt: Bytes) -> Result<Balance>;
}

/// Error type of this RPC api.
pub enum FiatFeeRpcError {
    /// The transaction was not decodable.
    DecodeError,
    /// The call to runtime failed.
    RuntimeError,
    /// The call succeeded but the function called returned an error
    GetCallFeeDock,
}
impl From<FiatFeeRpcError> for i64 {
    fn from(e: FiatFeeRpcError) -> i64 {
        match e {
            FiatFeeRpcError::RuntimeError => 1,
            FiatFeeRpcError::DecodeError => 2,
            FiatFeeRpcError::GetCallFeeDock => 3,
        }
    }
}

/// A struct that implements the FiatFeeApi
pub struct FiatFeeServer<Client, Block> {
    client: Arc<Client>,
    _marker_block: std::marker::PhantomData<Block>,
}
impl<Client, Block> FiatFeeServer<Client, Block> {
    pub fn new(client: Arc<Client>) -> Self {
        Self {
            client,
            _marker_block: Default::default(),
        }
    }
}
impl<Client, Block, Balance> FiatFeeApi<Balance> for FiatFeeServer<Client, Block>
where
    Block: BlockT,
    Client: Send + Sync + 'static + ProvideRuntimeApi<Block> + HeaderBackend<Block>,
    Client::Api: FiatFeeRuntimeApi<Block, Balance>,
    Balance: Codec + MaybeDisplay,
{
    fn get_call_fee_dock(&self, encoded_xt: Bytes) -> Result<Balance> {
        let api = self.client.runtime_api();
        // automatically pick the latest/best block
        let at = BlockId::<Block>::hash(self.client.info().best_hash);

        // decode extrinsic
        let uxt: Block::Extrinsic = Decode::decode(&mut &*encoded_xt).map_err(|e| RpcError {
            code: ErrorCode::ServerError(FiatFeeRpcError::DecodeError.into()),
            message: "Failed to decode request".into(),
            data: Some(format!("{:?}", e).into()),
        })?;

        // call runtime api method get_call_fee_dock()
        match api.get_call_fee_dock(&at, uxt) {
            Ok(rlt) => rlt.map_err(|e| RpcError {
                code: ErrorCode::ServerError(FiatFeeRpcError::GetCallFeeDock.into()),
                message: "Failed getting fee in DOCK".into(),
                data: Some(format!("{:?}", e).into()),
            }),
            Err(e) => Err(RpcError {
                code: ErrorCode::ServerError(FiatFeeRpcError::RuntimeError.into()),
                message: "Failed getting fee in DOCK".into(),
                data: Some(format!("{:?}", e).into()),
            }),
        }
    }
}
