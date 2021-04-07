#![cfg_attr(not(feature = "std"), no_std)]

use codec::Codec;
use sp_runtime::traits::MaybeDisplay;
use sp_runtime::DispatchError;

#[derive(Debug, PartialEq, codec::Encode, codec::Decode)]
pub enum Error {
    #[codec(index = 15)]
    GetCallFeeDock(DispatchError),
}
impl Error {
    pub fn new_getcallfeedock(e: DispatchError) -> Self {
        Error::GetCallFeeDock(e)
    }
}

sp_api::decl_runtime_apis! {
    pub trait FiatFeeRuntimeApi<Balance> where
        Balance: Codec + MaybeDisplay,
    {
        /// Accepts any extrinsic, signature not needed.
        /// Returns the call fee fee in µDOCK as Balance (Balance is u64 in current runtime)
        /// If the extrinsic is not one of the calls supported by FiatFilter, returns an error
        // Block refers to the type argument auto-added to FiatFeeRuntimeApi by decl_runtime_apis!
        fn get_call_fee_dock(uxt: Block::Extrinsic) -> Result<Balance,Error>;
    }
}
