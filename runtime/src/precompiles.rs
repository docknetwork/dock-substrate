use codec::Decode;
use frame_support::{dispatch::Dispatchable, weights::*};
use pallet_evm::{Precompile, PrecompileHandle, PrecompileResult, PrecompileSet};
use pallet_evm_precompile_storage_reader::meta_storage_reader::PalletStorageMetadataProvider;
use sp_core::H160;
use sp_std::marker::PhantomData;

#[derive(Default)]
pub struct FrontierPrecompiles<R>(PhantomData<R>);

impl<R> FrontierPrecompiles<R>
where
    R: pallet_evm::Config,
{
    pub fn new() -> Self {
        Self(Default::default())
    }

    pub fn used_addresses() -> sp_std::vec::Vec<H160> {
        (1..=15).map(hash).collect()
    }
}

impl<T> PrecompileSet for FrontierPrecompiles<T>
where
    T: pallet_evm::Config + PalletStorageMetadataProvider,
    T::Call: Dispatchable<PostInfo = PostDispatchInfo> + GetDispatchInfo + Decode,
    <T::Call as Dispatchable>::Origin: From<Option<T::AccountId>>,
{
    fn execute(&self, handle: &mut impl PrecompileHandle) -> Option<PrecompileResult> {
        match handle.code_address() {
            a if a == hash(1) => Some(pallet_evm_precompile_simple::ECRecover::execute(handle)),
            a if a == hash(2) => Some(pallet_evm_precompile_simple::Sha256::execute(handle)),
            a if a == hash(3) => Some(pallet_evm_precompile_simple::Ripemd160::execute(handle)),
            a if a == hash(4) => Some(pallet_evm_precompile_simple::Identity::execute(handle)),
            a if a == hash(5) => Some(pallet_evm_precompile_simple::ECRecoverPublicKey::execute(
                handle,
            )),
            a if a == hash(6) => Some(pallet_evm_precompile_sha3fips::Sha3FIPS256::execute(handle)),
            a if a == hash(7) => Some(pallet_evm_precompile_sha3fips::Sha3FIPS512::execute(handle)),
            a if a == hash(8) => Some(pallet_evm_precompile_ed25519::Ed25519Verify::execute(
                handle,
            )),
            a if a == hash(9) => Some(pallet_evm_precompile_modexp::Modexp::execute(handle)),
            a if a == hash(10) => Some(pallet_evm_precompile_bn128::Bn128Add::execute(handle)),
            a if a == hash(11) => Some(pallet_evm_precompile_bn128::Bn128Mul::execute(handle)),
            a if a == hash(12) => Some(pallet_evm_precompile_bn128::Bn128Pairing::execute(handle)),
            a if a == hash(13) => Some(pallet_evm_precompile_dispatch::Dispatch::<T>::execute(
                handle,
            )),
            a if a == hash(14) => {
                Some(pallet_evm_precompile_storage_reader::MetaStorageReader::<T>::execute(handle))
            }
            a if a == hash(15) => {
                Some(pallet_evm_precompile_storage_reader::RawStorageReader::<T>::execute(handle))
            }
            _ => None,
        }
    }

    fn is_precompile(&self, address: H160) -> bool {
        Self::used_addresses().contains(&address)
    }
}

fn hash(a: u64) -> H160 {
    H160::from_low_u64_be(a)
}
