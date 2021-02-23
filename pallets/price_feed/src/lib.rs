#![cfg_attr(not(feature = "std"), no_std)]

use codec::{Decode, Encode};
use frame_support::{
    decl_error, decl_event, decl_module, decl_storage, dispatch, fail,
    traits::Get,
    weights::{Pays, Weight},
};
use frame_system::{self as system, ensure_root, ensure_signed};
use pallet_evm::{GasWeightMapping, Runner};
use sp_core::{H160, U256};
use sp_runtime::traits::{UniqueSaturatedInto, Zero};
use sp_std::str::FromStr;
use sp_std::{prelude::Vec, vec};

// use ethabi::{decode as eth_decode, ParamType};

pub mod util;
use util::{decode as eth_decode, ParamType};

#[cfg(test)]
mod mock;
#[cfg(test)]
mod tests;

const DUMMY_SOURCE: H160 = H160::zero();
const ZERO_VALUE: U256 = U256::zero();
const GAS_LIMIT: u64 = u64::MAX;

#[derive(Encode, Decode, Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ContractConfig {
    /// Address of the contract
    pub address: H160,
    /// The ABI of the function to get the price, encoded
    pub query_abi_encoded: Vec<u8>,
    /// ABI of the return type of function corresponding to `query_abi_encoded`
    pub return_val_abi: Vec<ParamType>,
}

impl Default for ContractConfig {
    fn default() -> Self {
        ContractConfig {
            address: DUMMY_SOURCE,
            query_abi_encoded: vec![],
            return_val_abi: vec![],
        }
    }
}

pub trait Config: system::Config + pallet_evm::Config {
    /// The overarching event type.
    type Event: From<Event> + Into<<Self as system::Config>::Event>;
}

decl_storage! {
    trait Store for Module<T: Config> as PriceFeedModule {
        /// Stores contract configuration for DOCK/USD pair. This is the only pair that is relevant right now.
        /// If we need more pairs in future, we can change this to map with a runtime storage migration
        pub ContractConfigStore get(fn contract_config): Option<ContractConfig>;

        /// Price of DOCK/USD pair
        pub Price get(fn price): Option<u32>;

        /// Last update to price by reading from contract was done at this block number
        LastPriceUpdateAt get(fn last_price_update_at): Option<T::BlockNumber>;

        /// Price update frequency. After every few blocks the price is read from the contract and
        /// the storage item `Price` is updated unless update frequency is set to `None` or 0.
        PriceUpdateFreq get(fn price_update_freq): Option<u32>;
    }

    add_extra_genesis {
        config(contract_config): ContractConfig;
        build(|config| {
            ContractConfigStore::put(config.contract_config.clone());
        })
    }
}

decl_event!(
    pub enum Event {
        ContractConfigSet(ContractConfig),
        PriceSet(u32),
        UpdateFrequencySet(u32),
    }
);

decl_error! {
    pub enum Error for Module<T: Config> {
        ContractConfigNotFound,
        ContractCallFailed,
        ResponseParsingFailed,
        ResponseDoesNotHaveIntegerPrice,
        PriceIsZero,
    }
}

decl_module! {
    pub struct Module<T: Config> for enum Call where origin: T::Origin {
        fn deposit_event() = default;

        type Error = Error<T>;

        /// Set the config of the contract that has the price of DOCK/USD pair. Only callable by Root.
        #[weight = T::DbWeight::get().writes(1)]
        pub fn set_contract_config(origin, config: ContractConfig) -> dispatch::DispatchResultWithPostInfo {
            ensure_root(origin)?;
            ContractConfigStore::put(config.clone());
            Self::deposit_event(Event::ContractConfigSet(config));
            Ok(Pays::No.into())
        }

        /// Set the price update frequency in terms of number of blocks. After every `freq` number of blocks,
        /// the price of DOCK/USD pair is read from contract and storage item `Price` is updated.
        /// Only callable by Root.
        #[weight = T::DbWeight::get().writes(1)]
        pub fn set_update_frequency(origin, freq: u32) -> dispatch::DispatchResultWithPostInfo {
            ensure_root(origin)?;
            PriceUpdateFreq::put(freq);
            Self::deposit_event(Event::UpdateFrequencySet(freq));
            Ok(Pays::No.into())
        }

        // TODO: Remove this call
        #[weight = 0]
        pub fn get_(origin) -> dispatch::DispatchResultWithPostInfo {
            ensure_signed(origin)?;
            Self::get_price__()?;
            Ok(Pays::No.into())
        }

        fn on_initialize(current_block_no: T::BlockNumber) -> Weight {
            Self::update_price_if_stale(current_block_no).unwrap_or_else(|e| {
                sp_runtime::print(e);
                // Using larger weight than would occur most times to avoid code complexity
                T::DbWeight::get().reads(2)
            })
        }
    }
}

impl<T: Config> Module<T> {
    // TODO: Remove
    fn get_price__() -> dispatch::DispatchResult {
        let config = <T as pallet_evm::Config>::config();
        // let source = H160::from([0; 20]);
        let contract_addr = H160::from_str("0x6677AE2e2Cc985446d42a5BDeE182702e85E8587").unwrap();
        // let value = U256::from(0);
        let input = vec![254, 175, 150, 140];
        let ret_params = [
            ParamType::Uint(80),
            ParamType::Int(256),
            ParamType::Uint(256),
            ParamType::Uint(256),
            ParamType::Uint(80),
        ];
        // let info = <T as pallet_evm::Config>::Runner::call(source, contract_addr, input, value, 100000000, None, None, config).map_err(|err| err.into())?;
        let info = <T as pallet_evm::Config>::Runner::call(
            DUMMY_SOURCE,
            contract_addr,
            input,
            ZERO_VALUE,
            GAS_LIMIT,
            None,
            None,
            config,
        )
        .map_err(|err| err.into())?;
        frame_support::debug::native::debug!("info is {:?}", info);

        // let decoded = eth_decode(&[ParamType::Uint(80), ParamType::Int(256), ParamType::Uint(256), ParamType::Uint(256), ParamType::Uint(80)], &info.value).unwrap();
        // frame_support::debug::native::debug!("answer token is {:?}", decoded[1]);
        // let price = decoded[1].into_int();
        // frame_support::debug::native::debug!("answer is {:?}", price);
        // frame_support::debug::native::debug!("answer is {:?}", price.unwrap());

        let decoded = eth_decode(&ret_params, &info.value).unwrap();
        frame_support::debug::native::debug!("answer token is {:?}", decoded[1]);
        let price = decoded[1].clone().into_int();
        frame_support::debug::native::debug!("answer is {:?}", price);

        let p = price.unwrap();
        frame_support::debug::native::debug!("answer is {:?}", p);

        frame_support::debug::native::debug!("answer is {:?}", p.low_u128());

        // unimplemented!()
        Ok(())
    }

    fn update_price_if_stale(
        current_block_no: T::BlockNumber,
    ) -> Result<Weight, dispatch::DispatchError> {
        let (stale, mut weight) = Self::is_price_stale(current_block_no);
        if stale {
            weight += Self::update_price_from_contract()?;
            Ok(weight)
        } else {
            Ok(weight)
        }
    }

    /// Gets price of pair DOCK/USD from contract and update `Price`
    fn update_price_from_contract() -> Result<Weight, dispatch::DispatchError> {
        let (price, weight) = Self::get_price_from_contract()?;
        Price::put(price);
        LastPriceUpdateAt::<T>::put(<system::Module<T>>::block_number());
        Self::deposit_event(Event::PriceSet(price));
        Ok(weight + T::DbWeight::get().writes(2))
    }

    /// Return if price is stale and need to be updated and the weight consumed while finding that out
    pub fn is_price_stale(current_block_no: T::BlockNumber) -> (bool, Weight) {
        let freq = Self::price_update_freq().unwrap_or(0);
        if freq > 0 {
            let last_update = Self::last_price_update_at().unwrap_or(T::BlockNumber::zero());
            (
                (last_update > T::BlockNumber::zero())
                    && (current_block_no >= (last_update + T::BlockNumber::from(freq))),
                T::DbWeight::get().reads(2),
            )
        } else {
            (false, T::DbWeight::get().reads(1))
        }
    }

    /// Gets price of pair DOCK/USD by reading from the contract. Returns the weight consumed in
    /// this function as well
    pub fn get_price_from_contract() -> Result<(u32, Weight), dispatch::DispatchError> {
        let contract_config =
            Self::contract_config().ok_or_else(|| Error::<T>::ContractCallFailed)?;
        let (evm_resp, used_gas) = Self::get_evm_call_response(
            contract_config.address,
            contract_config.query_abi_encoded,
        )?;
        let price = Self::decode_evm_response_to_price(&contract_config.return_val_abi, &evm_resp)?;
        Ok((
            price,
            T::DbWeight::get().reads(1)
                + <T as pallet_evm::Config>::GasWeightMapping::gas_to_weight(
                    used_gas.unique_saturated_into(),
                ),
        ))
    }

    /// Make an EVM `call` to the contract with address `contract_addr` and the call is described by `input`.
    /// Returns the response and gas used in the call.
    pub fn get_evm_call_response(
        contract_addr: H160,
        input: Vec<u8>,
    ) -> Result<(Vec<u8>, U256), dispatch::DispatchError> {
        let evm_config = <T as pallet_evm::Config>::config();
        // As its a read call, the source can be any address and no gas price or nonce needs to be set.
        let info = <T as pallet_evm::Config>::Runner::call(
            DUMMY_SOURCE,
            contract_addr,
            input,
            ZERO_VALUE,
            GAS_LIMIT,
            None,
            None,
            evm_config,
        )
        .map_err(|err| err.into())?;
        if info.exit_reason.is_succeed() {
            Ok((info.value, info.used_gas))
        } else {
            fail!(Error::<T>::ContractCallFailed)
        }
    }

    /// Decode return value of contract call to price.
    pub fn decode_evm_response_to_price(
        return_val_abi: &[ParamType],
        return_val: &[u8],
    ) -> Result<u32, dispatch::DispatchError> {
        let decoded = eth_decode(return_val_abi, return_val)
            .map_err(|_| Error::<T>::ResponseParsingFailed)?;
        if decoded.len() < 2 {
            fail!(Error::<T>::ResponseParsingFailed)
        }

        // Using `low_u32` as its assumed that price always fit in 4 bytes
        let price = decoded[1]
            .clone()
            .into_int()
            .ok_or_else(|| Error::<T>::ResponseDoesNotHaveIntegerPrice)?
            .low_u32();
        if price == 0 {
            fail!(Error::<T>::PriceIsZero)
        }
        Ok(price)
    }
}
