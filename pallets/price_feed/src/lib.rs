//! Periodically fetches price of DOCK/USD from smart contract running on EVM and stores the price in its storage.
//! The periodicity and contract configuration like address, query method and return value type can be configured by root.

#![cfg_attr(not(feature = "std"), no_std)]

use codec::{Decode, Encode};
use frame_support::{
    decl_error, decl_event, decl_module, decl_storage, dispatch, fail,
    traits::Get,
    weights::{Pays, Weight},
};
use frame_system::{self as system, ensure_root};
use pallet_evm::{CallInfo, GasWeightMapping, Runner};
use sp_core::{H160, U256};
use sp_runtime::traits::{UniqueSaturatedInto, Zero};
use sp_std::{prelude::Vec, vec};

pub mod runtime_api;
pub mod util;
use util::{decode as eth_decode, ParamType};

use common::traits::PriceProvider;

#[cfg(test)]
mod mock;
#[cfg(test)]
mod tests;

const DUMMY_SOURCE: H160 = H160::zero();
const ZERO_VALUE: U256 = U256::zero();
const GAS_LIMIT: u64 = u32::MAX as u64;

#[derive(Encode, Decode, scale_info::TypeInfo, Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ContractConfig {
    /// Address of the proxy contract
    pub address: H160,
    /// ABI of the method `aggregator` of the proxy contract. This method is called to get the
    /// address of the Aggregator contract from which price has to be checked. The return value of
    /// this method is a single value which is an address.
    pub query_aggregator_abi_encoded: Vec<u8>,
    /// The ABI of the function to get the price, encoded.
    /// At the time of writing, it is function `latestRoundData` of the contract.
    pub query_price_abi_encoded: Vec<u8>,
    /// ABI of the return type of function corresponding to `query_abi_encoded`.
    /// At the time of writing, this is `[uint(80), int(256), uint(256), uint(256), uint(80)]`
    pub return_val_abi: Vec<ParamType>,
}

impl Default for ContractConfig {
    fn default() -> Self {
        ContractConfig {
            address: DUMMY_SOURCE,
            query_aggregator_abi_encoded: vec![],
            query_price_abi_encoded: vec![],
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
        ProxyContractCallFailed,
        AddressParsingFailed,
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
    /// Update price in pallet's storage from contract if the price is stale
    fn update_price_if_stale(
        current_block_no: T::BlockNumber,
    ) -> Result<Weight, dispatch::DispatchError> {
        let (stale, mut weight) = Self::is_price_stale(current_block_no);
        if stale {
            weight = weight.saturating_add(Self::update_price_from_contract()?);
            Ok(weight)
        } else {
            Ok(weight)
        }
    }

    /// Gets price of pair DOCK/USD from contract and update pallet storage item `Price`
    fn update_price_from_contract() -> Result<Weight, dispatch::DispatchError> {
        let (price, weight) = Self::get_price_from_contract()?;
        Price::put(price);
        LastPriceUpdateAt::<T>::put(<system::Pallet<T>>::block_number());
        Self::deposit_event(Event::PriceSet(price));
        Ok(weight + T::DbWeight::get().writes(2))
    }

    /// Return if price is stale and need to be updated and the weight consumed while finding that out
    pub fn is_price_stale(current_block_no: T::BlockNumber) -> (bool, Weight) {
        let freq = Self::price_update_freq().unwrap_or(0);
        if freq > 0 {
            let last_update = Self::last_price_update_at().unwrap_or(T::BlockNumber::zero());
            (
                current_block_no >= (last_update + T::BlockNumber::from(freq)),
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
        let (evm_resp, used_gas) = Self::get_response_from_evm(
            contract_config.address,
            contract_config.query_aggregator_abi_encoded,
            contract_config.query_price_abi_encoded,
        )?;
        // Ignoring the weight of this operation as its in-memory and cheap
        let price = Self::decode_evm_response_to_price(&contract_config.return_val_abi, &evm_resp)?;
        Ok((
            price,
            // Involves 2 reads, one to read the aggregator's address from proxy and one to read
            // the price from aggregator contract
            T::DbWeight::get().reads(2)
                + <T as pallet_evm::Config>::GasWeightMapping::gas_to_weight(
                    used_gas.unique_saturated_into(),
                ),
        ))
    }

    /// Make EVM `call`s (read) to get the price. Returns the response and gas used in the call
    /// `contract_addr` is the address of a proxy contract which can be queried for the address of the
    /// actual aggregator contract which is then queried for the price. The reason to have this proxy pattern
    /// is to enable upgradability
    pub fn get_response_from_evm(
        contract_addr: H160,
        query_aggregator_abi: Vec<u8>,
        query_price_abi: Vec<u8>,
    ) -> Result<(Vec<u8>, U256), dispatch::DispatchError> {
        let (aggregator_address, used_gas_a) =
            Self::get_aggregator_address_from_proxy(contract_addr, query_aggregator_abi)?;

        let (price, used_gas_p) =
            Self::get_price_from_aggregator(aggregator_address, query_price_abi)?;

        Ok((price, used_gas_a.saturating_add(used_gas_p)))
    }

    /// Get address of the aggregator contract from the proxy contract
    pub fn get_aggregator_address_from_proxy(
        proxy_contract_addr: H160,
        query_aggregator_abi: Vec<u8>,
    ) -> Result<(H160, U256), dispatch::DispatchError> {
        // Get aggregator address from proxy
        let info = Self::read_from_evm_contract(proxy_contract_addr, query_aggregator_abi)?;
        if !info.exit_reason.is_succeed() {
            // XXX: Would be better to not ignore the used gas even if failed.
            fail!(Error::<T>::ProxyContractCallFailed)
        }
        let decoded = eth_decode(&[ParamType::Address], &info.value)
            .map_err(|_| Error::<T>::AddressParsingFailed)?;
        if decoded.len() < 1 {
            fail!(Error::<T>::AddressParsingFailed)
        }

        let aggregator_address = decoded[0]
            .clone()
            .into_address()
            .ok_or_else(|| Error::<T>::AddressParsingFailed)?;
        Ok((aggregator_address, info.used_gas))
    }

    /// Get price from the aggregator contact.
    pub fn get_price_from_aggregator(
        aggregator_address: H160,
        query_price_abi: Vec<u8>,
    ) -> Result<(Vec<u8>, U256), dispatch::DispatchError> {
        let info = Self::read_from_evm_contract(aggregator_address, query_price_abi)?;
        if info.exit_reason.is_succeed() {
            Ok((info.value, info.used_gas))
        } else {
            // XXX: Would be better to not ignore the used gas even if failed.
            fail!(Error::<T>::ContractCallFailed)
        }
    }

    /// Read from EVM contract with address `contract_address`. The function to call is ABI encoded as `input`
    pub fn read_from_evm_contract(
        contract_address: H160,
        input: Vec<u8>,
    ) -> Result<CallInfo, dispatch::DispatchError> {
        let evm_config = <T as pallet_evm::Config>::config();
        // As its a read call, the source can be any address and no gas price or nonce needs to be set.
        let is_transactional = false;
        let validate = true;

        <T as pallet_evm::Config>::Runner::call(
            DUMMY_SOURCE,
            contract_address,
            input,
            ZERO_VALUE,
            GAS_LIMIT,
            None,
            None,
            None,
            Default::default(),
            is_transactional,
            validate,
            evm_config,
        )
        .map_err(|err| err.error.into())
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

impl<T: Config> PriceProvider for Module<T> {
    /// Gets the price of Dock/USD from pallet's storage
    fn get_dock_usd_price() -> Option<(u32, u64)> {
        Self::get_price_from_contract()
            .ok()
            .map(|(value, weight)| (value, weight.ref_time()))
    }

    /// Gets the price of Dock/USD from EVM contract
    fn optimized_get_dock_usd_price() -> Option<(u32, u64)> {
        Self::price().map(|p| (p, T::DbWeight::get().reads(1).ref_time()))
    }
}
