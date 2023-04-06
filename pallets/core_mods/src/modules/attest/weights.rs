//! Autogenerated weights for attest
//!
//! THIS FILE WAS AUTO-GENERATED USING THE SUBSTRATE BENCHMARK CLI VERSION 3.0.0
//! DATE: 2022-08-01, STEPS: `[50, ]`, REPEAT: 20, LOW RANGE: `[]`, HIGH RANGE: `[]`
//! EXECUTION: Some(Native), WASM-EXECUTION: Interpreted, CHAIN: Some("mainnet"), DB CACHE: 128

// Executed Command:
// ./target/production/dock-node
// benchmark
// --execution=native
// --chain=mainnet
// --pallet=attest
// --extra
// --extrinsic=*
// --repeat=20
// --steps=50
// --template=node/module-weight-template.hbs
// --output=./pallets/core_mods/src/modules/attest/weights.rs

#![allow(unused_parens)]
#![allow(unused_imports)]

use frame_support::{
    traits::Get,
    weights::{constants::RocksDbWeight, Weight},
};
use sp_std::marker::PhantomData;

/// Weight functions needed for attest.
pub trait WeightInfo {
    fn set_claim_sr25519(l: u32) -> Weight;
    fn set_claim_ed25519(l: u32) -> Weight;
    fn set_claim_secp256k1(l: u32) -> Weight;
}

/// Weights for attest using the Substrate node and recommended hardware.
pub struct SubstrateWeight<T>(PhantomData<T>);
impl<T: frame_system::Config> WeightInfo for SubstrateWeight<T> {
    fn set_claim_sr25519(l: u32) -> Weight {
        Weight::from_ref_time(49_216_000_u64)
            // Standard Error: 0
            .saturating_add(Weight::from_ref_time(3_000_u64).saturating_mul(l as u64))
            .saturating_add(T::DbWeight::get().reads(3_u64))
            .saturating_add(T::DbWeight::get().writes(2_u64))
    }
    fn set_claim_ed25519(l: u32) -> Weight {
        Weight::from_ref_time(49_142_000_u64)
            // Standard Error: 0
            .saturating_add(Weight::from_ref_time(2_000_u64).saturating_mul(l as u64))
            .saturating_add(T::DbWeight::get().reads(3_u64))
            .saturating_add(T::DbWeight::get().writes(2_u64))
    }
    fn set_claim_secp256k1(l: u32) -> Weight {
        Weight::from_ref_time(152_813_000_u64)
            // Standard Error: 0
            .saturating_add(Weight::from_ref_time(1_000_u64).saturating_mul(l as u64))
            .saturating_add(T::DbWeight::get().reads(3_u64))
            .saturating_add(T::DbWeight::get().writes(2_u64))
    }
}

// For backwards compatibility and tests
impl WeightInfo for () {
    fn set_claim_sr25519(l: u32) -> Weight {
        Weight::from_ref_time(49_216_000_u64)
            // Standard Error: 0
            .saturating_add(Weight::from_ref_time(3_000_u64).saturating_mul(l as u64))
            .saturating_add(RocksDbWeight::get().reads(3_u64))
            .saturating_add(RocksDbWeight::get().writes(2_u64))
    }
    fn set_claim_ed25519(l: u32) -> Weight {
        Weight::from_ref_time(49_142_000_u64)
            // Standard Error: 0
            .saturating_add(Weight::from_ref_time(2_000_u64).saturating_mul(l as u64))
            .saturating_add(RocksDbWeight::get().reads(3_u64))
            .saturating_add(RocksDbWeight::get().writes(2_u64))
    }
    fn set_claim_secp256k1(l: u32) -> Weight {
        Weight::from_ref_time(152_813_000_u64)
            // Standard Error: 0
            .saturating_add(Weight::from_ref_time(1_000_u64).saturating_mul(l as u64))
            .saturating_add(RocksDbWeight::get().reads(3_u64))
            .saturating_add(RocksDbWeight::get().writes(2_u64))
    }
}
