//! Autogenerated weights for anchor
//!
//! THIS FILE WAS AUTO-GENERATED USING THE SUBSTRATE BENCHMARK CLI VERSION 3.0.0
//! DATE: 2022-08-01, STEPS: `[50, ]`, REPEAT: 20, LOW RANGE: `[]`, HIGH RANGE: `[]`
//! EXECUTION: Some(Native), WASM-EXECUTION: Interpreted, CHAIN: Some("mainnet"), DB CACHE: 128

// Executed Command:
// ./target/production/dock-node
// benchmark
// --execution=native
// --chain=mainnet
// --pallet=anchor
// --extra
// --extrinsic=*
// --repeat=20
// --steps=50
// --template=node/module-weight-template.hbs
// --output=./pallets/core_mods/src/modules/anchor/weights.rs

#![allow(unused_parens)]
#![allow(unused_imports)]

use frame_support::{
    traits::Get,
    weights::{constants::RocksDbWeight, Weight},
};
use sp_std::marker::PhantomData;

/// Weight functions needed for anchor.
pub trait WeightInfo {
    fn deploy(l: u32) -> Weight;
}

/// Weights for anchor using the Substrate node and recommended hardware.
pub struct SubstrateWeight<T>(PhantomData<T>);
impl<T: frame_system::Config> WeightInfo for SubstrateWeight<T> {
    fn deploy(l: u32) -> Weight {
        (5_881_000 as Weight)
            // Standard Error: 0
            .saturating_add((1_000 as Weight).saturating_mul(l as Weight))
            .saturating_add(T::DbWeight::get().reads(1 as Weight))
            .saturating_add(T::DbWeight::get().writes(1 as Weight))
    }
}

// For backwards compatibility and tests
impl WeightInfo for () {
    fn deploy(l: u32) -> Weight {
        (5_881_000 as Weight)
            // Standard Error: 0
            .saturating_add((1_000 as Weight).saturating_mul(l as Weight))
            .saturating_add(RocksDbWeight::get().reads(1 as Weight))
            .saturating_add(RocksDbWeight::get().writes(1 as Weight))
    }
}
