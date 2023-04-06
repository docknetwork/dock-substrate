//! Autogenerated weights for accumulator
//!
//! THIS FILE WAS AUTO-GENERATED USING THE SUBSTRATE BENCHMARK CLI VERSION 3.0.0
//! DATE: 2022-08-01, STEPS: `[50, ]`, REPEAT: 20, LOW RANGE: `[]`, HIGH RANGE: `[]`
//! EXECUTION: Some(Native), WASM-EXECUTION: Interpreted, CHAIN: Some("mainnet"), DB CACHE: 128

// Executed Command:
// ./target/production/dock-node
// benchmark
// --execution=native
// --chain=mainnet
// --pallet=accumulator
// --extra
// --extrinsic=*
// --repeat=20
// --steps=50
// --template=node/module-weight-template.hbs
// --output=./pallets/core_mods/src/modules/accumulator/weights.rs

#![allow(unused_parens)]
#![allow(unused_imports)]

use frame_support::{
    traits::Get,
    weights::{constants::RocksDbWeight, Weight},
};
use sp_std::marker::PhantomData;

/// Weight functions needed for accumulator.
pub trait WeightInfo {
    fn add_params_sr25519(b: u32, l: u32) -> Weight;
    fn add_params_ed25519(b: u32, l: u32) -> Weight;
    fn add_params_secp256k1(b: u32, l: u32) -> Weight;
    fn remove_params_sr25519() -> Weight;
    fn remove_params_ed25519() -> Weight;
    fn remove_params_secp256k1() -> Weight;
    fn add_public_sr25519(b: u32) -> Weight;
    fn add_public_ed25519(b: u32) -> Weight;
    fn add_public_secp256k1(b: u32) -> Weight;
    fn remove_public_sr25519() -> Weight;
    fn remove_public_ed25519() -> Weight;
    fn remove_public_secp256k1() -> Weight;
    fn add_accumulator_sr25519(b: u32) -> Weight;
    fn add_accumulator_ed25519(b: u32) -> Weight;
    fn add_accumulator_secp256k1(b: u32) -> Weight;
    fn update_accumulator_sr25519(a: u32, b: u32, c: u32, d: u32, e: u32, f: u32) -> Weight;
    fn update_accumulator_ed25519(a: u32, b: u32, c: u32, d: u32, e: u32, f: u32) -> Weight;
    fn update_accumulator_secp256k1(a: u32, b: u32, c: u32, d: u32, e: u32, f: u32) -> Weight;
    fn remove_accumulator_sr25519() -> Weight;
    fn remove_accumulator_ed25519() -> Weight;
    fn remove_accumulator_secp256k1() -> Weight;
}

/// Weights for accumulator using the Substrate node and recommended hardware.
pub struct SubstrateWeight<T>(PhantomData<T>);
impl<T: frame_system::Config> WeightInfo for SubstrateWeight<T> {
    fn add_params_sr25519(b: u32, l: u32) -> Weight {
        Weight::from_ref_time(54_891_000_u64)
            // Standard Error: 0
            .saturating_add(Weight::from_ref_time(8_000_u64).saturating_mul(b as u64))
            // Standard Error: 0
            .saturating_add(Weight::from_ref_time(8_000_u64).saturating_mul(l as u64))
            .saturating_add(T::DbWeight::get().reads(3_u64))
            .saturating_add(T::DbWeight::get().writes(3_u64))
    }
    fn add_params_ed25519(b: u32, _l: u32) -> Weight {
        Weight::from_ref_time(55_802_000_u64)
            // Standard Error: 0
            .saturating_add(Weight::from_ref_time(4_000_u64).saturating_mul(b as u64))
            .saturating_add(T::DbWeight::get().reads(3_u64))
            .saturating_add(T::DbWeight::get().writes(3_u64))
    }
    fn add_params_secp256k1(b: u32, l: u32) -> Weight {
        Weight::from_ref_time(159_890_000_u64)
            // Standard Error: 0
            .saturating_add(Weight::from_ref_time(4_000_u64).saturating_mul(b as u64))
            // Standard Error: 1_000
            .saturating_add(Weight::from_ref_time(2_000_u64).saturating_mul(l as u64))
            .saturating_add(T::DbWeight::get().reads(3_u64))
            .saturating_add(T::DbWeight::get().writes(3_u64))
    }
    fn remove_params_sr25519() -> Weight {
        Weight::from_ref_time(58_306_000_u64)
            .saturating_add(T::DbWeight::get().reads(3_u64))
            .saturating_add(T::DbWeight::get().writes(2_u64))
    }
    fn remove_params_ed25519() -> Weight {
        Weight::from_ref_time(55_655_000_u64)
            .saturating_add(T::DbWeight::get().reads(3_u64))
            .saturating_add(T::DbWeight::get().writes(2_u64))
    }
    fn remove_params_secp256k1() -> Weight {
        Weight::from_ref_time(162_917_000_u64)
            .saturating_add(T::DbWeight::get().reads(3_u64))
            .saturating_add(T::DbWeight::get().writes(2_u64))
    }
    fn add_public_sr25519(b: u32) -> Weight {
        Weight::from_ref_time(61_674_000_u64)
            // Standard Error: 0
            .saturating_add(Weight::from_ref_time(5_000_u64).saturating_mul(b as u64))
            .saturating_add(T::DbWeight::get().reads(4_u64))
            .saturating_add(T::DbWeight::get().writes(3_u64))
    }
    fn add_public_ed25519(b: u32) -> Weight {
        Weight::from_ref_time(60_164_000_u64)
            // Standard Error: 0
            .saturating_add(Weight::from_ref_time(4_000_u64).saturating_mul(b as u64))
            .saturating_add(T::DbWeight::get().reads(4_u64))
            .saturating_add(T::DbWeight::get().writes(3_u64))
    }
    fn add_public_secp256k1(_b: u32) -> Weight {
        Weight::from_ref_time(167_138_000_u64)
            .saturating_add(T::DbWeight::get().reads(4_u64))
            .saturating_add(T::DbWeight::get().writes(3_u64))
    }
    fn remove_public_sr25519() -> Weight {
        Weight::from_ref_time(56_413_000_u64)
            .saturating_add(T::DbWeight::get().reads(3_u64))
            .saturating_add(T::DbWeight::get().writes(2_u64))
    }
    fn remove_public_ed25519() -> Weight {
        Weight::from_ref_time(55_915_000_u64)
            .saturating_add(T::DbWeight::get().reads(3_u64))
            .saturating_add(T::DbWeight::get().writes(2_u64))
    }
    fn remove_public_secp256k1() -> Weight {
        Weight::from_ref_time(164_392_000_u64)
            .saturating_add(T::DbWeight::get().reads(3_u64))
            .saturating_add(T::DbWeight::get().writes(2_u64))
    }
    fn add_accumulator_sr25519(b: u32) -> Weight {
        Weight::from_ref_time(63_558_000_u64)
            // Standard Error: 0
            .saturating_add(Weight::from_ref_time(9_000_u64).saturating_mul(b as u64))
            .saturating_add(T::DbWeight::get().reads(5_u64))
            .saturating_add(T::DbWeight::get().writes(3_u64))
    }
    fn add_accumulator_ed25519(b: u32) -> Weight {
        Weight::from_ref_time(61_650_000_u64)
            // Standard Error: 0
            .saturating_add(Weight::from_ref_time(3_000_u64).saturating_mul(b as u64))
            .saturating_add(T::DbWeight::get().reads(5_u64))
            .saturating_add(T::DbWeight::get().writes(3_u64))
    }
    fn add_accumulator_secp256k1(_b: u32) -> Weight {
        Weight::from_ref_time(167_711_000_u64)
            .saturating_add(T::DbWeight::get().reads(5_u64))
            .saturating_add(T::DbWeight::get().writes(3_u64))
    }
    fn update_accumulator_sr25519(a: u32, b: u32, c: u32, d: u32, e: u32, _f: u32) -> Weight {
        Weight::from_ref_time(46_170_000_u64)
            // Standard Error: 0
            .saturating_add(Weight::from_ref_time(7_000_u64).saturating_mul(a as u64))
            // Standard Error: 4_000
            .saturating_add(Weight::from_ref_time(326_000_u64).saturating_mul(b as u64))
            // Standard Error: 1_000
            .saturating_add(Weight::from_ref_time(85_000_u64).saturating_mul(c as u64))
            // Standard Error: 4_000
            .saturating_add(Weight::from_ref_time(291_000_u64).saturating_mul(d as u64))
            // Standard Error: 1_000
            .saturating_add(Weight::from_ref_time(84_000_u64).saturating_mul(e as u64))
            .saturating_add(T::DbWeight::get().reads(4_u64))
            .saturating_add(T::DbWeight::get().writes(3_u64))
    }
    fn update_accumulator_ed25519(a: u32, b: u32, c: u32, d: u32, e: u32, f: u32) -> Weight {
        Weight::from_ref_time(37_112_000_u64)
            // Standard Error: 3_000
            .saturating_add(Weight::from_ref_time(13_000_u64).saturating_mul(a as u64))
            // Standard Error: 19_000
            .saturating_add(Weight::from_ref_time(247_000_u64).saturating_mul(b as u64))
            // Standard Error: 4_000
            .saturating_add(Weight::from_ref_time(90_000_u64).saturating_mul(c as u64))
            // Standard Error: 19_000
            .saturating_add(Weight::from_ref_time(326_000_u64).saturating_mul(d as u64))
            // Standard Error: 4_000
            .saturating_add(Weight::from_ref_time(98_000_u64).saturating_mul(e as u64))
            // Standard Error: 4_000
            .saturating_add(Weight::from_ref_time(30_000_u64).saturating_mul(f as u64))
            .saturating_add(T::DbWeight::get().reads(4_u64))
            .saturating_add(T::DbWeight::get().writes(3_u64))
    }
    fn update_accumulator_secp256k1(a: u32, b: u32, c: u32, d: u32, e: u32, _f: u32) -> Weight {
        Weight::from_ref_time(161_276_000_u64)
            // Standard Error: 1_000
            .saturating_add(Weight::from_ref_time(1_000_u64).saturating_mul(a as u64))
            // Standard Error: 7_000
            .saturating_add(Weight::from_ref_time(110_000_u64).saturating_mul(b as u64))
            // Standard Error: 1_000
            .saturating_add(Weight::from_ref_time(22_000_u64).saturating_mul(c as u64))
            // Standard Error: 7_000
            .saturating_add(Weight::from_ref_time(93_000_u64).saturating_mul(d as u64))
            // Standard Error: 1_000
            .saturating_add(Weight::from_ref_time(18_000_u64).saturating_mul(e as u64))
            .saturating_add(T::DbWeight::get().reads(4_u64))
            .saturating_add(T::DbWeight::get().writes(3_u64))
    }
    fn remove_accumulator_sr25519() -> Weight {
        Weight::from_ref_time(60_493_000_u64)
            .saturating_add(T::DbWeight::get().reads(4_u64))
            .saturating_add(T::DbWeight::get().writes(3_u64))
    }
    fn remove_accumulator_ed25519() -> Weight {
        Weight::from_ref_time(57_062_000_u64)
            .saturating_add(T::DbWeight::get().reads(4_u64))
            .saturating_add(T::DbWeight::get().writes(3_u64))
    }
    fn remove_accumulator_secp256k1() -> Weight {
        Weight::from_ref_time(167_644_000_u64)
            .saturating_add(T::DbWeight::get().reads(4_u64))
            .saturating_add(T::DbWeight::get().writes(3_u64))
    }
}

// For backwards compatibility and tests
impl WeightInfo for () {
    fn add_params_sr25519(b: u32, l: u32) -> Weight {
        Weight::from_ref_time(54_891_000_u64)
            // Standard Error: 0
            .saturating_add(Weight::from_ref_time(8_000_u64).saturating_mul(b as u64))
            // Standard Error: 0
            .saturating_add(Weight::from_ref_time(8_000_u64).saturating_mul(l as u64))
            .saturating_add(RocksDbWeight::get().reads(3_u64))
            .saturating_add(RocksDbWeight::get().writes(3_u64))
    }
    fn add_params_ed25519(b: u32, _l: u32) -> Weight {
        Weight::from_ref_time(55_802_000_u64)
            // Standard Error: 0
            .saturating_add(Weight::from_ref_time(4_000_u64).saturating_mul(b as u64))
            .saturating_add(RocksDbWeight::get().reads(3_u64))
            .saturating_add(RocksDbWeight::get().writes(3_u64))
    }
    fn add_params_secp256k1(b: u32, l: u32) -> Weight {
        Weight::from_ref_time(159_890_000_u64)
            // Standard Error: 0
            .saturating_add(Weight::from_ref_time(4_000_u64).saturating_mul(b as u64))
            // Standard Error: 1_000
            .saturating_add(Weight::from_ref_time(2_000_u64).saturating_mul(l as u64))
            .saturating_add(RocksDbWeight::get().reads(3_u64))
            .saturating_add(RocksDbWeight::get().writes(3_u64))
    }
    fn remove_params_sr25519() -> Weight {
        Weight::from_ref_time(58_306_000_u64)
            .saturating_add(RocksDbWeight::get().reads(3_u64))
            .saturating_add(RocksDbWeight::get().writes(2_u64))
    }
    fn remove_params_ed25519() -> Weight {
        Weight::from_ref_time(55_655_000_u64)
            .saturating_add(RocksDbWeight::get().reads(3_u64))
            .saturating_add(RocksDbWeight::get().writes(2_u64))
    }
    fn remove_params_secp256k1() -> Weight {
        Weight::from_ref_time(162_917_000_u64)
            .saturating_add(RocksDbWeight::get().reads(3_u64))
            .saturating_add(RocksDbWeight::get().writes(2_u64))
    }
    fn add_public_sr25519(b: u32) -> Weight {
        Weight::from_ref_time(61_674_000_u64)
            // Standard Error: 0
            .saturating_add(Weight::from_ref_time(5_000_u64).saturating_mul(b as u64))
            .saturating_add(RocksDbWeight::get().reads(4_u64))
            .saturating_add(RocksDbWeight::get().writes(3_u64))
    }
    fn add_public_ed25519(b: u32) -> Weight {
        Weight::from_ref_time(60_164_000_u64)
            // Standard Error: 0
            .saturating_add(Weight::from_ref_time(4_000_u64).saturating_mul(b as u64))
            .saturating_add(RocksDbWeight::get().reads(4_u64))
            .saturating_add(RocksDbWeight::get().writes(3_u64))
    }
    fn add_public_secp256k1(_b: u32) -> Weight {
        Weight::from_ref_time(167_138_000_u64)
            .saturating_add(RocksDbWeight::get().reads(4_u64))
            .saturating_add(RocksDbWeight::get().writes(3_u64))
    }
    fn remove_public_sr25519() -> Weight {
        Weight::from_ref_time(56_413_000_u64)
            .saturating_add(RocksDbWeight::get().reads(3_u64))
            .saturating_add(RocksDbWeight::get().writes(2_u64))
    }
    fn remove_public_ed25519() -> Weight {
        Weight::from_ref_time(55_915_000_u64)
            .saturating_add(RocksDbWeight::get().reads(3_u64))
            .saturating_add(RocksDbWeight::get().writes(2_u64))
    }
    fn remove_public_secp256k1() -> Weight {
        Weight::from_ref_time(164_392_000_u64)
            .saturating_add(RocksDbWeight::get().reads(3_u64))
            .saturating_add(RocksDbWeight::get().writes(2_u64))
    }
    fn add_accumulator_sr25519(b: u32) -> Weight {
        Weight::from_ref_time(63_558_000_u64)
            // Standard Error: 0
            .saturating_add(Weight::from_ref_time(9_000_u64).saturating_mul(b as u64))
            .saturating_add(RocksDbWeight::get().reads(5_u64))
            .saturating_add(RocksDbWeight::get().writes(3_u64))
    }
    fn add_accumulator_ed25519(b: u32) -> Weight {
        Weight::from_ref_time(61_650_000_u64)
            // Standard Error: 0
            .saturating_add(Weight::from_ref_time(3_000_u64).saturating_mul(b as u64))
            .saturating_add(RocksDbWeight::get().reads(5_u64))
            .saturating_add(RocksDbWeight::get().writes(3_u64))
    }
    fn add_accumulator_secp256k1(_b: u32) -> Weight {
        Weight::from_ref_time(167_711_000_u64)
            .saturating_add(RocksDbWeight::get().reads(5_u64))
            .saturating_add(RocksDbWeight::get().writes(3_u64))
    }
    fn update_accumulator_sr25519(a: u32, b: u32, c: u32, d: u32, e: u32, _f: u32) -> Weight {
        Weight::from_ref_time(46_170_000_u64)
            // Standard Error: 0
            .saturating_add(Weight::from_ref_time(7_000_u64).saturating_mul(a as u64))
            // Standard Error: 4_000
            .saturating_add(Weight::from_ref_time(326_000_u64).saturating_mul(b as u64))
            // Standard Error: 1_000
            .saturating_add(Weight::from_ref_time(85_000_u64).saturating_mul(c as u64))
            // Standard Error: 4_000
            .saturating_add(Weight::from_ref_time(291_000_u64).saturating_mul(d as u64))
            // Standard Error: 1_000
            .saturating_add(Weight::from_ref_time(84_000_u64).saturating_mul(e as u64))
            .saturating_add(RocksDbWeight::get().reads(4_u64))
            .saturating_add(RocksDbWeight::get().writes(3_u64))
    }
    fn update_accumulator_ed25519(a: u32, b: u32, c: u32, d: u32, e: u32, f: u32) -> Weight {
        Weight::from_ref_time(37_112_000_u64)
            // Standard Error: 3_000
            .saturating_add(Weight::from_ref_time(13_000_u64).saturating_mul(a as u64))
            // Standard Error: 19_000
            .saturating_add(Weight::from_ref_time(247_000_u64).saturating_mul(b as u64))
            // Standard Error: 4_000
            .saturating_add(Weight::from_ref_time(90_000_u64).saturating_mul(c as u64))
            // Standard Error: 19_000
            .saturating_add(Weight::from_ref_time(326_000_u64).saturating_mul(d as u64))
            // Standard Error: 4_000
            .saturating_add(Weight::from_ref_time(98_000_u64).saturating_mul(e as u64))
            // Standard Error: 4_000
            .saturating_add(Weight::from_ref_time(30_000_u64).saturating_mul(f as u64))
            .saturating_add(RocksDbWeight::get().reads(4_u64))
            .saturating_add(RocksDbWeight::get().writes(3_u64))
    }
    fn update_accumulator_secp256k1(a: u32, b: u32, c: u32, d: u32, e: u32, _f: u32) -> Weight {
        Weight::from_ref_time(161_276_000_u64)
            // Standard Error: 1_000
            .saturating_add(Weight::from_ref_time(1_000_u64).saturating_mul(a as u64))
            // Standard Error: 7_000
            .saturating_add(Weight::from_ref_time(110_000_u64).saturating_mul(b as u64))
            // Standard Error: 1_000
            .saturating_add(Weight::from_ref_time(22_000_u64).saturating_mul(c as u64))
            // Standard Error: 7_000
            .saturating_add(Weight::from_ref_time(93_000_u64).saturating_mul(d as u64))
            // Standard Error: 1_000
            .saturating_add(Weight::from_ref_time(18_000_u64).saturating_mul(e as u64))
            .saturating_add(RocksDbWeight::get().reads(4_u64))
            .saturating_add(RocksDbWeight::get().writes(3_u64))
    }
    fn remove_accumulator_sr25519() -> Weight {
        Weight::from_ref_time(60_493_000_u64)
            .saturating_add(RocksDbWeight::get().reads(4_u64))
            .saturating_add(RocksDbWeight::get().writes(3_u64))
    }
    fn remove_accumulator_ed25519() -> Weight {
        Weight::from_ref_time(57_062_000_u64)
            .saturating_add(RocksDbWeight::get().reads(4_u64))
            .saturating_add(RocksDbWeight::get().writes(3_u64))
    }
    fn remove_accumulator_secp256k1() -> Weight {
        Weight::from_ref_time(167_644_000_u64)
            .saturating_add(RocksDbWeight::get().reads(4_u64))
            .saturating_add(RocksDbWeight::get().writes(3_u64))
    }
}
