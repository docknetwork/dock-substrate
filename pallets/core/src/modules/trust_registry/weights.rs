//! Autogenerated weights for trust_registry
//!
//! THIS FILE WAS AUTO-GENERATED USING THE SUBSTRATE BENCHMARK CLI VERSION 4.0.0-dev
//! DATE: 2023-10-22, STEPS: `50`, REPEAT: 20, LOW RANGE: `[]`, HIGH RANGE: `[]`
//! EXECUTION: None, WASM-EXECUTION: Compiled, CHAIN: None, DB CACHE: 1024

// Executed Command:
// ./target/release/dock-node
// benchmark
// pallet
// --wasm-execution=compiled
// --pallet=trust_registry
// --extra
// --repeat=20
// --extrinsic=*
// --steps=50
// --template=node/module-weight-template.hbs
// --output=./pallets/core/src/modules/trust_registry/weights.rs

#![allow(unused_parens)]
#![allow(unused_imports)]

use frame_support::{
    traits::Get,
    weights::{constants::RocksDbWeight, Weight},
};
use sp_std::marker::PhantomData;

/// Weight functions needed for trust_registry.
pub trait WeightInfo {
    fn init_or_update_trust_registry_sr25519(n: u32) -> Weight;
    fn init_or_update_trust_registry_ed25519(n: u32) -> Weight;
    fn init_or_update_trust_registry_secp256k1(n: u32) -> Weight;
    fn add_schema_metadata_sr25519(i: u32, v: u32, s: u32) -> Weight;
    fn add_schema_metadata_ed25519(i: u32, v: u32, s: u32) -> Weight;
    fn add_schema_metadata_secp256k1(i: u32, v: u32, s: u32) -> Weight;
    fn update_schema_metadata_sr25519(i: u32, v: u32, s: u32) -> Weight;
    fn update_schema_metadata_ed25519(i: u32, v: u32, s: u32) -> Weight;
    fn update_schema_metadata_secp256k1(i: u32, v: u32, s: u32) -> Weight;
    fn update_delegated_issuers_sr25519(i: u32) -> Weight;
    fn update_delegated_issuers_ed25519(i: u32) -> Weight;
    fn update_delegated_issuers_secp256k1(i: u32) -> Weight;
    fn suspend_issuers_sr25519(i: u32) -> Weight;
    fn suspend_issuers_ed25519(i: u32) -> Weight;
    fn suspend_issuers_secp256k1(i: u32) -> Weight;
    fn unsuspend_issuers_sr25519(i: u32) -> Weight;
    fn unsuspend_issuers_ed25519(i: u32) -> Weight;
    fn unsuspend_issuers_secp256k1(i: u32) -> Weight;
}

/// Weights for trust_registry using the Substrate node and recommended hardware.
pub struct SubstrateWeight<T>(PhantomData<T>);
impl<T: frame_system::Config> WeightInfo for SubstrateWeight<T> {
    fn init_or_update_trust_registry_sr25519(n: u32) -> Weight {
        Weight::from_ref_time(67_521_000) // Standard Error: 9_000
            .saturating_add(Weight::from_ref_time(29_000).saturating_mul(n as u64))
            .saturating_add(T::DbWeight::get().reads(5))
            .saturating_add(T::DbWeight::get().writes(4))
    }
    fn init_or_update_trust_registry_ed25519(_n: u32) -> Weight {
        Weight::from_ref_time(67_974_000)
            .saturating_add(T::DbWeight::get().reads(5))
            .saturating_add(T::DbWeight::get().writes(4))
    }
    fn init_or_update_trust_registry_secp256k1(_n: u32) -> Weight {
        Weight::from_ref_time(160_766_000)
            .saturating_add(T::DbWeight::get().reads(5))
            .saturating_add(T::DbWeight::get().writes(4))
    }
    fn add_schema_metadata_sr25519(i: u32, v: u32, s: u32) -> Weight {
        Weight::from_ref_time(0) // Standard Error: 120_000
            .saturating_add(Weight::from_ref_time(54_765_000).saturating_mul(i as u64)) // Standard Error: 120_000
            .saturating_add(Weight::from_ref_time(4_719_000).saturating_mul(v as u64)) // Standard Error: 631_000
            .saturating_add(Weight::from_ref_time(288_634_000).saturating_mul(s as u64))
            .saturating_add(T::DbWeight::get().reads(3))
            .saturating_add(T::DbWeight::get().reads(1_u64.saturating_mul(i as u64)))
            .saturating_add(T::DbWeight::get().reads(1_u64.saturating_mul(v as u64)))
            .saturating_add(T::DbWeight::get().reads(1_u64.saturating_mul(s as u64)))
            .saturating_add(T::DbWeight::get().writes(2))
            .saturating_add(T::DbWeight::get().writes(1_u64.saturating_mul(i as u64)))
            .saturating_add(T::DbWeight::get().writes(1_u64.saturating_mul(v as u64)))
            .saturating_add(T::DbWeight::get().writes(2_u64.saturating_mul(s as u64)))
    }
    fn add_schema_metadata_ed25519(i: u32, v: u32, s: u32) -> Weight {
        Weight::from_ref_time(0) // Standard Error: 148_000
            .saturating_add(Weight::from_ref_time(47_419_000).saturating_mul(i as u64)) // Standard Error: 148_000
            .saturating_add(Weight::from_ref_time(345_000).saturating_mul(v as u64)) // Standard Error: 780_000
            .saturating_add(Weight::from_ref_time(242_555_000).saturating_mul(s as u64))
            .saturating_add(T::DbWeight::get().reads(3))
            .saturating_add(T::DbWeight::get().reads(1_u64.saturating_mul(i as u64)))
            .saturating_add(T::DbWeight::get().reads(1_u64.saturating_mul(v as u64)))
            .saturating_add(T::DbWeight::get().reads(1_u64.saturating_mul(s as u64)))
            .saturating_add(T::DbWeight::get().writes(2))
            .saturating_add(T::DbWeight::get().writes(1_u64.saturating_mul(i as u64)))
            .saturating_add(T::DbWeight::get().writes(1_u64.saturating_mul(v as u64)))
            .saturating_add(T::DbWeight::get().writes(2_u64.saturating_mul(s as u64)))
    }
    fn add_schema_metadata_secp256k1(i: u32, v: u32, s: u32) -> Weight {
        Weight::from_ref_time(0) // Standard Error: 85_000
            .saturating_add(Weight::from_ref_time(53_089_000).saturating_mul(i as u64)) // Standard Error: 85_000
            .saturating_add(Weight::from_ref_time(5_454_000).saturating_mul(v as u64)) // Standard Error: 446_000
            .saturating_add(Weight::from_ref_time(274_233_000).saturating_mul(s as u64))
            .saturating_add(T::DbWeight::get().reads(3))
            .saturating_add(T::DbWeight::get().reads(1_u64.saturating_mul(i as u64)))
            .saturating_add(T::DbWeight::get().reads(1_u64.saturating_mul(v as u64)))
            .saturating_add(T::DbWeight::get().reads(1_u64.saturating_mul(s as u64)))
            .saturating_add(T::DbWeight::get().writes(2))
            .saturating_add(T::DbWeight::get().writes(1_u64.saturating_mul(i as u64)))
            .saturating_add(T::DbWeight::get().writes(1_u64.saturating_mul(v as u64)))
            .saturating_add(T::DbWeight::get().writes(2_u64.saturating_mul(s as u64)))
    }
    fn update_schema_metadata_sr25519(i: u32, v: u32, s: u32) -> Weight {
        Weight::from_ref_time(487_656_000) // Standard Error: 98_000
            .saturating_add(Weight::from_ref_time(5_448_000).saturating_mul(v as u64)) // Standard Error: 513_000
            .saturating_add(Weight::from_ref_time(301_780_000).saturating_mul(s as u64))
            .saturating_add(T::DbWeight::get().reads(3))
            .saturating_add(T::DbWeight::get().reads(1_u64.saturating_mul(i as u64)))
            .saturating_add(T::DbWeight::get().reads(1_u64.saturating_mul(v as u64)))
            .saturating_add(T::DbWeight::get().reads(1_u64.saturating_mul(s as u64)))
            .saturating_add(T::DbWeight::get().writes(2))
            .saturating_add(T::DbWeight::get().writes(1_u64.saturating_mul(i as u64)))
            .saturating_add(T::DbWeight::get().writes(1_u64.saturating_mul(v as u64)))
            .saturating_add(T::DbWeight::get().writes(1_u64.saturating_mul(s as u64)))
    }
    fn update_schema_metadata_ed25519(i: u32, v: u32, s: u32) -> Weight {
        Weight::from_ref_time(754_704_000) // Standard Error: 196_000
            .saturating_add(Weight::from_ref_time(4_864_000).saturating_mul(v as u64)) // Standard Error: 1_027_000
            .saturating_add(Weight::from_ref_time(286_870_000).saturating_mul(s as u64))
            .saturating_add(T::DbWeight::get().reads(3))
            .saturating_add(T::DbWeight::get().reads(1_u64.saturating_mul(i as u64)))
            .saturating_add(T::DbWeight::get().reads(1_u64.saturating_mul(v as u64)))
            .saturating_add(T::DbWeight::get().reads(1_u64.saturating_mul(s as u64)))
            .saturating_add(T::DbWeight::get().writes(2))
            .saturating_add(T::DbWeight::get().writes(1_u64.saturating_mul(i as u64)))
            .saturating_add(T::DbWeight::get().writes(1_u64.saturating_mul(v as u64)))
            .saturating_add(T::DbWeight::get().writes(1_u64.saturating_mul(s as u64)))
    }
    fn update_schema_metadata_secp256k1(i: u32, v: u32, s: u32) -> Weight {
        Weight::from_ref_time(492_705_000) // Standard Error: 230_000
            .saturating_add(Weight::from_ref_time(8_280_000).saturating_mul(v as u64)) // Standard Error: 1_206_000
            .saturating_add(Weight::from_ref_time(298_766_000).saturating_mul(s as u64))
            .saturating_add(T::DbWeight::get().reads(3))
            .saturating_add(T::DbWeight::get().reads(1_u64.saturating_mul(i as u64)))
            .saturating_add(T::DbWeight::get().reads(1_u64.saturating_mul(v as u64)))
            .saturating_add(T::DbWeight::get().reads(1_u64.saturating_mul(s as u64)))
            .saturating_add(T::DbWeight::get().writes(2))
            .saturating_add(T::DbWeight::get().writes(1_u64.saturating_mul(i as u64)))
            .saturating_add(T::DbWeight::get().writes(1_u64.saturating_mul(v as u64)))
            .saturating_add(T::DbWeight::get().writes(1_u64.saturating_mul(s as u64)))
    }
    fn update_delegated_issuers_sr25519(i: u32) -> Weight {
        Weight::from_ref_time(69_735_000) // Standard Error: 20_000
            .saturating_add(Weight::from_ref_time(82_000).saturating_mul(i as u64))
            .saturating_add(T::DbWeight::get().reads(5))
            .saturating_add(T::DbWeight::get().writes(3))
    }
    fn update_delegated_issuers_ed25519(i: u32) -> Weight {
        Weight::from_ref_time(67_411_000) // Standard Error: 25_000
            .saturating_add(Weight::from_ref_time(285_000).saturating_mul(i as u64))
            .saturating_add(T::DbWeight::get().reads(5))
            .saturating_add(T::DbWeight::get().writes(3))
    }
    fn update_delegated_issuers_secp256k1(i: u32) -> Weight {
        Weight::from_ref_time(156_238_000) // Standard Error: 27_000
            .saturating_add(Weight::from_ref_time(440_000).saturating_mul(i as u64))
            .saturating_add(T::DbWeight::get().reads(5))
            .saturating_add(T::DbWeight::get().writes(3))
    }
    fn suspend_issuers_sr25519(i: u32) -> Weight {
        Weight::from_ref_time(68_092_000) // Standard Error: 18_000
            .saturating_add(Weight::from_ref_time(6_287_000).saturating_mul(i as u64))
            .saturating_add(T::DbWeight::get().reads(3))
            .saturating_add(T::DbWeight::get().reads(2_u64.saturating_mul(i as u64)))
            .saturating_add(T::DbWeight::get().writes(2))
            .saturating_add(T::DbWeight::get().writes(1_u64.saturating_mul(i as u64)))
    }
    fn suspend_issuers_ed25519(i: u32) -> Weight {
        Weight::from_ref_time(68_414_000) // Standard Error: 12_000
            .saturating_add(Weight::from_ref_time(6_145_000).saturating_mul(i as u64))
            .saturating_add(T::DbWeight::get().reads(3))
            .saturating_add(T::DbWeight::get().reads(2_u64.saturating_mul(i as u64)))
            .saturating_add(T::DbWeight::get().writes(2))
            .saturating_add(T::DbWeight::get().writes(1_u64.saturating_mul(i as u64)))
    }
    fn suspend_issuers_secp256k1(i: u32) -> Weight {
        Weight::from_ref_time(154_606_000) // Standard Error: 15_000
            .saturating_add(Weight::from_ref_time(6_280_000).saturating_mul(i as u64))
            .saturating_add(T::DbWeight::get().reads(3))
            .saturating_add(T::DbWeight::get().reads(2_u64.saturating_mul(i as u64)))
            .saturating_add(T::DbWeight::get().writes(2))
            .saturating_add(T::DbWeight::get().writes(1_u64.saturating_mul(i as u64)))
    }
    fn unsuspend_issuers_sr25519(i: u32) -> Weight {
        Weight::from_ref_time(66_790_000) // Standard Error: 16_000
            .saturating_add(Weight::from_ref_time(6_381_000).saturating_mul(i as u64))
            .saturating_add(T::DbWeight::get().reads(3))
            .saturating_add(T::DbWeight::get().reads(2_u64.saturating_mul(i as u64)))
            .saturating_add(T::DbWeight::get().writes(2))
            .saturating_add(T::DbWeight::get().writes(1_u64.saturating_mul(i as u64)))
    }
    fn unsuspend_issuers_ed25519(i: u32) -> Weight {
        Weight::from_ref_time(65_885_000) // Standard Error: 21_000
            .saturating_add(Weight::from_ref_time(6_341_000).saturating_mul(i as u64))
            .saturating_add(T::DbWeight::get().reads(3))
            .saturating_add(T::DbWeight::get().reads(2_u64.saturating_mul(i as u64)))
            .saturating_add(T::DbWeight::get().writes(2))
            .saturating_add(T::DbWeight::get().writes(1_u64.saturating_mul(i as u64)))
    }
    fn unsuspend_issuers_secp256k1(i: u32) -> Weight {
        Weight::from_ref_time(158_605_000) // Standard Error: 16_000
            .saturating_add(Weight::from_ref_time(6_207_000).saturating_mul(i as u64))
            .saturating_add(T::DbWeight::get().reads(3))
            .saturating_add(T::DbWeight::get().reads(2_u64.saturating_mul(i as u64)))
            .saturating_add(T::DbWeight::get().writes(2))
            .saturating_add(T::DbWeight::get().writes(1_u64.saturating_mul(i as u64)))
    }
}

// For backwards compatibility and tests
impl WeightInfo for () {
    fn init_or_update_trust_registry_sr25519(n: u32) -> Weight {
        Weight::from_ref_time(67_521_000) // Standard Error: 9_000
            .saturating_add(Weight::from_ref_time(29_000).saturating_mul(n as u64))
            .saturating_add(RocksDbWeight::get().reads(5))
            .saturating_add(RocksDbWeight::get().writes(4))
    }
    fn init_or_update_trust_registry_ed25519(_n: u32) -> Weight {
        Weight::from_ref_time(67_974_000)
            .saturating_add(RocksDbWeight::get().reads(5))
            .saturating_add(RocksDbWeight::get().writes(4))
    }
    fn init_or_update_trust_registry_secp256k1(_n: u32) -> Weight {
        Weight::from_ref_time(160_766_000)
            .saturating_add(RocksDbWeight::get().reads(5))
            .saturating_add(RocksDbWeight::get().writes(4))
    }
    fn add_schema_metadata_sr25519(i: u32, v: u32, s: u32) -> Weight {
        Weight::from_ref_time(0) // Standard Error: 120_000
            .saturating_add(Weight::from_ref_time(54_765_000).saturating_mul(i as u64)) // Standard Error: 120_000
            .saturating_add(Weight::from_ref_time(4_719_000).saturating_mul(v as u64)) // Standard Error: 631_000
            .saturating_add(Weight::from_ref_time(288_634_000).saturating_mul(s as u64))
            .saturating_add(RocksDbWeight::get().reads(3))
            .saturating_add(RocksDbWeight::get().reads(1_u64.saturating_mul(i as u64)))
            .saturating_add(RocksDbWeight::get().reads(1_u64.saturating_mul(v as u64)))
            .saturating_add(RocksDbWeight::get().reads(1_u64.saturating_mul(s as u64)))
            .saturating_add(RocksDbWeight::get().writes(2))
            .saturating_add(RocksDbWeight::get().writes(1_u64.saturating_mul(i as u64)))
            .saturating_add(RocksDbWeight::get().writes(1_u64.saturating_mul(v as u64)))
            .saturating_add(RocksDbWeight::get().writes(2_u64.saturating_mul(s as u64)))
    }
    fn add_schema_metadata_ed25519(i: u32, v: u32, s: u32) -> Weight {
        Weight::from_ref_time(0) // Standard Error: 148_000
            .saturating_add(Weight::from_ref_time(47_419_000).saturating_mul(i as u64)) // Standard Error: 148_000
            .saturating_add(Weight::from_ref_time(345_000).saturating_mul(v as u64)) // Standard Error: 780_000
            .saturating_add(Weight::from_ref_time(242_555_000).saturating_mul(s as u64))
            .saturating_add(RocksDbWeight::get().reads(3))
            .saturating_add(RocksDbWeight::get().reads(1_u64.saturating_mul(i as u64)))
            .saturating_add(RocksDbWeight::get().reads(1_u64.saturating_mul(v as u64)))
            .saturating_add(RocksDbWeight::get().reads(1_u64.saturating_mul(s as u64)))
            .saturating_add(RocksDbWeight::get().writes(2))
            .saturating_add(RocksDbWeight::get().writes(1_u64.saturating_mul(i as u64)))
            .saturating_add(RocksDbWeight::get().writes(1_u64.saturating_mul(v as u64)))
            .saturating_add(RocksDbWeight::get().writes(2_u64.saturating_mul(s as u64)))
    }
    fn add_schema_metadata_secp256k1(i: u32, v: u32, s: u32) -> Weight {
        Weight::from_ref_time(0) // Standard Error: 85_000
            .saturating_add(Weight::from_ref_time(53_089_000).saturating_mul(i as u64)) // Standard Error: 85_000
            .saturating_add(Weight::from_ref_time(5_454_000).saturating_mul(v as u64)) // Standard Error: 446_000
            .saturating_add(Weight::from_ref_time(274_233_000).saturating_mul(s as u64))
            .saturating_add(RocksDbWeight::get().reads(3))
            .saturating_add(RocksDbWeight::get().reads(1_u64.saturating_mul(i as u64)))
            .saturating_add(RocksDbWeight::get().reads(1_u64.saturating_mul(v as u64)))
            .saturating_add(RocksDbWeight::get().reads(1_u64.saturating_mul(s as u64)))
            .saturating_add(RocksDbWeight::get().writes(2))
            .saturating_add(RocksDbWeight::get().writes(1_u64.saturating_mul(i as u64)))
            .saturating_add(RocksDbWeight::get().writes(1_u64.saturating_mul(v as u64)))
            .saturating_add(RocksDbWeight::get().writes(2_u64.saturating_mul(s as u64)))
    }
    fn update_schema_metadata_sr25519(i: u32, v: u32, s: u32) -> Weight {
        Weight::from_ref_time(487_656_000) // Standard Error: 98_000
            .saturating_add(Weight::from_ref_time(5_448_000).saturating_mul(v as u64)) // Standard Error: 513_000
            .saturating_add(Weight::from_ref_time(301_780_000).saturating_mul(s as u64))
            .saturating_add(RocksDbWeight::get().reads(3))
            .saturating_add(RocksDbWeight::get().reads(1_u64.saturating_mul(i as u64)))
            .saturating_add(RocksDbWeight::get().reads(1_u64.saturating_mul(v as u64)))
            .saturating_add(RocksDbWeight::get().reads(1_u64.saturating_mul(s as u64)))
            .saturating_add(RocksDbWeight::get().writes(2))
            .saturating_add(RocksDbWeight::get().writes(1_u64.saturating_mul(i as u64)))
            .saturating_add(RocksDbWeight::get().writes(1_u64.saturating_mul(v as u64)))
            .saturating_add(RocksDbWeight::get().writes(1_u64.saturating_mul(s as u64)))
    }
    fn update_schema_metadata_ed25519(i: u32, v: u32, s: u32) -> Weight {
        Weight::from_ref_time(754_704_000) // Standard Error: 196_000
            .saturating_add(Weight::from_ref_time(4_864_000).saturating_mul(v as u64)) // Standard Error: 1_027_000
            .saturating_add(Weight::from_ref_time(286_870_000).saturating_mul(s as u64))
            .saturating_add(RocksDbWeight::get().reads(3))
            .saturating_add(RocksDbWeight::get().reads(1_u64.saturating_mul(i as u64)))
            .saturating_add(RocksDbWeight::get().reads(1_u64.saturating_mul(v as u64)))
            .saturating_add(RocksDbWeight::get().reads(1_u64.saturating_mul(s as u64)))
            .saturating_add(RocksDbWeight::get().writes(2))
            .saturating_add(RocksDbWeight::get().writes(1_u64.saturating_mul(i as u64)))
            .saturating_add(RocksDbWeight::get().writes(1_u64.saturating_mul(v as u64)))
            .saturating_add(RocksDbWeight::get().writes(1_u64.saturating_mul(s as u64)))
    }
    fn update_schema_metadata_secp256k1(i: u32, v: u32, s: u32) -> Weight {
        Weight::from_ref_time(492_705_000) // Standard Error: 230_000
            .saturating_add(Weight::from_ref_time(8_280_000).saturating_mul(v as u64)) // Standard Error: 1_206_000
            .saturating_add(Weight::from_ref_time(298_766_000).saturating_mul(s as u64))
            .saturating_add(RocksDbWeight::get().reads(3))
            .saturating_add(RocksDbWeight::get().reads(1_u64.saturating_mul(i as u64)))
            .saturating_add(RocksDbWeight::get().reads(1_u64.saturating_mul(v as u64)))
            .saturating_add(RocksDbWeight::get().reads(1_u64.saturating_mul(s as u64)))
            .saturating_add(RocksDbWeight::get().writes(2))
            .saturating_add(RocksDbWeight::get().writes(1_u64.saturating_mul(i as u64)))
            .saturating_add(RocksDbWeight::get().writes(1_u64.saturating_mul(v as u64)))
            .saturating_add(RocksDbWeight::get().writes(1_u64.saturating_mul(s as u64)))
    }
    fn update_delegated_issuers_sr25519(i: u32) -> Weight {
        Weight::from_ref_time(69_735_000) // Standard Error: 20_000
            .saturating_add(Weight::from_ref_time(82_000).saturating_mul(i as u64))
            .saturating_add(RocksDbWeight::get().reads(5))
            .saturating_add(RocksDbWeight::get().writes(3))
    }
    fn update_delegated_issuers_ed25519(i: u32) -> Weight {
        Weight::from_ref_time(67_411_000) // Standard Error: 25_000
            .saturating_add(Weight::from_ref_time(285_000).saturating_mul(i as u64))
            .saturating_add(RocksDbWeight::get().reads(5))
            .saturating_add(RocksDbWeight::get().writes(3))
    }
    fn update_delegated_issuers_secp256k1(i: u32) -> Weight {
        Weight::from_ref_time(156_238_000) // Standard Error: 27_000
            .saturating_add(Weight::from_ref_time(440_000).saturating_mul(i as u64))
            .saturating_add(RocksDbWeight::get().reads(5))
            .saturating_add(RocksDbWeight::get().writes(3))
    }
    fn suspend_issuers_sr25519(i: u32) -> Weight {
        Weight::from_ref_time(68_092_000) // Standard Error: 18_000
            .saturating_add(Weight::from_ref_time(6_287_000).saturating_mul(i as u64))
            .saturating_add(RocksDbWeight::get().reads(3))
            .saturating_add(RocksDbWeight::get().reads(2_u64.saturating_mul(i as u64)))
            .saturating_add(RocksDbWeight::get().writes(2))
            .saturating_add(RocksDbWeight::get().writes(1_u64.saturating_mul(i as u64)))
    }
    fn suspend_issuers_ed25519(i: u32) -> Weight {
        Weight::from_ref_time(68_414_000) // Standard Error: 12_000
            .saturating_add(Weight::from_ref_time(6_145_000).saturating_mul(i as u64))
            .saturating_add(RocksDbWeight::get().reads(3))
            .saturating_add(RocksDbWeight::get().reads(2_u64.saturating_mul(i as u64)))
            .saturating_add(RocksDbWeight::get().writes(2))
            .saturating_add(RocksDbWeight::get().writes(1_u64.saturating_mul(i as u64)))
    }
    fn suspend_issuers_secp256k1(i: u32) -> Weight {
        Weight::from_ref_time(154_606_000) // Standard Error: 15_000
            .saturating_add(Weight::from_ref_time(6_280_000).saturating_mul(i as u64))
            .saturating_add(RocksDbWeight::get().reads(3))
            .saturating_add(RocksDbWeight::get().reads(2_u64.saturating_mul(i as u64)))
            .saturating_add(RocksDbWeight::get().writes(2))
            .saturating_add(RocksDbWeight::get().writes(1_u64.saturating_mul(i as u64)))
    }
    fn unsuspend_issuers_sr25519(i: u32) -> Weight {
        Weight::from_ref_time(66_790_000) // Standard Error: 16_000
            .saturating_add(Weight::from_ref_time(6_381_000).saturating_mul(i as u64))
            .saturating_add(RocksDbWeight::get().reads(3))
            .saturating_add(RocksDbWeight::get().reads(2_u64.saturating_mul(i as u64)))
            .saturating_add(RocksDbWeight::get().writes(2))
            .saturating_add(RocksDbWeight::get().writes(1_u64.saturating_mul(i as u64)))
    }
    fn unsuspend_issuers_ed25519(i: u32) -> Weight {
        Weight::from_ref_time(65_885_000) // Standard Error: 21_000
            .saturating_add(Weight::from_ref_time(6_341_000).saturating_mul(i as u64))
            .saturating_add(RocksDbWeight::get().reads(3))
            .saturating_add(RocksDbWeight::get().reads(2_u64.saturating_mul(i as u64)))
            .saturating_add(RocksDbWeight::get().writes(2))
            .saturating_add(RocksDbWeight::get().writes(1_u64.saturating_mul(i as u64)))
    }
    fn unsuspend_issuers_secp256k1(i: u32) -> Weight {
        Weight::from_ref_time(158_605_000) // Standard Error: 16_000
            .saturating_add(Weight::from_ref_time(6_207_000).saturating_mul(i as u64))
            .saturating_add(RocksDbWeight::get().reads(3))
            .saturating_add(RocksDbWeight::get().reads(2_u64.saturating_mul(i as u64)))
            .saturating_add(RocksDbWeight::get().writes(2))
            .saturating_add(RocksDbWeight::get().writes(1_u64.saturating_mul(i as u64)))
    }
}