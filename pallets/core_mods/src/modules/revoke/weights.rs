//! Autogenerated weights for revoke
//!
//! THIS FILE WAS AUTO-GENERATED USING THE SUBSTRATE BENCHMARK CLI VERSION 3.0.0
//! DATE: 2022-08-01, STEPS: `[50, ]`, REPEAT: 20, LOW RANGE: `[]`, HIGH RANGE: `[]`
//! EXECUTION: Some(Native), WASM-EXECUTION: Interpreted, CHAIN: Some("mainnet"), DB CACHE: 128

// Executed Command:
// ./target/production/dock-node
// benchmark
// --execution=native
// --chain=mainnet
// --pallet=revoke
// --extra
// --extrinsic=*
// --repeat=20
// --steps=50
// --template=node/module-weight-template.hbs
// --output=./pallets/core_mods/src/modules/revoke/weights.rs

#![allow(unused_parens)]
#![allow(unused_imports)]

use frame_support::{
    traits::Get,
    weights::{constants::RocksDbWeight, Weight},
};
use sp_std::marker::PhantomData;

/// Weight functions needed for revoke.
pub trait WeightInfo {
    fn revoke_sr25519(r: u32) -> Weight;
    fn revoke_ed25519(r: u32) -> Weight;
    fn revoke_secp256k1(r: u32) -> Weight;
    fn unrevoke_sr25519(r: u32) -> Weight;
    fn unrevoke_ed25519(r: u32) -> Weight;
    fn unrevoke_secp256k1(r: u32) -> Weight;
    fn remove_registry_sr25519() -> Weight;
    fn remove_registry_ed25519() -> Weight;
    fn remove_registry_secp256k1() -> Weight;
    fn new_registry(c: u32) -> Weight;
}

/// Weights for revoke using the Substrate node and recommended hardware.
pub struct SubstrateWeight<T>(PhantomData<T>);
impl<T: frame_system::Config> WeightInfo for SubstrateWeight<T> {
    fn revoke_sr25519(r: u32) -> Weight {
        Weight::from_ref_time(51_886_000_u64)
            // Standard Error: 0
            .saturating_add(Weight::from_ref_time(744_000_u64).saturating_mul(r as u64))
            .saturating_add(T::DbWeight::get().reads(4_u64))
            .saturating_add(T::DbWeight::get().writes(3_u64))
            .saturating_add(T::DbWeight::get().writes(1_u64.saturating_mul(r as u64)))
    }
    fn revoke_ed25519(r: u32) -> Weight {
        Weight::from_ref_time(55_942_000_u64)
            // Standard Error: 1_000
            .saturating_add(Weight::from_ref_time(718_000_u64).saturating_mul(r as u64))
            .saturating_add(T::DbWeight::get().reads(4_u64))
            .saturating_add(T::DbWeight::get().writes(3_u64))
            .saturating_add(T::DbWeight::get().writes(1_u64.saturating_mul(r as u64)))
    }
    fn revoke_secp256k1(r: u32) -> Weight {
        Weight::from_ref_time(148_000_000_u64)
            // Standard Error: 1_000
            .saturating_add(Weight::from_ref_time(707_000_u64).saturating_mul(r as u64))
            .saturating_add(T::DbWeight::get().reads(4_u64))
            .saturating_add(T::DbWeight::get().writes(3_u64))
            .saturating_add(T::DbWeight::get().writes(1_u64.saturating_mul(r as u64)))
    }
    fn unrevoke_sr25519(r: u32) -> Weight {
        Weight::from_ref_time(67_695_000_u64)
            // Standard Error: 1_000
            .saturating_add(Weight::from_ref_time(741_000_u64).saturating_mul(r as u64))
            .saturating_add(T::DbWeight::get().reads(4_u64))
            .saturating_add(T::DbWeight::get().writes(3_u64))
            .saturating_add(T::DbWeight::get().writes(1_u64.saturating_mul(r as u64)))
    }
    fn unrevoke_ed25519(r: u32) -> Weight {
        Weight::from_ref_time(65_882_000_u64)
            // Standard Error: 3_000
            .saturating_add(Weight::from_ref_time(747_000_u64).saturating_mul(r as u64))
            .saturating_add(T::DbWeight::get().reads(4_u64))
            .saturating_add(T::DbWeight::get().writes(3_u64))
            .saturating_add(T::DbWeight::get().writes(1_u64.saturating_mul(r as u64)))
    }
    fn unrevoke_secp256k1(r: u32) -> Weight {
        Weight::from_ref_time(166_568_000_u64)
            // Standard Error: 1_000
            .saturating_add(Weight::from_ref_time(704_000_u64).saturating_mul(r as u64))
            .saturating_add(T::DbWeight::get().reads(4_u64))
            .saturating_add(T::DbWeight::get().writes(3_u64))
            .saturating_add(T::DbWeight::get().writes(1_u64.saturating_mul(r as u64)))
    }
    fn remove_registry_sr25519() -> Weight {
        Weight::from_ref_time(128_526_000_u64)
            .saturating_add(T::DbWeight::get().reads(4_u64))
            .saturating_add(T::DbWeight::get().writes(103_u64))
    }
    fn remove_registry_ed25519() -> Weight {
        Weight::from_ref_time(122_116_000_u64)
            .saturating_add(T::DbWeight::get().reads(4_u64))
            .saturating_add(T::DbWeight::get().writes(103_u64))
    }
    fn remove_registry_secp256k1() -> Weight {
        Weight::from_ref_time(230_576_000_u64)
            .saturating_add(T::DbWeight::get().reads(4_u64))
            .saturating_add(T::DbWeight::get().writes(103_u64))
    }
    fn new_registry(c: u32) -> Weight {
        Weight::from_ref_time(9_069_000_u64)
            // Standard Error: 1_000
            .saturating_add(Weight::from_ref_time(35_000_u64).saturating_mul(c as u64))
            .saturating_add(T::DbWeight::get().reads(2_u64))
            .saturating_add(T::DbWeight::get().writes(2_u64))
    }
}

// For backwards compatibility and tests
impl WeightInfo for () {
    fn revoke_sr25519(r: u32) -> Weight {
        Weight::from_ref_time(51_886_000_u64)
            // Standard Error: 0
            .saturating_add(Weight::from_ref_time(744_000_u64).saturating_mul(r as u64))
            .saturating_add(RocksDbWeight::get().reads(4_u64))
            .saturating_add(RocksDbWeight::get().writes(3_u64))
            .saturating_add(RocksDbWeight::get().writes(1_u64.saturating_mul(r as u64)))
    }
    fn revoke_ed25519(r: u32) -> Weight {
        Weight::from_ref_time(55_942_000_u64)
            // Standard Error: 1_000
            .saturating_add(Weight::from_ref_time(718_000_u64).saturating_mul(r as u64))
            .saturating_add(RocksDbWeight::get().reads(4_u64))
            .saturating_add(RocksDbWeight::get().writes(3_u64))
            .saturating_add(RocksDbWeight::get().writes(1_u64.saturating_mul(r as u64)))
    }
    fn revoke_secp256k1(r: u32) -> Weight {
        Weight::from_ref_time(148_000_000_u64)
            // Standard Error: 1_000
            .saturating_add(Weight::from_ref_time(707_000_u64).saturating_mul(r as u64))
            .saturating_add(RocksDbWeight::get().reads(4_u64))
            .saturating_add(RocksDbWeight::get().writes(3_u64))
            .saturating_add(RocksDbWeight::get().writes(1_u64.saturating_mul(r as u64)))
    }
    fn unrevoke_sr25519(r: u32) -> Weight {
        Weight::from_ref_time(67_695_000_u64)
            // Standard Error: 1_000
            .saturating_add(Weight::from_ref_time(741_000_u64).saturating_mul(r as u64))
            .saturating_add(RocksDbWeight::get().reads(4_u64))
            .saturating_add(RocksDbWeight::get().writes(3_u64))
            .saturating_add(RocksDbWeight::get().writes(1_u64.saturating_mul(r as u64)))
    }
    fn unrevoke_ed25519(r: u32) -> Weight {
        Weight::from_ref_time(65_882_000_u64)
            // Standard Error: 3_000
            .saturating_add(Weight::from_ref_time(747_000_u64).saturating_mul(r as u64))
            .saturating_add(RocksDbWeight::get().reads(4_u64))
            .saturating_add(RocksDbWeight::get().writes(3_u64))
            .saturating_add(RocksDbWeight::get().writes(1_u64.saturating_mul(r as u64)))
    }
    fn unrevoke_secp256k1(r: u32) -> Weight {
        Weight::from_ref_time(166_568_000_u64)
            // Standard Error: 1_000
            .saturating_add(Weight::from_ref_time(704_000_u64).saturating_mul(r as u64))
            .saturating_add(RocksDbWeight::get().reads(4_u64))
            .saturating_add(RocksDbWeight::get().writes(3_u64))
            .saturating_add(RocksDbWeight::get().writes(1_u64.saturating_mul(r as u64)))
    }
    fn remove_registry_sr25519() -> Weight {
        Weight::from_ref_time(128_526_000_u64)
            .saturating_add(RocksDbWeight::get().reads(4_u64))
            .saturating_add(RocksDbWeight::get().writes(103_u64))
    }
    fn remove_registry_ed25519() -> Weight {
        Weight::from_ref_time(122_116_000_u64)
            .saturating_add(RocksDbWeight::get().reads(4_u64))
            .saturating_add(RocksDbWeight::get().writes(103_u64))
    }
    fn remove_registry_secp256k1() -> Weight {
        Weight::from_ref_time(230_576_000_u64)
            .saturating_add(RocksDbWeight::get().reads(4_u64))
            .saturating_add(RocksDbWeight::get().writes(103_u64))
    }
    fn new_registry(c: u32) -> Weight {
        Weight::from_ref_time(9_069_000_u64)
            // Standard Error: 1_000
            .saturating_add(Weight::from_ref_time(35_000_u64).saturating_mul(c as u64))
            .saturating_add(RocksDbWeight::get().reads(2_u64))
            .saturating_add(RocksDbWeight::get().writes(2_u64))
    }
}
