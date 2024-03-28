//! Autogenerated weights for trust_registry
//!
//! THIS FILE WAS AUTO-GENERATED USING THE SUBSTRATE BENCHMARK CLI VERSION 4.0.0-dev
//! DATE: 2024-03-27, STEPS: `50`, REPEAT: 20, LOW RANGE: `[]`, HIGH RANGE: `[]`
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
// --template=node/module-weight-template-without-system.hbs
// --output=./pallets/core/src/modules/trust_registry/weights.rs

#![allow(unused_parens)]
#![allow(unused_imports)]

use frame_support::{
    traits::Get,
    weights::{constants::RocksDbWeight, RuntimeDbWeight, Weight},
};
use sp_std::marker::PhantomData;

/// Weight functions needed for trust_registry.
pub trait WeightInfo {
    fn init_or_update_trust_registry_sr25519(n: u32, g: u32) -> Weight;
    fn init_or_update_trust_registry_ed25519(n: u32, g: u32) -> Weight;
    fn init_or_update_trust_registry_secp256k1(n: u32, g: u32) -> Weight;
    fn set_schemas_metadata_sr25519(i: u32, v: u32, s: u32) -> Weight;
    fn set_schemas_metadata_ed25519(i: u32, v: u32, s: u32) -> Weight;
    fn set_schemas_metadata_secp256k1(i: u32, v: u32, s: u32) -> Weight;
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
pub struct SubstrateWeight<W>(PhantomData<W>);
impl<W: Get<RuntimeDbWeight>> WeightInfo for SubstrateWeight<W> {
    fn init_or_update_trust_registry_sr25519(_n: u32, g: u32) -> Weight {
        Weight::from_ref_time(60_019_000) // Standard Error: 0
            .saturating_add(Weight::from_ref_time(2_000).saturating_mul(g as u64))
            .saturating_add(W::get().reads(5))
            .saturating_add(W::get().writes(4))
    }
    fn init_or_update_trust_registry_ed25519(_n: u32, g: u32) -> Weight {
        Weight::from_ref_time(58_501_000) // Standard Error: 0
            .saturating_add(Weight::from_ref_time(2_000).saturating_mul(g as u64))
            .saturating_add(W::get().reads(5))
            .saturating_add(W::get().writes(4))
    }
    fn init_or_update_trust_registry_secp256k1(n: u32, g: u32) -> Weight {
        Weight::from_ref_time(150_833_000) // Standard Error: 6_000
            .saturating_add(Weight::from_ref_time(9_000).saturating_mul(n as u64)) // Standard Error: 1_000
            .saturating_add(Weight::from_ref_time(4_000).saturating_mul(g as u64))
            .saturating_add(W::get().reads(5))
            .saturating_add(W::get().writes(4))
    }
    fn set_schemas_metadata_sr25519(i: u32, v: u32, s: u32) -> Weight {
        Weight::from_ref_time(0) // Standard Error: 103_000
            .saturating_add(Weight::from_ref_time(7_131_000).saturating_mul(i as u64)) // Standard Error: 103_000
            .saturating_add(Weight::from_ref_time(8_216_000).saturating_mul(v as u64)) // Standard Error: 540_000
            .saturating_add(Weight::from_ref_time(288_014_000).saturating_mul(s as u64))
            .saturating_add(W::get().reads(3))
            .saturating_add(W::get().reads((3 as u64).saturating_mul(i as u64)))
            .saturating_add(W::get().reads((2 as u64).saturating_mul(v as u64)))
            .saturating_add(W::get().reads((1 as u64).saturating_mul(s as u64)))
            .saturating_add(W::get().writes(1))
            .saturating_add(W::get().writes((2 as u64).saturating_mul(i as u64)))
            .saturating_add(W::get().writes((2 as u64).saturating_mul(v as u64)))
            .saturating_add(W::get().writes((1 as u64).saturating_mul(s as u64)))
    }
    fn set_schemas_metadata_ed25519(i: u32, v: u32, s: u32) -> Weight {
        Weight::from_ref_time(75_911_000) // Standard Error: 53_000
            .saturating_add(Weight::from_ref_time(1_122_000).saturating_mul(i as u64)) // Standard Error: 53_000
            .saturating_add(Weight::from_ref_time(6_590_000).saturating_mul(v as u64)) // Standard Error: 281_000
            .saturating_add(Weight::from_ref_time(254_849_000).saturating_mul(s as u64))
            .saturating_add(W::get().reads(3))
            .saturating_add(W::get().reads((3 as u64).saturating_mul(i as u64)))
            .saturating_add(W::get().reads((2 as u64).saturating_mul(v as u64)))
            .saturating_add(W::get().reads((1 as u64).saturating_mul(s as u64)))
            .saturating_add(W::get().writes(1))
            .saturating_add(W::get().writes((2 as u64).saturating_mul(i as u64)))
            .saturating_add(W::get().writes((2 as u64).saturating_mul(v as u64)))
            .saturating_add(W::get().writes((1 as u64).saturating_mul(s as u64)))
    }
    fn set_schemas_metadata_secp256k1(i: u32, v: u32, s: u32) -> Weight {
        Weight::from_ref_time(0) // Standard Error: 57_000
            .saturating_add(Weight::from_ref_time(4_984_000).saturating_mul(i as u64)) // Standard Error: 57_000
            .saturating_add(Weight::from_ref_time(7_288_000).saturating_mul(v as u64)) // Standard Error: 302_000
            .saturating_add(Weight::from_ref_time(274_224_000).saturating_mul(s as u64))
            .saturating_add(W::get().reads(3))
            .saturating_add(W::get().reads((3 as u64).saturating_mul(i as u64)))
            .saturating_add(W::get().reads((2 as u64).saturating_mul(v as u64)))
            .saturating_add(W::get().reads((1 as u64).saturating_mul(s as u64)))
            .saturating_add(W::get().writes(1))
            .saturating_add(W::get().writes((2 as u64).saturating_mul(i as u64)))
            .saturating_add(W::get().writes((2 as u64).saturating_mul(v as u64)))
            .saturating_add(W::get().writes((1 as u64).saturating_mul(s as u64)))
    }
    fn update_delegated_issuers_sr25519(i: u32) -> Weight {
        Weight::from_ref_time(60_856_000) // Standard Error: 9_000
            .saturating_add(Weight::from_ref_time(2_102_000).saturating_mul(i as u64))
            .saturating_add(W::get().reads(4))
            .saturating_add(W::get().reads((1 as u64).saturating_mul(i as u64)))
            .saturating_add(W::get().writes(2))
            .saturating_add(W::get().writes((1 as u64).saturating_mul(i as u64)))
    }
    fn update_delegated_issuers_ed25519(i: u32) -> Weight {
        Weight::from_ref_time(59_882_000) // Standard Error: 7_000
            .saturating_add(Weight::from_ref_time(2_035_000).saturating_mul(i as u64))
            .saturating_add(W::get().reads(4))
            .saturating_add(W::get().reads((1 as u64).saturating_mul(i as u64)))
            .saturating_add(W::get().writes(2))
            .saturating_add(W::get().writes((1 as u64).saturating_mul(i as u64)))
    }
    fn update_delegated_issuers_secp256k1(i: u32) -> Weight {
        Weight::from_ref_time(151_818_000) // Standard Error: 14_000
            .saturating_add(Weight::from_ref_time(2_047_000).saturating_mul(i as u64))
            .saturating_add(W::get().reads(4))
            .saturating_add(W::get().reads((1 as u64).saturating_mul(i as u64)))
            .saturating_add(W::get().writes(2))
            .saturating_add(W::get().writes((1 as u64).saturating_mul(i as u64)))
    }
    fn suspend_issuers_sr25519(i: u32) -> Weight {
        Weight::from_ref_time(57_310_000) // Standard Error: 5_000
            .saturating_add(Weight::from_ref_time(4_892_000).saturating_mul(i as u64))
            .saturating_add(W::get().reads(3))
            .saturating_add(W::get().reads((2 as u64).saturating_mul(i as u64)))
            .saturating_add(W::get().writes(1))
            .saturating_add(W::get().writes((1 as u64).saturating_mul(i as u64)))
    }
    fn suspend_issuers_ed25519(i: u32) -> Weight {
        Weight::from_ref_time(56_366_000) // Standard Error: 5_000
            .saturating_add(Weight::from_ref_time(4_851_000).saturating_mul(i as u64))
            .saturating_add(W::get().reads(3))
            .saturating_add(W::get().reads((2 as u64).saturating_mul(i as u64)))
            .saturating_add(W::get().writes(1))
            .saturating_add(W::get().writes((1 as u64).saturating_mul(i as u64)))
    }
    fn suspend_issuers_secp256k1(i: u32) -> Weight {
        Weight::from_ref_time(148_698_000) // Standard Error: 7_000
            .saturating_add(Weight::from_ref_time(4_876_000).saturating_mul(i as u64))
            .saturating_add(W::get().reads(3))
            .saturating_add(W::get().reads((2 as u64).saturating_mul(i as u64)))
            .saturating_add(W::get().writes(1))
            .saturating_add(W::get().writes((1 as u64).saturating_mul(i as u64)))
    }
    fn unsuspend_issuers_sr25519(i: u32) -> Weight {
        Weight::from_ref_time(57_300_000) // Standard Error: 6_000
            .saturating_add(Weight::from_ref_time(6_151_000).saturating_mul(i as u64))
            .saturating_add(W::get().reads(3))
            .saturating_add(W::get().reads((2 as u64).saturating_mul(i as u64)))
            .saturating_add(W::get().writes(1))
            .saturating_add(W::get().writes((1 as u64).saturating_mul(i as u64)))
    }
    fn unsuspend_issuers_ed25519(i: u32) -> Weight {
        Weight::from_ref_time(55_859_000) // Standard Error: 6_000
            .saturating_add(Weight::from_ref_time(6_120_000).saturating_mul(i as u64))
            .saturating_add(W::get().reads(3))
            .saturating_add(W::get().reads((2 as u64).saturating_mul(i as u64)))
            .saturating_add(W::get().writes(1))
            .saturating_add(W::get().writes((1 as u64).saturating_mul(i as u64)))
    }
    fn unsuspend_issuers_secp256k1(i: u32) -> Weight {
        Weight::from_ref_time(148_200_000) // Standard Error: 9_000
            .saturating_add(Weight::from_ref_time(6_154_000).saturating_mul(i as u64))
            .saturating_add(W::get().reads(3))
            .saturating_add(W::get().reads((2 as u64).saturating_mul(i as u64)))
            .saturating_add(W::get().writes(1))
            .saturating_add(W::get().writes((1 as u64).saturating_mul(i as u64)))
    }
}

// For backwards compatibility and tests
impl WeightInfo for () {
    fn init_or_update_trust_registry_sr25519(_n: u32, g: u32) -> Weight {
        Weight::from_ref_time(60_019_000) // Standard Error: 0
            .saturating_add(Weight::from_ref_time(2_000).saturating_mul(g as u64))
            .saturating_add(RocksDbWeight::get().reads(5))
            .saturating_add(RocksDbWeight::get().writes(4))
    }
    fn init_or_update_trust_registry_ed25519(_n: u32, g: u32) -> Weight {
        Weight::from_ref_time(58_501_000) // Standard Error: 0
            .saturating_add(Weight::from_ref_time(2_000).saturating_mul(g as u64))
            .saturating_add(RocksDbWeight::get().reads(5))
            .saturating_add(RocksDbWeight::get().writes(4))
    }
    fn init_or_update_trust_registry_secp256k1(n: u32, g: u32) -> Weight {
        Weight::from_ref_time(150_833_000) // Standard Error: 6_000
            .saturating_add(Weight::from_ref_time(9_000).saturating_mul(n as u64)) // Standard Error: 1_000
            .saturating_add(Weight::from_ref_time(4_000).saturating_mul(g as u64))
            .saturating_add(RocksDbWeight::get().reads(5))
            .saturating_add(RocksDbWeight::get().writes(4))
    }
    fn set_schemas_metadata_sr25519(i: u32, v: u32, s: u32) -> Weight {
        Weight::from_ref_time(0) // Standard Error: 103_000
            .saturating_add(Weight::from_ref_time(7_131_000).saturating_mul(i as u64)) // Standard Error: 103_000
            .saturating_add(Weight::from_ref_time(8_216_000).saturating_mul(v as u64)) // Standard Error: 540_000
            .saturating_add(Weight::from_ref_time(288_014_000).saturating_mul(s as u64))
            .saturating_add(RocksDbWeight::get().reads(3))
            .saturating_add(RocksDbWeight::get().reads((3 as u64).saturating_mul(i as u64)))
            .saturating_add(RocksDbWeight::get().reads((2 as u64).saturating_mul(v as u64)))
            .saturating_add(RocksDbWeight::get().reads((1 as u64).saturating_mul(s as u64)))
            .saturating_add(RocksDbWeight::get().writes(1))
            .saturating_add(RocksDbWeight::get().writes((2 as u64).saturating_mul(i as u64)))
            .saturating_add(RocksDbWeight::get().writes((2 as u64).saturating_mul(v as u64)))
            .saturating_add(RocksDbWeight::get().writes((1 as u64).saturating_mul(s as u64)))
    }
    fn set_schemas_metadata_ed25519(i: u32, v: u32, s: u32) -> Weight {
        Weight::from_ref_time(75_911_000) // Standard Error: 53_000
            .saturating_add(Weight::from_ref_time(1_122_000).saturating_mul(i as u64)) // Standard Error: 53_000
            .saturating_add(Weight::from_ref_time(6_590_000).saturating_mul(v as u64)) // Standard Error: 281_000
            .saturating_add(Weight::from_ref_time(254_849_000).saturating_mul(s as u64))
            .saturating_add(RocksDbWeight::get().reads(3))
            .saturating_add(RocksDbWeight::get().reads((3 as u64).saturating_mul(i as u64)))
            .saturating_add(RocksDbWeight::get().reads((2 as u64).saturating_mul(v as u64)))
            .saturating_add(RocksDbWeight::get().reads((1 as u64).saturating_mul(s as u64)))
            .saturating_add(RocksDbWeight::get().writes(1))
            .saturating_add(RocksDbWeight::get().writes((2 as u64).saturating_mul(i as u64)))
            .saturating_add(RocksDbWeight::get().writes((2 as u64).saturating_mul(v as u64)))
            .saturating_add(RocksDbWeight::get().writes((1 as u64).saturating_mul(s as u64)))
    }
    fn set_schemas_metadata_secp256k1(i: u32, v: u32, s: u32) -> Weight {
        Weight::from_ref_time(0) // Standard Error: 57_000
            .saturating_add(Weight::from_ref_time(4_984_000).saturating_mul(i as u64)) // Standard Error: 57_000
            .saturating_add(Weight::from_ref_time(7_288_000).saturating_mul(v as u64)) // Standard Error: 302_000
            .saturating_add(Weight::from_ref_time(274_224_000).saturating_mul(s as u64))
            .saturating_add(RocksDbWeight::get().reads(3))
            .saturating_add(RocksDbWeight::get().reads((3 as u64).saturating_mul(i as u64)))
            .saturating_add(RocksDbWeight::get().reads((2 as u64).saturating_mul(v as u64)))
            .saturating_add(RocksDbWeight::get().reads((1 as u64).saturating_mul(s as u64)))
            .saturating_add(RocksDbWeight::get().writes(1))
            .saturating_add(RocksDbWeight::get().writes((2 as u64).saturating_mul(i as u64)))
            .saturating_add(RocksDbWeight::get().writes((2 as u64).saturating_mul(v as u64)))
            .saturating_add(RocksDbWeight::get().writes((1 as u64).saturating_mul(s as u64)))
    }
    fn update_delegated_issuers_sr25519(i: u32) -> Weight {
        Weight::from_ref_time(60_856_000) // Standard Error: 9_000
            .saturating_add(Weight::from_ref_time(2_102_000).saturating_mul(i as u64))
            .saturating_add(RocksDbWeight::get().reads(4))
            .saturating_add(RocksDbWeight::get().reads((1 as u64).saturating_mul(i as u64)))
            .saturating_add(RocksDbWeight::get().writes(2))
            .saturating_add(RocksDbWeight::get().writes((1 as u64).saturating_mul(i as u64)))
    }
    fn update_delegated_issuers_ed25519(i: u32) -> Weight {
        Weight::from_ref_time(59_882_000) // Standard Error: 7_000
            .saturating_add(Weight::from_ref_time(2_035_000).saturating_mul(i as u64))
            .saturating_add(RocksDbWeight::get().reads(4))
            .saturating_add(RocksDbWeight::get().reads((1 as u64).saturating_mul(i as u64)))
            .saturating_add(RocksDbWeight::get().writes(2))
            .saturating_add(RocksDbWeight::get().writes((1 as u64).saturating_mul(i as u64)))
    }
    fn update_delegated_issuers_secp256k1(i: u32) -> Weight {
        Weight::from_ref_time(151_818_000) // Standard Error: 14_000
            .saturating_add(Weight::from_ref_time(2_047_000).saturating_mul(i as u64))
            .saturating_add(RocksDbWeight::get().reads(4))
            .saturating_add(RocksDbWeight::get().reads((1 as u64).saturating_mul(i as u64)))
            .saturating_add(RocksDbWeight::get().writes(2))
            .saturating_add(RocksDbWeight::get().writes((1 as u64).saturating_mul(i as u64)))
    }
    fn suspend_issuers_sr25519(i: u32) -> Weight {
        Weight::from_ref_time(57_310_000) // Standard Error: 5_000
            .saturating_add(Weight::from_ref_time(4_892_000).saturating_mul(i as u64))
            .saturating_add(RocksDbWeight::get().reads(3))
            .saturating_add(RocksDbWeight::get().reads((2 as u64).saturating_mul(i as u64)))
            .saturating_add(RocksDbWeight::get().writes(1))
            .saturating_add(RocksDbWeight::get().writes((1 as u64).saturating_mul(i as u64)))
    }
    fn suspend_issuers_ed25519(i: u32) -> Weight {
        Weight::from_ref_time(56_366_000) // Standard Error: 5_000
            .saturating_add(Weight::from_ref_time(4_851_000).saturating_mul(i as u64))
            .saturating_add(RocksDbWeight::get().reads(3))
            .saturating_add(RocksDbWeight::get().reads((2 as u64).saturating_mul(i as u64)))
            .saturating_add(RocksDbWeight::get().writes(1))
            .saturating_add(RocksDbWeight::get().writes((1 as u64).saturating_mul(i as u64)))
    }
    fn suspend_issuers_secp256k1(i: u32) -> Weight {
        Weight::from_ref_time(148_698_000) // Standard Error: 7_000
            .saturating_add(Weight::from_ref_time(4_876_000).saturating_mul(i as u64))
            .saturating_add(RocksDbWeight::get().reads(3))
            .saturating_add(RocksDbWeight::get().reads((2 as u64).saturating_mul(i as u64)))
            .saturating_add(RocksDbWeight::get().writes(1))
            .saturating_add(RocksDbWeight::get().writes((1 as u64).saturating_mul(i as u64)))
    }
    fn unsuspend_issuers_sr25519(i: u32) -> Weight {
        Weight::from_ref_time(57_300_000) // Standard Error: 6_000
            .saturating_add(Weight::from_ref_time(6_151_000).saturating_mul(i as u64))
            .saturating_add(RocksDbWeight::get().reads(3))
            .saturating_add(RocksDbWeight::get().reads((2 as u64).saturating_mul(i as u64)))
            .saturating_add(RocksDbWeight::get().writes(1))
            .saturating_add(RocksDbWeight::get().writes((1 as u64).saturating_mul(i as u64)))
    }
    fn unsuspend_issuers_ed25519(i: u32) -> Weight {
        Weight::from_ref_time(55_859_000) // Standard Error: 6_000
            .saturating_add(Weight::from_ref_time(6_120_000).saturating_mul(i as u64))
            .saturating_add(RocksDbWeight::get().reads(3))
            .saturating_add(RocksDbWeight::get().reads((2 as u64).saturating_mul(i as u64)))
            .saturating_add(RocksDbWeight::get().writes(1))
            .saturating_add(RocksDbWeight::get().writes((1 as u64).saturating_mul(i as u64)))
    }
    fn unsuspend_issuers_secp256k1(i: u32) -> Weight {
        Weight::from_ref_time(148_200_000) // Standard Error: 9_000
            .saturating_add(Weight::from_ref_time(6_154_000).saturating_mul(i as u64))
            .saturating_add(RocksDbWeight::get().reads(3))
            .saturating_add(RocksDbWeight::get().reads((2 as u64).saturating_mul(i as u64)))
            .saturating_add(RocksDbWeight::get().writes(1))
            .saturating_add(RocksDbWeight::get().writes((1 as u64).saturating_mul(i as u64)))
    }
}
