#![cfg_attr(not(feature = "std"), no_std)]

use support::{decl_module, decl_event, decl_storage, StorageValue};
use system::ensure_signed;
use support::dispatch::DispatchResultWithPostInfo;
use sp_std::prelude::*;


// // more imports
// use codec::{Decode, Encode};
// use frame_support::{
//     debug::{debug, error, RuntimeLogger},
//     decl_error, decl_event, decl_module, decl_storage, dispatch, ensure, fail, runtime_print,
//     sp_runtime::{
//         print,
//         traits::{AccountIdConversion, CheckedSub, OpaqueKeys, Saturating, StaticLookup, Zero},
//         ModuleId, SaturatedConversion,
//     },
//     traits::{
//         BalanceStatus::Reserved, Currency, ExistenceRequirement::AllowDeath, Get, Imbalance,
//         OnUnbalanced, ReservableCurrency,
//     },
//     weights::{Pays, Weight},
// };

// use frame_system::{self as system, ensure_root, RawOrigin};
// use sp_std::prelude::Vec;

// use support::{dispatch::Result, StorageValue};
// use system::ensure_signed;

/// Handler for updating the DockUsdRate
// #[impl_for_tuples(30)]
pub trait HandlerUpdateDockUsdRate {
    // fn update_dock_usd_rate(who: &AccountId);
	/// Handler for updating the DockUsdRate
	fn update_dock_usd_rate();
}

// Workaround for https://github.com/rust-lang/rust/issues/26925 . Remove when sorted.
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct Test;

// parameter_types! {
//     // pub const InitialDockUsdRate: f64 = 0.02251112;
//     // pub const InitialUpdateEveryNBlocks: u8 = 10;
// }
// The pallet's configuration trait
pub trait Trait: system::Trait { // TODO add necessary pallet traits + did::Trait
    // the Event used here must impl these traits
    type Event: From<Event<Self>> + Into<<Self as system::Trait>::Event>;
    // type BlockNumber: <Self as frame_system::Trait>::BlockNumber;
    // type InitialDockUsdRate = InitialDockUsdRate;
    // type BaseCallFilter = BaseFilter; // TODO lives in runtime.


    /// The dispatchable gets called. It is possible to use another type here, but
    /// it's expected that your runtime::Call will be used.
    /// a dispatchable is a lazy Call. Gets executed via its `dispatch()` method
    type Call: Parameter + UnfilteredDispatchable<Origin = Self::Origin> + GetDispatchInfo;

	/// Handler for updating the DockUsdRate. Configurable.
	// type HandlerUpdateDockUsdRate: HandlerUpdateDockUsdRate<Self::AccountId> = ();
	type HandlerUpdateDockUsdRate: HandlerUpdateDockUsdRate = ();
}
// TODO
// Test that a filtered call can be dispatched.
// pub struct BaseFilter;
// impl Filter<Call> for BaseFilter {
//     fn filter(call: &Call) -> bool {
//         // TODO make it match:
//         //     DID write, update, remove (depending on key type)
//         //     revoke/unrevoke (depending on number of items), 
//         //     blob (depending on byte size).
//         !matches!(
//             call,
//             &Call::Balances(pallet_balances::Call::set_balance(..))
//         )
//         match call {
//             &Call::SOMETHING(pallet_did)
//         }
//     }
// }

decl_event! {
    // pub enum Event<T> where
    // AccountId = <T as system::Trait>::AccountId, // TODO I probably don't need this trait bound ?
    pub enum Event
    {
        // on set_dock_usd_rate executed
        DockUsdRateSet(f64),
        // on root_set_update_freq executed
        UpdateFreqSet(u8),
    }
}

// impl Default for Membership {
//     fn default() -> Self {
//         Membership {
//             members: BTreeSet::new(),
//             vote_requirement: 1,
//         }
//     }
// }

// pub type FiatPrice = u64;
// pub trait FiatPricing {
//     fn DidCall() -> FiatPrice;
//     fn BlobCall() -> FiatPrice;
// }

/// An index to a block.
pub type BlockNumber = u32;

pub const INIT_DOCK_USD_RATE: f64 = 0.02251112;
pub const INIT_UPDATE_EVERY_N_BLOCKS: u8 = 10;
decl_storage!(
    trait Store for Module<T: Trait> as FiatFilterStorage {
        /// price of one DOCK in USD
        pub DockUsdRate get(fn dock_usd_rate) config(): f64 = INIT_DOCK_USD_RATE;

        /// price update frequency (in number of blocks)
        pub UpdateFreq get(fn update_freq) config(): u8 = INIT_UPDATE_EVERY_N_BLOCKS;
        /// block number of last DockUsdRate update
        pub UpdatedAt get(fn updated_at): BlockNumber;
    }

    // add_extra_genesis { // TODO use this to initialize value at genesis, instead of config types
    //     config(dock_usd_rate): SomeTypeImplDefault; // TODO tpye impl default
    //     build (|config| {
    //       //...
    //     });
    //   }
)

// the module's callable functions
decl_module! {
    pub struct Module<T:Trait> for enum Call where origin: T:Origin {
        fn deposit_event() = default;

        // pub fn execute_call(origin, call: Box<<T as Trait>::Call>) -> DispatchResultWithPostInfo { // TODO call type
        //     let sender = ensure_signed(origin)?;

        //     // TODO update DockUsdRate if more than N blocks
        //     let current_block = <system::Module<T>>::block_number().saturated_into::<u64>(); // TODO check safety of saturated_into
        //     // TODO type of current block, vs type of updated_at, update_freq
        //     if current_block - Self::udpated_at() > Self::update_freq() {
        //         T::HandlerUpdateDockUsdRate::update_dock_usd_rate()?;
        //     }

        //     // TODO calculate fee based on type of call
        //     let fee = Self::compute_call_fee_(&call)?;
        //     // TODO deduct fees based on Currency::Withdraw
        //     Self::charge_fees_(sender, fee)?;

        //     // TODO return Pays::No in PostDispatchInfo
        //     Ok(Pays::No.into())
        // }

        // // set update frequency through Root
        // pub fn root_set_update_freq(origin, next_update_freq: u8) {
        //     let sender= ensure_signed(origin)?; 
        //     ensure!(sender == system::RawOrigin::Root.into(), "only Root can force-update the update frequency");

        //     UpdateFreq::put(next_update_freq);
        //     Self::deposit_event(RawEvent::UpdateFreqSet(next_update_freq));
        // }

        // pub fn root_set_dock_usd_rate(origin, next_dock_usd_rate:f64) {
        //     let sender= ensure_signed(origin)?; 
        //     ensure!(sender == system::RawOrigin::Root.into(), "only Root can force-update the dock_usd_rate");

        //     DockUsdRate::put(next_dock_usd_rate);
        //     Self::deposit_event(RawEvent::DockUsdRateSet(next_dock_usd_rate));
        // }
    }
}



// private helper functions
impl <T: Trait> Module<T> {
    // fn compute_call_fee_(call: &Box<<T as Trait>::Call>) -> Result<u64, &'static str> {
    //     // TODO get type of call



    //     // match type: get USD price
    //     let fee_usdcent = match call_type {
    //         _ => 50,
    //     };
    //     // convert to DOCKs
    //     // TODO check conversion to f64 and division
    //     let fee_dock: InsertMinimumUnitType = fee_usdcent as f64.checked_div(Self::dock_usd_rate as f64) // TODO safe math and type conversion
    //     // TODO what is minimum unit for DOCKs
    //     .ok_or("checked_div err: Dock usd rate is zero")?;

    //     Ok(fee_dock)
    // }

    // fn charge_fees_(sender: T::AccountId, amount: T::Balance) -> Result {
    //     let _ = <balances::Module<T> as Currency<_>>::withdraw(
    //       &who,
    //       amount,
    //       WithdrawReason::Fee,
    //       ExistenceRequirement::KeepAlive
    //     )?;
    //     Ok(())
    // }

    // fn execute_call_(origin: T::Origin, call: Box<<T as Trait>::Call>) -> DispatchWithCallResult{
    //     let sender = ensure_signed(origin)?;

    //     let dispatch_result = call.clone().dipatch(sender);

    //     // Log event for success or failure of execution
    //     match dispatch_result {
    //         Ok(post_dispatch_info) => {
    //             Self::deposit_event(RawEvent::Executed(authors, proposal));
    //             Ok(PostDispatchInfo {
    //                 actual_weight: actual_weight(post_dispatch_info),
    //                 pays_fee: post_dispatch_info.pays_fee, // TODO pay no fee, already withdrawn
    //             })
    //         }
    //         Err(e) => {
    //             Self::deposit_event(RawEvent::ExecutionFailed(authors, proposal, e.error));
    //             Err(DispatchErrorWithPostInfo {
    //                 post_info: PostDispatchInfo {
    //                     actual_weight: actual_weight(e.post_info),
    //                     pays_fee: e.post_info.pays_fee,
    //                 },
    //                 error: e.error,
    //             })
    //         }
    //     }
    // }

    // /// update the dock_usd_rate
    // pub fn set_dock_usd_rate(origin, value: u64) -> DispatchResultWithPostInfo {
    //     let sender= ensure_signed(origin)?;   

    //     ////////////////
    //     // TODO check that it's the price fedd contract that is updating the value

    //     DockUsdRate::put(value);
    //     Self::deposit_event(RawEvent::DockUsdRateSet(value));
    // }
}

// TODO in runtime/src/lib.rs: update BaseCallFilter to disallow direct calls to DID, Blob, ...


#[cfg(test)]
mod tests {
    use super::*;

	use frame_support::{assert_ok, assert_noop, impl_outer_origin, parameter_types, weights::Weight};
	use sp_runtime::{testing::Header, traits::IdentityLookup, Perbill};
	use sp_core::testing::{KeyStore, SR25519};
    use sp_core::traits::KeystoreExt;
    
    impl_outer_origin! {
         pub enum Origin for Test {}
    }

    #[derive(Clone, Eq, PartialEq)]
    pub struct Test;

    parameter_types! {
        pub const BlockHashCount: u64 = 250;
        pub const MaximumBlockWeight: Weight = 1024;
        pub const MaximumBlockLength: u32 = 2 * 1024;
        pub const AvailableBlockRatio: Perbill = Perbill::from_percent(75);
    }
    impl system::Trait for Test {
        type Origin = Origin;
        type Call = ();
        type Index = u64;
        type BlockNumber = u64;
        type Hash = H256;
        type Hashing = BlakeTwo256;
        type AccountId = u64;
        type Lookup = IdentityLookup<Self::AccountId>;
        type Header = Header;
        type Event = ();
        type BlockHashCount = BlockHashCount;
        type MaximumBlockWeight = MaximumBlockWeight;
        type MaximumBlockLength = MaximumBlockLength;
        type AvailableBlockRatio = AvailableBlockRatio;
        type Version = ();
        type ModuleToIndex = ();
        type AccountData = ();
        type OnNewAccount = ();
        type OnKilledAccount = ();
    }
    impl Trait for Test {
        // type Event: From<Event<Self>> + Into<<Self as system::Trait>::Event>;
        type Event = ();
        // type BlockNumber: <Self as frame_system::Trait>::BlockNumber;
        type BlockNumber = u64;
        // type BaseCallFilter = BaseFilter;
        type BaseCallFilter = ();
        // type Call: Parameter + UnfilteredDispatchable<Origin = Self::Origin> + GetDispatchInfo;
        type Call: ();
        // type HandlerUpdateDockUsdRate: HandlerUpdateDockUsdRate = ();
        type HandlerUpdateDockUsdRate: ();
    }

    type FiatFilterModule = Module<Test>; 

    const ALICE_PHRASE:&'static str = "secret lawsuit code vehicle special addict list find swap black elbow pizza";
    use hex_literal::hex;
    const GENESIS_UTXO: [u8;32] = hex!("FDKHJSKFHGJKHSDJFKGHJKSDF"); // TODO replace


    // each new test will invoke this for setup
    fn new_test_ext() -> sp_io::TestExternalities {
        // 1. Create new keys for test user Alice
        let keystore = Keystore::new();
        let alice_pub_key = keystore.write().sr25519_generate_new(SR25519, Some(ALICE_PHRASE)).unwrap();

        // 2. Store a genesis UTXO (500, Alice owned) in genesis storage
        let mut t = system::GenesisConfig::default()
            .build_storage::<Test>()
            .unwrap();

        t.top.extend(
            GenesisConfig {
                genesis_utxos:vec![
                    TransactionOutput {
                        value:100,
                        pubkey: H256::from(alice_pub_key),
                    }
                ],
                ..Default::default()
            }
            .build_storage()
            unwrap()
            .top
        );
                
        // 3. Store Alice's keys in storage for every test to use
        let mut ext = sp_io::TestExternalities::from(t);
        ext.register_extension(KeyStoreExt(keystore))

        ext
    }

    #[test]
    fn test_simple_transaction() {
        new_test_ext().execute_with(|| {
            let alice_pub_key = sp_io::crypto::sr25519_public_keys(SR25519)[0];

            let mut transaction = Transaction {
                inputs: vec![ TransactionInput{
                    outpoint: H256::from(GENESIS_UTXO),
                    sigscript:  H512::zero(),
                }],
                outputs: vec![TransactionOutput{
                    value: 50,
                    pubkey: H256::from(alice_pub_key),
                }]
            }

            let alice_signature = sp_io::crypto::sr25519_sign(SR25519, &alice_pub_key, &transaction.encode()).unwrap();

            // inject back
            transaction.inputs[0].sigscript = H512::from(alice_signature);
            // calculate new UTXO hash
            let new_utxo_hash = BlakeTwo256::hash_of(&transaction.encode(),  0 as u64);

            // now invoke the spend function and test
            // 1. assert that everything will be ok
            assert_ok!(Utxo::spend(Origin::signed(0), transaction));
            // 2. expect that spent UTXO has disappeared
            assert!( !UtxoStore::contains_key(H256::from(GENESIS_UTXO)));
            // 3. expect the new UTO to exist
            assert!(UtxoStore::contains_key(new_utxo_hash));
            assert_eq!(UtxoStore::get(new_utxo_hash).unwrap().value, 50);
        });
    }
}


// ////////////////////
// TODO adapt for filtering DID, Blob calls
// ////////
// / Signed extension to ensure that only a Migrator can send the migrate extrinsic.
// / This is necessary to prevent a `migrate` call done by non-Migrator to even enter a block.
// #[derive(Encode, Decode, Clone, Eq, PartialEq)]
// pub struct OnlyMigrator<T: Trait + Send + Sync>(PhantomData<T>);

// impl<T: Trait + Send + Sync> sp_std::fmt::Debug for OnlyMigrator<T> {
//     fn fmt(&self, f: &mut sp_std::fmt::Formatter) -> sp_std::fmt::Result {
//         write!(f, "OnlyMigrator")
//     }
// }

// impl<T: Trait + Send + Sync> SignedExtension for OnlyMigrator<T>
// where
//     <T as system::Trait>::Call: IsSubType<Call<T>>,
// {
//     const IDENTIFIER: &'static str = "OnlyMigrator";
//     type AccountId = T::AccountId;
//     type Call = <T as system::Trait>::Call;
//     type AdditionalSigned = ();
//     type Pre = ();

//     fn additional_signed(&self) -> sp_std::result::Result<(), TransactionValidityError> {
//         Ok(())
//     }

//     fn validate(
//         &self,
//         who: &Self::AccountId,
//         call: &Self::Call,
//         _info: &DispatchInfoOf<Self::Call>,
//         _len: usize,
//     ) -> TransactionValidity {
//         if let Some(local_call) = call.is_sub_type() {
//             match local_call {
//                 // Migrator can make only these 2 calls without paying fees
//                 Call::migrate(..) | Call::give_bonuses(..) => {
//                     if !<Migrators<T>>::contains_key(who) {
//                         // If migrator not registered, don't include transaction in block
//                         return InvalidTransaction::Custom(1).into();
//                     }
//                 }
//                 _ => (),
//             }
//         }
//         Ok(ValidTransaction::default())
//     }
// }
