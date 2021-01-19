#![cfg_attr(not(feature = "std"), no_std)]

use support::{decl_module, decl_event, decl_storage, StorageValue};
use system::ensure_signed;
use support::dispatch::DispatchResultWithPostInfo;

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

parameter_types! {
    // pub const InitialDockUsdRate: f64 = 0.02251112;
    // pub const InitialUpdateEveryNBlocks: u8 = 10;
}
// The pallet's configuration trait
pub trait Trait: system::Trait { // TODO add necessary pallet traits
    // the Event used here must impl these traits
    type Event: From<Event<Self>> + Into<<Self as system::Trait>::Event>;
    type BlockNumber: <Self as frame_system::Trait>::BlockNumber;
    // type InitialDockUsdRate = InitialDockUsdRate;
    type BaseCallFilter = BaseFilter;


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
pub struct BaseFilter;
impl Filter<Call> for BaseFilter {
    fn filter(call: &Call) -> bool {
        // TODO make it match:
        //     DID write, update, remove (depending on key type)
        //     revoke/unrevoke (depending on number of items), 
        //     blob (depending on byte size).
        !matches!(
            call,
            &Call::Balances(pallet_balances::Call::set_balance(..))
        )
    }
}

decl_event!(
    // pub enum Event<T> where
    // AccountId = <T as system::Trait>::AccountId, // TODO I probably don't need this trait bound ?
    pub enum Event
    {
        // on set_dock_usd_rate executed
        DockUsdRateSet(f64),
        // on root_set_update_freq executed
        UpdateFreqSet(u8),
    }
)

// impl Default for Membership {
//     fn default() -> Self {
//         Membership {
//             members: BTreeSet::new(),
//             vote_requirement: 1,
//         }
//     }
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
        pub UpdatedAt get(fn updated_at): BlockNumber
    }

    // add_extra_genesis { // TODO use this to initialize value at genesis, instead of config types
    //     config(dock_usd_rate): SomeTypeImplDefault; // TODO tpye impl default
    //     build (|config| {
    //       //...
    //     });
    //   }
)

// the module's callable functions
decl_module!(
    pub struct Module<T:Trait> for enum Call where origin: T:Origin {
        fn deposit_event() = default;

        pub fn execute_call(origin, call: Box<<T as Trait>::Call>) -> DispatchResultWithPostInfo { // TODO call type
            let sender = ensure_signed(origin)?;

            // TODO update DockUsdRate if more than N blocks
            if getCurrentBlock() - Self::udpated_at() > Self::update_freq() {
                T::HandlerUpdateDockUsdRate::update_dock_usd_rate()?;
            }

            // TODO calculate fee based on type of call
            let fee = Self::compute_call_fee_(&call)?;
            // TODO deduct fees based on Currency::Withdraw
            Self::charge_fees_(sender, fee)?;

            // TODO return Pays::No in PostDispatchInfo
            Ok(Pays::No.into())
        }

        // set update frequency through Root
        pub fn root_set_update_freq(origin, next_update_freq: u8) {
            let sender= ensure_signed(origin)?; 
            ensure!(sender == system::RawOrigin::Root.into(), "only Root can force-update the update frequency");

            UpdateFreq::put(next_update_freq);
            Self::deposit_event(RawEvent::UpdateFreqSet(next_update_freq));
        }

        pub fn root_set_dock_usd_rate(origin, next_dock_usd_rate:f64) {
            let sender= ensure_signed(origin)?; 
            ensure!(sender == system::RawOrigin::Root.into(), "only Root can force-update the dock_usd_rate");

            DockUsdRate::put(next_dock_usd_rate);
            Self::deposit_event(RawEvent::DockUsdRateSet(next_dock_usd_rate));
        }
    }
)

// private helper functions
impl <T: Trait> Module<T> {
    fn compute_call_fee_(call: Box<<T as Trait>::Call>) -> u64 {
        // TODO get type of call


        
        // match type: get USD price
        let fee_usdcent = match call_type {
            _ => 50,
        };
        // convert to DOCKs
        let fee_dock = fee_usdcent / Self::dock_usd_rate // TODO safe math and type conversion
    }

    fn charge_fees_(sender: T::AccountId, amount: T::Balance) -> Result {
        let _ = <balances::Module<T> as Currency<_>>::withdraw(
          &who,
          amount,
          WithdrawReason::Fee,
          ExistenceRequirement::KeepAlive
        )?;
        Ok(())
    }

    fn execute_call_(origin: T::Origin, call: Box<<T as Trait>::Call>) -> DispatchWithCallResult{
        let sender = ensure_signed(origin)?;

        let dispatch_result = call.clone().dipatch(sender);

        // Log event for success or failure of execution
        match dispatch_result {
            Ok(post_dispatch_info) => {
                Self::deposit_event(RawEvent::Executed(authors, proposal));
                Ok(PostDispatchInfo {
                    actual_weight: actual_weight(post_dispatch_info),
                    pays_fee: post_dispatch_info.pays_fee,
                })
            }
            Err(e) => {
                Self::deposit_event(RawEvent::ExecutionFailed(authors, proposal, e.error));
                Err(DispatchErrorWithPostInfo {
                    post_info: PostDispatchInfo {
                        actual_weight: actual_weight(e.post_info),
                        pays_fee: e.post_info.pays_fee,
                    },
                    error: e.error,
                })
            }
        }
    }

    /// update the dock_usd_rate
    pub fn set_dock_usd_rate(origin, value: u64) -> DispatchResultWithPostInfo {
        let sender= ensure_signed(origin)?;   

        ////////////////
        // TODO check that it's the price fedd contract that is updating the value

        DockUsdRate::put(value);
        Self::deposit_event(RawEvent::DockUsdRateSet(value));
    }
}

// TODO in runtime/src/lib.rs: update BaseCallFilter to disallow direct calls to DID, Blob, ...


#[cfg(test)]
mod tests {
    use super::*;

	use frame_support::{assert_ok, assert_noop, impl_outer_origin, parameter_types, weights::Weight};
	use sp_runtime::{testing::Header, traits::IdentityLookup, Perbill};
	use sp_core::testing::{KeyStore, SR25519};
	use sp_core::traits::KeystoreExt;
}