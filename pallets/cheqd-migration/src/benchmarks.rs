use super::*;
use frame_benchmarking::{benchmarks, whitelisted_caller};
use frame_support::traits::{Currency, IsType};
use frame_system::{Pallet as System, RawOrigin};
use scale_info::prelude::string::ToString;
use sp_runtime::{traits::Zero, DispatchError};

fn assert_event<T: Config>(expected_event: impl Into<<T as pallet::Config>::Event>) {
    let events = System::<T>::events();
    let expected_event = expected_event.into();

    assert!(events
        .iter()
        .any(|event| &event.event == expected_event.into_ref()));
}

benchmarks! {
    migrate {
        let destination = "cheqd1fktkf9nsj625jkxz7r7gmryna6uy8y2pptang4".to_string();
        let caller: T::AccountId = whitelisted_caller();
        T::Currency::make_free_balance_be(&caller, 100_000_000u32.into());
        let dock_amount = T::Currency::free_balance(&caller);

    }: _(RawOrigin::Signed(caller.clone()), destination.clone())
    verify {
        assert_event::<T>(Event::<T>::Migrated {
            sender: caller.clone(),
            cheqd_recipient: CheqdAddress::new::<T>(destination).unwrap(),
            dock_amount,
        });
        assert!(
            T::Currency::free_balance(&caller).is_zero()
        );
    }

    migrate_validation_failure {
        let destination = "cosmos12zddgw36trnvwm4s3x0etjd86r4lgqdthrzjdk".to_string();
        let caller: T::AccountId = whitelisted_caller();
        let dock_amount = T::Currency::free_balance(&caller);

    }: {
        Pallet::<T>::migrate(RawOrigin::Signed(caller.clone()).into(), destination.clone()).unwrap_err();
        Ok::<_, DispatchError>(())
    }
    verify {
        assert_eq!(
            T::Currency::free_balance(&caller), dock_amount
        );
    }
}
