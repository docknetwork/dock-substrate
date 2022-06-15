use super::*;
use crate::benchmark_utils::{
    get_data_for_did_removal, get_data_for_key_update, get_data_for_sig_ver, DID_DATA_SIZE,
};
use frame_benchmarking::{account, benchmarks};
use sp_std::prelude::*;
use system::RawOrigin;

const SEED: u32 = 0;
const MAX_USER_INDEX: u32 = 1000;

benchmarks! {
    _ {
        // Origin
        let u in 1 .. MAX_USER_INDEX => ();
        // DID
        let d in 0 .. 255 => ();
        // Key
        let k in 0 .. 255 => ();
        // Key type
        let t in 0 .. 2 => ();
        // index into hardcoded public key and signature data
        // Does not compile without the cast to u32
        let i in 0 .. (DID_DATA_SIZE - 1) as u32 => ();
    }

    new {
        let u in ...;
        let d in ...;
        let k in ...;
        let t in ...;

        let caller = account("caller", u, SEED);
        let did: Did = [d as u8; Did::BYTE_SIZE].into();
        let pk = match t {
            n if n == 0 => PublicKey::Sr25519(Bytes32 { value: [k as u8; 32] }),
            n if n == 1 => PublicKey::Ed25519(Bytes32 { value: [k as u8; 32] }),
            _ => PublicKey::Secp256k1(Bytes33 { value: [k as u8; 33] }),
        };

    }: _(RawOrigin::Signed(caller), did, KeyDetail {controller: did, public_key: pk})
    verify {
        let value = Self::did(did);
        assert!(value.is_some());
    }

    // Using hardcoded data for keys and signatures and key generation and signing is not
    // available with benchmarks

    key_update_sr25519 {
        let u in ...;
        let i in ...;

        let caller = account("caller", u, SEED);

        let (n, did, pk_1, pk_2, sig) = get_data_for_key_update(0, i as usize);
        let detail = KeyDetail::new(did.clone(), pk_1);
        let block_number = <T as system::Config>::BlockNumber::from(n);
        Dids::<T>::insert(did.clone(), (detail, block_number));

        let key_update = KeyUpdate::new(
            did.clone(),
            pk_2,
            None,
            n,
        );
    }: update_key(RawOrigin::Signed(caller), key_update, sig)
    verify {
        let value = Self::did(did);
        assert!(value.is_some());
    }

    key_update_ed25519 {
        let u in ...;
        let i in ...;

        let caller = account("caller", u, SEED);

        let (n, did, pk_1, pk_2, sig) = get_data_for_key_update(1, i as usize);
        let detail = KeyDetail::new(did.clone(), pk_1);
        let block_number = <T as system::Config>::BlockNumber::from(n);
        Dids::<T>::insert(did.clone(), (detail, block_number));

        let key_update = KeyUpdate::new(
            did.clone(),
            pk_2,
            None,
            n,
        );
    }: update_key(RawOrigin::Signed(caller), key_update, sig)
    verify {
        let value = Self::did(did);
        assert!(value.is_some());
    }

    key_update_secp256k1 {
        let u in ...;
        let i in ...;

        let caller = account("caller", u, SEED);

        let (n, did, pk_1, pk_2, sig) = get_data_for_key_update(2, i as usize);
        let detail = KeyDetail::new(did.clone(), pk_1);
        let block_number = <T as system::Config>::BlockNumber::from(n);
        Dids::<T>::insert(did.clone(), (detail, block_number));

        let key_update = KeyUpdate::new(
            did.clone(),
            pk_2,
            None,
            n,
        );
    }: update_key(RawOrigin::Signed(caller), key_update, sig)
    verify {
        let value = Self::did(did);
        assert!(value.is_some());
    }

    remove_sr25519 {
        let u in ...;
        let i in ...;

        let caller = account("caller", u, SEED);

        let (n, did, pk, sig) = get_data_for_did_removal(0, i as usize);
        let detail = KeyDetail::new(did.clone(), pk);
        let block_number = <T as system::Config>::BlockNumber::from(n);
        Dids::<T>::insert(did.clone(), (detail, block_number));

        let remove = DidRemoval::new(
            did.clone(),
            n,
        );
    }: remove(RawOrigin::Signed(caller), remove, sig)
    verify {
        let value = Self::did(did);
        assert!(value.is_none());
    }

    sig_ver_sr25519 {
        let i in ...;
        let (msg, pk, sig) = get_data_for_sig_ver(0, i as usize);

    }: {
        assert!(super::Module::<T>::verify_sig_with_public_key(&sig, &msg, &pk).unwrap());
    }

    sig_ver_ed25519 {
        let i in ...;
        let (msg, pk, sig) = get_data_for_sig_ver(1, i as usize);

    }: {
        assert!(super::Module::<T>::verify_sig_with_public_key(&sig, &msg, &pk).unwrap());
    }

    sig_ver_secp256k1 {
        let i in ...;
        let (msg, pk, sig) = get_data_for_sig_ver(2, i as usize);

    }: {
        assert!(super::Module::<T>::verify_sig_with_public_key(&sig, &msg, &pk).unwrap());
    }
}
