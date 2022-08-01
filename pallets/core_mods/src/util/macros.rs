#[macro_export]
macro_rules! impl_bits_conversion {
    ($ident: ident, $type: ty) => {
        impl From<$ident> for $type {
            fn from(value: $ident) -> Self {
                value.bits()
            }
        }

        impl TryFrom<$type> for $ident {
            type Error = $type;

            fn try_from(value: $type) -> Result<Self, $type> {
                Self::from_bits(value).ok_or(value)
            }
        }
    };
}

#[macro_export]
macro_rules! pub_for_test {
    ($(#[$meta:meta])* fn $($val: tt)*) => {
        #[cfg(test)]
        $(#[$meta])*
        pub fn $($val)*

        #[cfg(not(test))]
        $(#[$meta])*
        fn $($val)*
    }
}

#[macro_export]
macro_rules! field_accessor {
    ($self: ident, () $($add: tt)*) => {
        ()
    };
    ($self: ident, $lit: literal $($add: tt)*) => {
        $lit
    };
    ($self: ident, { $expr: expr }$($add: tt)*) => {
        $expr($self)
    };
    ($self: ident, $($ident: tt $(($($call: tt),*))?).+ with $($add: tt)*) => {
        $self.$($ident $(($($call)*))*).+ $($add)*
    };
}

#[macro_export]
macro_rules! impl_to_state_change {
    ($type: ident) => {
        impl<T: frame_system::Config> $crate::ToStateChange<T> for $type<T> {
            fn to_state_change(&self) -> $crate::StateChange<'_, T> {
                $crate::StateChange::$type(sp_std::borrow::Cow::Borrowed(self))
            }

            fn into_state_change(self) -> $crate::StateChange<'static, T> {
                $crate::StateChange::$type(sp_std::borrow::Cow::Owned(self))
            }
        }
    };
}

#[macro_export]
macro_rules! impl_action {
    ($type: ident for $target: ty: with $($len: tt $(($($call: tt),*))?).+ as len, $($target_field: tt $(($($target_call: tt),*))?).+ as target) => {
        $crate::impl_to_state_change! { $type }

        impl<T: frame_system::Config> $crate::Action<T> for $type<T> {
            type Target = $target;

            fn target(&self) -> $target {
                $crate::field_accessor!(self, $($target_field $(($($target_call)*))*).+ with)
            }

            fn len(&self) -> u32 {
                $crate::field_accessor!(self, $($len $(($($call)*))*).+ with as u32)
            }
        }
    };
    ($type: ident for $target: ty: with $($len: tt $(($($call: tt),*))?).+ as len, $($target_field: tt $(($($target_call: tt),*))?).+ as target no_state_change) => {
        impl<T: frame_system::Config> $crate::Action<T> for $type<T> {
            type Target = $target;

            fn target(&self) -> $target {
                $crate::field_accessor!(self, $($target_field $(($($target_call)*))*).+ with)
            }

            fn len(&self) -> u32 {
                $crate::field_accessor!(self, $($len $(($($call)*))*).+ with as u32)
            }
        }
    };
    (for $target: ty: $($type: ident with $($len: tt $(($($call: tt),*))?).+ as len, $($target_field: tt $(($($target_call: tt),*))?).+ as target $($addition: tt)?),+) => {
        $(
            $crate::impl_action! { $type for $target: with $($len $(($($call),*))*).+ as len, $($target_field $(($($target_call)*))*).+ as target $($addition)? }
        )+
    };
}

#[macro_export]
macro_rules! impl_action_with_nonce {
    ($type: ident for $($token: tt)*) => {
        $crate::impl_action! { $type for $($token)* }

        impl<T: frame_system::Config> $crate::ActionWithNonce<T> for $type<T> {
            fn nonce(&self) -> T::BlockNumber {
                self.nonce
            }
        }
    };
    (for $target: ty: $($type: ident with $($len: tt $(($($call: tt),*))?).+ as len, $($target_field: tt $(($($target_call: tt),*))?).+ as target),+) => {
        $(
            $crate::impl_action_with_nonce! { $type for $target: with $($len $(($($call),*))*).+ as len, $($target_field $(($($target_call)*))*).+ as target }
        )+
    };
}

#[macro_export]
macro_rules! deposit_indexed_event {
    ($event: ident($($value: expr),+) over $($index: expr),+) => {
        <system::Module<T>>::deposit_event_indexed(
            &[$(<T as system::Config>::Hashing::hash(&$index[..])),+],
            <T as Config>::Event::from(Event::$event($($value),+)).into()
        );
    };
    ($event: ident($($value: expr),+)) => {
        <system::Module<T>>::deposit_event_indexed(
            &[$(<T as system::Config>::Hashing::hash(&$value[..])),+],
            <T as Config>::Event::from(Event::$event($($value),+)).into()
        );
    }
}

#[macro_export]
macro_rules! impl_wrapper {
    ($wrapper: ident, $type: ty $(,$($tt: tt)*)?) => {
        $($crate::impl_encode_decode_wrapper_tests! { $wrapper, $type, $($tt)* })?

        impl sp_std::borrow::Borrow<$type> for $wrapper {
            fn borrow(&self) -> &$type {
                &self.0
            }
        }

        impl From<$type> for $wrapper {
            fn from(value: $type) -> $wrapper {
                $wrapper(value)
            }
        }

        impl From<$wrapper> for $type {
            fn from(wrapper: $wrapper) -> $type {
                wrapper.0
            }
        }

        impl sp_std::ops::Deref for $wrapper {
            type Target = $type;

            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }

        impl sp_std::ops::DerefMut for $wrapper {
            fn deref_mut(&mut self) -> &mut Self::Target {
                &mut self.0
            }
        }
    };
}

#[macro_export]
macro_rules! def_state_change {
    ($(#[$meta:meta])* $name: ident: $($mod: ident::$type: ident),+) => {
        #[derive(codec::Encode, codec::Decode, Debug, Clone)]
        $(#[$meta])*
        pub enum $name<'a, T: frame_system::Config> {
            $($type(sp_std::borrow::Cow<'a, $mod::$type<T>>)),+
        }
    }
}

#[macro_export]
macro_rules! impl_encode_decode_wrapper_tests {
    ($wrapper: ident, $type: ty, with tests as $mod: ident) => {
        $crate::impl_encode_decode_wrapper_tests!($wrapper, $type, for rand use rand::random(), with tests as $mod);
    };
    ($wrapper: ident, $type: ty, for rand use $rand: expr, with tests as $mod: ident) => {
        #[cfg(test)]
        pub mod $mod {
            use super::*;
            use codec::{Decode, Encode};

            #[test]
            pub fn encode_decode() {
                let type_value: $type = $rand;
                let wrapper_value = $wrapper(type_value.clone());

                let encoded_wrapper = Encode::encode(&wrapper_value);
                let encoded_type = Encode::encode(&type_value);

                assert_eq!(encoded_type, encoded_wrapper);

                let decoded_wrapper: $wrapper = Decode::decode(&mut &encoded_wrapper[..]).unwrap();
                assert_eq!(decoded_wrapper, wrapper_value);
                let decoded_wrapper: $wrapper = Decode::decode(&mut &encoded_type[..]).unwrap();
                assert_eq!(decoded_wrapper, wrapper_value);

                let decoded_type: $type = Decode::decode(&mut &encoded_type[..]).unwrap();
                assert_eq!(decoded_type, type_value);
                let decoded_type: $type = Decode::decode(&mut &encoded_wrapper[..]).unwrap();
                assert_eq!(decoded_type, type_value);
            }
        }
    };
}

#[cfg(feature = "runtime-benchmarks")]
#[macro_export]
macro_rules! with_pair {
    (let $pair: ident as Pair with idx $idx: expr; $($body: tt)+) => {
        $crate::with_pair!(let $pair as Pair with idx $idx, seed &[1; 32]; $($body)+ )
    };
    (let $pair: ident as Pair with idx $idx: expr, seed $seed: expr; $($body: tt)+) => {
        match $idx {
            0 => {
                let $pair = $crate::def_pair!(sr25519, $seed);
                $($body)+
            },
            1 => {
                let $pair = $crate::def_pair!(ed25519, $seed);
                $($body)+
            },
            2 => {
                let $pair = $crate::def_pair!(secp256k1, $seed);
                $($body)+
            }
            _ => unimplemented!()
        }
    }
}

#[cfg(feature = "runtime-benchmarks")]
#[macro_export]
macro_rules! def_pair {
    (sr25519, $seed: expr) => {{
        use sp_core::Pair;

        let pair = sp_core::sr25519::Pair::from_seed($seed);
        struct TestSr25519Pair {
            pair: sp_core::sr25519::Pair,
        }

        impl TestSr25519Pair {
            fn sign(&self, msg: &[u8]) -> sp_core::sr25519::Signature {
                use rand_chacha::rand_core::SeedableRng;
                use schnorrkel::{context::attach_rng, *};

                let mut transcript = merlin::Transcript::new(b"SigningContext");
                transcript.append_message(b"", b"substrate");
                transcript.append_message(b"sign-bytes", msg);
                let context = attach_rng(transcript, rand_chacha::ChaChaRng::from_seed([10u8; 32]));

                let sk = SecretKey::from_bytes(&self.pair.to_raw_vec()[..]).unwrap();

                sk.sign(
                    context,
                    &PublicKey::from_bytes(&self.pair.public()[..]).unwrap(),
                )
                .into()
            }

            fn public(&self) -> sp_core::sr25519::Public {
                self.pair.public()
            }
        }

        TestSr25519Pair { pair }
    }};
    (ed25519, $seed: expr) => {{
        use sp_core::Pair;

        sp_core::ed25519::Pair::from_seed($seed)
    }};
    (secp256k1, $seed: expr) => {
        $crate::keys_and_sigs::get_secp256k1_keypair_1($seed)
    };
}

#[cfg(feature = "runtime-benchmarks")]
#[macro_export]
macro_rules! bench_with_all_pairs {
    (
        with_pairs:
            $(
                $bench_name_sr25519: ident for sr25519,
                $bench_name_ed25519: ident for ed25519,
                $bench_name_secp256k1: ident for secp256k1
                {
                    $({ $($init: tt)* })?
                    let $pair: ident as Pair;
                    $($body: tt)+
                }: $call_tt: tt($($call_e: expr),+)
                verify { $($verification: tt)* }
            )+
        $(;
            standard:
                $($other: tt)*
        )?
    ) => {
        benchmarks! {
            where_clause { where T: core::fmt::Debug }

            $(
                $bench_name_sr25519 {
                    $($($init)*)*
                    #[allow(unused_imports)]
                    use sp_core::Pair;
                    let $pair = $crate::def_pair!(sr25519, &[4; 32]);
                    $($body)+
                }: $call_tt($($call_e),+) verify { $($verification)* }

                $bench_name_ed25519 {
                    $($($init)*)*
                    #[allow(unused_imports)]
                    use sp_core::Pair;
                    let $pair = $crate::def_pair!(ed25519, &[3; 32]);
                    $($body)+
                }: $call_tt($($call_e),+) verify { $($verification)* }

                $bench_name_secp256k1 {
                    $($($init)*)*
                    #[allow(unused_imports)]
                    use sp_core::Pair;
                    let $pair = $crate::def_pair!(secp256k1, &[2; 32]);
                    $($body)+
                }: $call_tt($($call_e),+) verify { $($verification)* }
            )+

            $($($other)*)?
        }
    };
}
