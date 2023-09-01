/// Implements bits conversion from/to the given type for the supplied bitflags identifier.
#[macro_export]
macro_rules! impl_bits_conversion {
    ($ident: ident from $type: ty) => {
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

        impl Encode for $ident {
            fn encode(&self) -> Vec<u8> {
                <$type>::encode(&self.clone().into())
            }
        }

        impl Decode for $ident {
            fn decode<I: codec::Input>(input: &mut I) -> Result<Self, codec::Error> {
                let decoded = <$type>::decode(input)?;

                Self::from_bits(decoded).ok_or("Invalid value".into())
            }
        }
    };
}

/// Makes given ident `pub` only for test and uses supplied visibility if compiled otherwise.
#[macro_export]
macro_rules! pub_for_test {
    ($(#[$meta:meta])* $vis: vis $ident: ident $($val: tt)*) => {
        #[cfg(test)]
        $(#[$meta])*
        pub $ident $($val)*

        #[cfg(not(test))]
        $(#[$meta])*
        $vis $ident $($val)*
    }
}

/// Implements field accessor based on input using supplied `self`.
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

/// Implements `ToStateChange` trait with supplied params for the given ident(s).
#[macro_export]
macro_rules! impl_to_state_change {
    ($type: ident) => {
        impl<T: frame_system::Config> $crate::common::ToStateChange<T> for $type<T> {
            fn to_state_change(&self) -> $crate::common::StateChange<'_, T> {
                $crate::common::StateChange::$type(sp_std::borrow::Cow::Borrowed(self))
            }
        }
    };
}

/// Implements `Action` trait with supplied params for the given ident(s).
#[macro_export]
macro_rules! impl_action {
    (
        $type: ident for $target: ty: with
        $($len_field: tt $(($($len_call: tt),*))?).+ as len,
        $($target_field: tt $(($($target_call: tt),*))?).+ as target
    ) => {
        $crate::impl_to_state_change! { $type }

        impl<T: frame_system::Config> $crate::util::Action<T> for $type<T> {
            type Target = $target;

            fn target(&self) -> $target {
                $crate::field_accessor!(self, $($target_field $(($($target_call)*))*).+ with)
            }

            fn len(&self) -> u32 {
                $crate::field_accessor!(self, $($len_field $(($($len_call)*))*).+ with as u32)
            }
        }
    };
    (
        $type: ident for $target: ty: with
        $($len_field: tt $(($($len_call: tt),*))?).+ as len,
        $($target_field: tt $(($($target_call: tt),*))?).+ as target
        no_state_change
    ) => {
        impl<T: frame_system::Config> $crate::util::Action<T> for $type<T> {
            type Target = $target;

            fn target(&self) -> $target {
                $crate::field_accessor!(self, $($target_field $(($($target_call)*))*).+ with)
            }

            fn len(&self) -> u32 {
                $crate::field_accessor!(self, $($len_field $(($($len_call)*))*).+ with as u32)
            }
        }
    };
    (
        for $target: ty:
        $(
            $type: ident with $($len: tt $(($($call: tt),*))?).+ as len,
            $($target_field: tt $(($($target_call: tt),*))?).+ as target
            $($addition: tt)?
        ),+
    ) => {
        $(
            $crate::impl_action! { $type for $target: with $($len $(($($call),*))*).+ as len, $($target_field $(($($target_call)*))*).+ as target $($addition)? }
        )+
    };
}

/// Implements `Action` and `ActionWithNonce` traits with supplied params for the given ident(s).
#[macro_export]
macro_rules! impl_action_with_nonce {
    ($type: ident for $($token: tt)*) => {
        $crate::impl_action! { $type for $($token)* }

        impl<T: frame_system::Config> $crate::util::ActionWithNonce<T> for $type<T> {
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

/// Deposits an event indexed over the supplied fields.
#[macro_export]
macro_rules! deposit_indexed_event {
    ($event: ident($($value: expr),+) over $($index: expr),+) => {{
        <system::Pallet<T>>::deposit_event_indexed(
            &[$(<<T as frame_system::Config>::Hashing as sp_core::Hasher>::hash(&$index[..])),+],
            <T as Config>::Event::from(Event::$event($($value),+)).into()
        );
    }};
    ($event: ident($($value: expr),+)) => {
        $crate::deposit_indexed_event!($event($($value),+) over $($value),+)
    }
}

/// Implements two-direction `From`/`Into` and one-direction `Deref`/`DeferMut` traits for the supplied wrapper and type.
#[macro_export]
macro_rules! impl_wrapper {
    (no_wrapper_from_type $wrapper: ident($type: ty) $(,$($tt: tt)*)?) => {
        $($crate::impl_encode_decode_wrapper_tests! { $wrapper($type), $($tt)* })?

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
    ($wrapper: ident($type: ty) $(,$($tt: tt)*)?) => {
        $crate::impl_wrapper! { no_wrapper_from_type $wrapper($type) $(,$($tt)*)? }

        $crate::impl_wrapper_from_type_conversion! { $wrapper: $type }
    };
}

/// Implements `From<type>` for the wrapper.
#[macro_export]
macro_rules! impl_wrapper_from_type_conversion {
    ($wrapper: ident: $($type: ty),+) => {
        $(
            impl From<$type> for $wrapper {
                fn from(value: $type) -> $wrapper {
                    $wrapper(value.into())
                }
            }
        )+
    }
}

/// Implements type's type info for the wrapper.
#[macro_export]
macro_rules! impl_wrapper_type_info {
    ($wrapper: ident($type: ty)) => {
        impl scale_info::TypeInfo for $wrapper {
            type Identity = Self;

            fn type_info() -> scale_info::Type {
                scale_info::Type::builder()
                    .path(scale_info::Path::new(
                        rust_core::stringify!($wrapper),
                        rust_core::stringify!($wrapper),
                    ))
                    .composite(scale_info::build::Fields::unnamed().field(|f| f.ty::<$type>()))
            }
        }
    };
}

/// Defines `StateChange` using supplied actions.
#[macro_export]
macro_rules! def_state_change {
    ($(#[$meta:meta])* $name: ident: $($mod: ident::$type: ident),+) => {
        $(#[$meta])*
        #[derive(scale_info_derive::TypeInfo, codec::Encode, codec::Decode, Debug, Clone, PartialEq)]
        #[scale_info(skip_type_params(T))]
        #[scale_info(omit_prefix)]
        pub enum $name<'a, T: frame_system::Config> {
            $($type(sp_std::borrow::Cow<'a, $crate::modules::$mod::$type<T>>)),+
        }
    }
}

/// Implements `Encode`/`Decode` wrapper tests for the supplied wrapper and type.
#[macro_export]
macro_rules! impl_encode_decode_wrapper_tests {
    ($wrapper: ident($type: ty), with tests as $mod: ident) => {
        $crate::impl_encode_decode_wrapper_tests!(
            $wrapper($type), for rand use rand::random(), with tests as $mod
        );
    };
    ($wrapper: ident($type: ty), for rand use $rand: expr, with tests as $mod: ident) => {
        #[cfg(test)]
        pub mod $mod {
            use super::*;
            use codec::{Decode, Encode};

            #[test]
            fn encode_decode() {
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

            #[test]
            fn deref() {
                let type_value: $type = $rand;
                let wrapper_value = $wrapper(type_value.clone());

                assert_eq!(*wrapper_value, type_value);
            }

            #[test]
            fn deref_mut() {
                let type_value: $type = $rand;
                let mut wrapper_value = $wrapper($rand);

                *wrapper_value = type_value.clone();
                assert_eq!(wrapper_value.0, type_value);
            }

            #[test]
            fn from_into() {
                let type_value: $type = $rand;
                let wrapper_value = $wrapper(type_value.clone());

                assert_eq!(<$wrapper>::from(type_value.clone()), wrapper_value);
                assert_eq!(<$type>::from(wrapper_value), type_value);
            }
        }
    };
}

/// Creates pair of given type using supplied seed.
#[cfg(feature = "runtime-benchmarks")]
#[macro_export]
macro_rules! def_test_pair {
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
        $crate::common::get_secp256k1_keypair_struct($seed)
    };
}

/// Repeats the benchmark for every pair.
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
                    let $pair = $crate::def_test_pair!(sr25519, &[4; 32]);
                    $($body)+
                }: $call_tt($($call_e),+) verify { $($verification)* }

                $bench_name_ed25519 {
                    $($($init)*)*
                    #[allow(unused_imports)]
                    use sp_core::Pair;
                    let $pair = $crate::def_test_pair!(ed25519, &[3; 32]);
                    $($body)+
                }: $call_tt($($call_e),+) verify { $($verification)* }

                $bench_name_secp256k1 {
                    $($($init)*)*
                    #[allow(unused_imports)]
                    use sp_core::Pair;
                    let $pair = $crate::def_test_pair!(secp256k1, &[2; 32]);
                    $($body)+
                }: $call_tt($($call_e),+) verify { $($verification)* }
            )+

            $($($other)*)?
        }
    };
}
