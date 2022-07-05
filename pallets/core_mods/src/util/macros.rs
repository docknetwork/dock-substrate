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
macro_rules! field_accessor {
    ($self: ident, () $($add: tt)*) => {
        ()
    };
    ($self: ident, $lit: literal $($add: tt)*) => {
        $lit
    };
    ($self: ident, $ident: ident $($add: tt)*) => {
        $self.$ident$($add)*
    };
    ($self: ident, { $expr: expr }$($add: tt)*) => {
        $expr($self)
    }
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
    ($type: ident for $target: ty: with $len: tt as len, $target_field: tt as target) => {
        $crate::impl_to_state_change! { $type }

        impl<T: frame_system::Config> $crate::Action<T> for $type<T> {
            type Target = $target;

            fn target(&self) -> $target {
                $crate::field_accessor!(self, $target_field)
            }

            fn len(&self) -> u32 {
                $crate::field_accessor!(self, $len.len() as u32)
            }
        }
    };
    ($type: ident for $target: ty: with $len: tt as len, $target_field: tt as target no_state_change) => {
        impl<T: frame_system::Config> $crate::Action<T> for $type<T> {
            type Target = $target;

            fn target(&self) -> $target {
                $crate::field_accessor!(self, $target_field)
            }

            fn len(&self) -> u32 {
                $crate::field_accessor!(self, $len.len() as u32)
            }
        }
    };
    (for $target: ty: $($type: ident with $len: tt as len, $target_field: tt as target $($addition: tt)?),+) => {
        $(
            $crate::impl_action! { $type for $target: with $len as len, $target_field as target $($addition)? }
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
    (for $target: ty: $($type: ident with $len: tt as len, $target_field: tt as target),+) => {
        $(
            $crate::impl_action_with_nonce! { $type for $target: with $len as len, $target_field as target }
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
        #[derive(Encode, Decode, Debug, Clone)]
        $(#[$meta])*
        pub enum $name<'a, T: frame_system::Config> {
            $($type(Cow<'a, $mod::$type<T>>)),+
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
