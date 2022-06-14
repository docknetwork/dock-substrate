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
macro_rules! impl_did_action {
    ($type: ident with $len: ident as len) => {
        impl<T: frame_system::Config> Action<T> for $type<T> {
            type Target = Did;

            fn target(&self) -> Did {
                self.did
            }

            fn nonce(&self) -> T::BlockNumber {
                self.nonce
            }

            fn len(&self) -> u32 {
                self.$len.len() as u32
            }

            fn to_state_change(&self) -> StateChange<'_, T> {
                StateChange::$type(Cow::Borrowed(self))
            }
        }
    };
    ($type: ident with { $len: expr } as len) => {
        impl<T: frame_system::Config> Action<T> for $type<T> {
            type Target = Did;

            fn target(&self) -> Did {
                self.did
            }

            fn nonce(&self) -> T::BlockNumber {
                self.nonce
            }

            fn len(&self) -> u32 {
                $len(self)
            }

            fn to_state_change(&self) -> StateChange<'_, T> {
                StateChange::$type(Cow::Borrowed(self))
            }
        }
    };
    ($($type: ident with $len: tt as len),+) => {
        $(
            impl_did_action!($type with $len as len);
        )+
    };
}
