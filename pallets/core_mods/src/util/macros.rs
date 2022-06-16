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
macro_rules! impl_action {
    ($type: ident for $target: ty: with $len: ident as len, () as target) => {

        impl<T: frame_system::Config> $crate::Action<T> for $type<T> {
            type Target = $target;

            fn target(&self) -> $target {
                ()
            }

            fn len(&self) -> u32 {
                self.$len.len() as u32
            }

            fn to_state_change(&self) -> $crate::StateChange<'_, T> {
                $crate::StateChange::$type(sp_std::borrow::Cow::Borrowed(self))
            }

            fn into_state_change(self) -> $crate::StateChange<'static, T> {
                $crate::StateChange::$type(sp_std::borrow::Cow::Owned(self))
            }
        }
    };
    ($type: ident for $target: ty: with { $len: expr } as len, () as target) => {

        impl<T: frame_system::Config> $crate::Action<T> for $type<T> {
            type Target = $target;

            fn target(&self) -> $target {
                ()
            }

            fn len(&self) -> u32 {
                $len(self)
            }

            fn to_state_change(&self) -> $crate::StateChange<'_, T> {
                $crate::StateChange::$type(sp_std::borrow::Cow::Borrowed(self))
            }

            fn into_state_change(self) -> $crate::StateChange<'static, T> {
                $crate::StateChange::$type(sp_std::borrow::Cow::Owned(self))
            }
        }
    };
    ($type: ident for $target: ty: with $len: ident as len, $target_field: ident as target) => {

        impl<T: frame_system::Config> $crate::Action<T> for $type<T> {
            type Target = $target;

            fn target(&self) -> $target {
                self.$target_field
            }

            fn len(&self) -> u32 {
                self.$len.len() as u32
            }

            fn to_state_change(&self) -> $crate::StateChange<'_, T> {
                $crate::StateChange::$type(sp_std::borrow::Cow::Borrowed(self))
            }

            fn into_state_change(self) -> $crate::StateChange<'static, T> {
                $crate::StateChange::$type(sp_std::borrow::Cow::Owned(self))
            }
        }
    };
    ($type: ident for $target: ty: with { $len: expr } as len, $target_field: ident as target) => {

        impl<T: frame_system::Config> $crate::Action<T> for $type<T> {
            type Target = $target;

            fn target(&self) -> Self::Target {
                self.$target_field
            }

            fn len(&self) -> u32 {
                $len(self)
            }

            fn to_state_change(&self) -> $crate::StateChange<'_, T> {
                $crate::StateChange::$type(sp_std::borrow::Cow::Borrowed(self))
            }

            fn into_state_change(self) -> $crate::StateChange<'static, T> {
                $crate::StateChange::$type(sp_std::borrow::Cow::Owned(self))
            }
        }
    };
    (for $target: ty: $($type: ident with $len: tt as len, $target_field: tt as target),+) => {
        $(
            $crate::impl_action! { $type for $target: with $len as len, $target_field as target }
        )+
    };
}

#[macro_export]
macro_rules! impl_nonced_action {
    ($type: ident for $($token: tt)*) => {
        $crate::impl_action! { $type for $($token)* }

        impl<T: frame_system::Config> $crate::WithNonceAction<T> for $type<T> {
            fn nonce(&self) -> T::BlockNumber {
                self.nonce
            }
        }
    };
    (for $target: ty: $($type: ident with $len: tt as len, $target_field: tt as target),+) => {
        $(
            $crate::impl_nonced_action! { $type for $target: with $len as len, $target_field as target }
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
    ($wrapper: ident, $type: ty) => {
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
