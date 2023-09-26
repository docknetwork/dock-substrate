use crate::impl_wrapper;
#[cfg(feature = "serde")]
use crate::util::hex;
use codec::{Decode, Encode, MaxEncodedLen};
use core::ops::{Index, RangeFull};
use frame_support::*;
use sp_runtime::traits::Get;

use sp_std::{fmt, vec::Vec};

/// Wrapper around the bounded vector. providing the ability to encode/decode in `hex` format.
#[derive(
    Encode,
    Decode,
    DebugNoBound,
    CloneNoBound,
    PartialEqNoBound,
    EqNoBound,
    DefaultNoBound,
    PartialOrd,
    Ord,
    MaxEncodedLen,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(bound(serialize = "MaxSize: Sized", deserialize = "MaxSize: Sized"))
)]
#[derive(scale_info_derive::TypeInfo)]
#[scale_info(skip_type_params(MaxSize))]
#[scale_info(omit_prefix)]
pub struct BoundedBytes<MaxSize: Get<u32>>(
    #[cfg_attr(feature = "serde", serde(with = "hex"))] pub BoundedVec<u8, MaxSize>,
);

crate::impl_wrapper!(BoundedBytes<MaxSize: Get<u32>>(BoundedVec<u8, MaxSize>));

impl<MaxSize: Get<u32>> TryFrom<Vec<u8>> for BoundedBytes<MaxSize> {
    type Error = ();

    fn try_from(bytes: Vec<u8>) -> Result<Self, ()> {
        TryFrom::try_from(bytes).map(Self)
    }
}

/// Wrapper around raw bytes vector providing the ability to encode/decode in `hex` format.
#[derive(Encode, Decode, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(scale_info_derive::TypeInfo)]
#[scale_info(omit_prefix)]
pub struct Bytes(#[cfg_attr(feature = "serde", serde(with = "hex"))] pub Vec<u8>);

impl FromIterator<u8> for Bytes {
    fn from_iter<I: IntoIterator<Item = u8>>(iter: I) -> Bytes {
        Bytes(Vec::from_iter(iter))
    }
}

#[cfg(test)]
use rand::distributions::Distribution;
impl_wrapper! { Bytes(Vec<u8>), for rand use rand::distributions::Standard.sample_iter(&mut rand::thread_rng()).take(32).collect(), with tests as wrapped_bytes_tests }

// XXX: This could have been a tuple struct. Keeping it a normal struct for Substrate UI
/// A wrapper over 32-byte array
#[derive(Encode, Decode, Debug, Clone, PartialEq, Eq, Ord, Copy, PartialOrd, MaxEncodedLen)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(scale_info_derive::TypeInfo)]
#[scale_info(omit_prefix)]
pub struct Bytes32(#[cfg_attr(feature = "serde", serde(with = "hex"))] pub [u8; 32]);

crate::impl_wrapper! { Bytes32([u8; 32]) }

impl Index<RangeFull> for Bytes32 {
    type Output = [u8; 32];

    fn index(&self, _: RangeFull) -> &Self::Output {
        &self.0
    }
}

#[cfg(feature = "serde")]
serde_big_array::big_array! {
    BigArray;
    33, 64, 65
}

// XXX: These could have been a tuple structs. Keeping them normal struct for Substrate UI
/// Creates a struct named `$name` which contains only 1 element which is a bytearray, useful when
/// wrapping arrays of size > 32. `$size` is the size of the underlying bytearray. Implements the `Default`,
/// `sp_std::fmt::Debug`, `PartialEq` and `Eq` trait as they will not be automatically implemented for arrays of size > 32.
macro_rules! struct_over_byte_array {
    ( $name:ident, $size:tt ) => {
        /// A wrapper over a byte array
        #[derive(
            Encode, Decode, Clone, Copy, PartialOrd, Ord, scale_info_derive::TypeInfo, MaxEncodedLen,
        )]
        #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
        #[scale_info(omit_prefix)]
        pub struct $name(
            #[cfg_attr(feature = "serde", serde(with = "hex::big_array"))]
            pub [u8; $size]
        );

        $crate::impl_wrapper! { $name([u8; $size]) }

        /// Implementing Default as it cannot be automatically derived for arrays of size > 32
        impl Default for $name {
            fn default() -> Self {
                Self([0; $size])
            }
        }

        impl Index<RangeFull> for $name {
            type Output = [u8; $size];

            fn index(&self, _: RangeFull) -> &Self::Output {
                &self.0
            }
        }

        /// Implementing Debug as it cannot be automatically derived for arrays of size > 32
        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                self.0[..].fmt(f)
            }
        }

        /// Implementing PartialEq as it cannot be automatically derived for arrays of size > 32
        impl PartialEq for $name {
            fn eq(&self, other: &Self) -> bool {
                self.0[..] == other.0[..]
            }
        }

        impl Eq for $name {}

        impl $name {
            /// Return a slice to the underlying bytearray
            pub fn as_bytes(&self) -> &[u8] {
                &self.0
            }
        }
    };
}

struct_over_byte_array!(Bytes33, 33);
struct_over_byte_array!(Bytes64, 64);
struct_over_byte_array!(Bytes65, 65);
