use codec::{Decode, Encode};
use sp_std::fmt;

// XXX: This could have been a tuple struct. Keeping it a normal struct for Substrate UI
/// A wrapper over 32-byte array
#[derive(Encode, Decode, Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Bytes32 {
    pub value: [u8; 32],
}

impl Bytes32 {
    pub fn as_bytes(&self) -> &[u8] {
        &self.value
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
        #[derive(Encode, Decode, Clone)]
        #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
        pub struct $name {
            #[cfg_attr(feature = "serde", serde(with = "BigArray"))]
            pub value: [u8; $size],
        }

        /// Implementing Default as it cannot be automatically derived for arrays of size > 32
        impl Default for $name {
            fn default() -> Self {
                Self { value: [0; $size] }
            }
        }

        /// Implementing Debug as it cannot be automatically derived for arrays of size > 32
        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                self.value[..].fmt(f)
            }
        }

        /// Implementing PartialEq as it cannot be automatically derived for arrays of size > 32
        impl PartialEq for $name {
            fn eq(&self, other: &Self) -> bool {
                self.value[..] == other.value[..]
            }
        }

        impl Eq for $name {}

        impl $name {
            /// Return a slice to the underlying bytearray
            pub fn as_bytes(&self) -> &[u8] {
                &self.value
            }
        }
    };
}

struct_over_byte_array!(Bytes33, 33);
struct_over_byte_array!(Bytes64, 64);
struct_over_byte_array!(Bytes65, 65);

/*#[derive(Encode, Decode, Debug, Clone, PartialEq, Eq)]
pub struct Bytes32(pub [u8;32]);*/
