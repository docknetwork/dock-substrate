use crate::impl_wrapper_from_type_conversion;
use codec::{Decode, Encode};

/// An incremental identifier.
#[derive(Encode, Decode, Debug, Clone, PartialEq, Eq, Copy, Default, Ord, PartialOrd, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(scale_info_derive::TypeInfo)]
#[scale_info(omit_prefix)]
pub struct IncId(u32);

impl Iterator for &'_ mut IncId {
    type Item = IncId;

    fn next(&mut self) -> Option<Self::Item> {
        Some(*self.inc())
    }
}

impl IncId {
    /// Creates new `IncId` equal to zero.
    pub fn new() -> Self {
        Self::default()
    }

    /// Increases `IncId` value returning next sequential identifier.
    pub fn inc(&mut self) -> &mut Self {
        self.0 += 1;
        self
    }
}

impl_wrapper_from_type_conversion! { IncId: u8, u16, u32 }
