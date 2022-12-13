use codec::{Decode, Encode};

/// An incremental identifier.
#[derive(Encode, Decode, Debug, Clone, PartialEq, Eq, Copy, Default, Ord, PartialOrd, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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

impl From<u32> for IncId {
    fn from(val: u32) -> IncId {
        IncId(val)
    }
}

impl From<u16> for IncId {
    fn from(val: u16) -> IncId {
        IncId(val.into())
    }
}

impl From<u8> for IncId {
    fn from(val: u8) -> IncId {
        IncId(val.into())
    }
}
