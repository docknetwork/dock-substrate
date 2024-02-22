use frame_support::{traits::Get, weights::RuntimeDbWeight};

pub struct ZeroDbWeight;

impl ZeroDbWeight {
    pub const WEIGHT: RuntimeDbWeight = RuntimeDbWeight { read: 0, write: 0 };
}

impl Get<RuntimeDbWeight> for ZeroDbWeight {
    fn get() -> RuntimeDbWeight {
        Self::WEIGHT
    }
}
