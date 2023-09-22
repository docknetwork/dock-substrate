pub mod keys;
pub mod limits;
pub mod policy;
pub mod signatures;
pub mod state_change;
pub mod storage_version;
pub mod types;

pub use keys::*;
pub use limits::*;
pub use policy::*;
pub use signatures::*;
pub use state_change::*;
pub use storage_version::*;
pub use types::*;

/// All associated types and size limits for the encodable data structures used by the `dock-core`.
pub trait TypesAndLimits: Types + Limits {}
impl<T: Types + Limits> TypesAndLimits for T {}
