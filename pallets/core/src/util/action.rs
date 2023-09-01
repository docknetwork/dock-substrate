/// Describes an action which can be performed on some `Target`.
pub trait Action<T: frame_system::Config> {
    /// Action target.
    type Target;

    /// Returns underlying action target.
    fn target(&self) -> Self::Target;

    /// Returns action unit length.
    fn len(&self) -> u32;

    /// Returns `true` if the action unit count is equal to zero.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Describes an action with nonce which can be performed on some `Target`
pub trait ActionWithNonce<T: frame_system::Config>: Action<T> {
    /// Returns action's nonce.
    fn nonce(&self) -> T::BlockNumber;
}
