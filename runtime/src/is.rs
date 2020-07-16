/// If any type T implements Is<S>, then T = S.
pub trait Is<T>: private::Sealed<T>
where
    Self: From<T>,
    T: From<T>,
{
    fn into_is(self) -> T;
    fn from_is(other: T) -> Self;
    fn into_ref_is(&self) -> &T;
    fn from_ref_is(other: &T) -> &Self;
}

impl<T> Is<T> for T {
    fn into_is(self) -> T {
        self
    }

    fn from_is(other: T) -> Self {
        other
    }

    fn into_ref_is(&self) -> &T {
        self
    }

    fn from_ref_is(other: &T) -> &Self {
        other
    }
}

mod private {
    pub trait Sealed<T> {}
    impl<T> Sealed<T> for T {}
}
