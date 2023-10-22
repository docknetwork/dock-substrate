pub trait OptionExt<V> {
    fn update_with<S, F, R>(&mut self, f: F) -> R
    where
        F: FnOnce(&mut Option<S>) -> R,
        V: TryInto<S>,
        S: Into<V>;

    fn initialized(&mut self) -> &mut Self
    where
        V: Default;
}

impl<V> OptionExt<V> for Option<V> {
    fn update_with<S, F, R>(&mut self, f: F) -> R
    where
        F: FnOnce(&mut Option<S>) -> R,
        V: TryInto<S>,
        S: Into<V>,
    {
        let mut entity = self.take().and_then(|opt| opt.try_into().ok());

        let res = f(&mut entity);

        *self = entity.map(Into::into);

        res
    }

    fn initialized(&mut self) -> &mut Self
    where
        V: Default,
    {
        if self.is_none() {
            self.replace(Default::default());
        }

        self
    }
}
