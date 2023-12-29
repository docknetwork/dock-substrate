pub trait OptionExt<V> {
    fn update_with<S, F, R>(&mut self, f: F) -> R
    where
        F: FnOnce(&mut Option<S>) -> R,
        V: TryInto<S>,
        S: TryInto<V>;

    fn initialized(&mut self) -> &mut Self
    where
        V: Default;
}

impl<V> OptionExt<V> for Option<V> {
    fn update_with<S, F, R>(&mut self, f: F) -> R
    where
        F: FnOnce(&mut Option<S>) -> R,
        V: TryInto<S>,
        S: TryInto<V>,
    {
        let mut entity = self.take().map(TryInto::try_into).and_then(Result::ok);

        let res = f(&mut entity);

        *self = entity.map(TryInto::try_into).and_then(Result::ok);

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
