use codec::{Decode, Encode};
use frame_support::ensure;
use itertools::Itertools;
use sp_std::collections::btree_set::BTreeSet;

#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[derive(scale_info_derive::TypeInfo)]
#[scale_info(omit_prefix)]
pub enum AnyOfOrAll<V: Ord> {
    AnyOf(BTreeSet<V>),
    All(BTreeSet<V>),
}

#[derive(PartialEq, Eq, Debug, Clone, Copy)]
pub struct ItemNotFound;

impl<V: Ord> AnyOfOrAll<V> {
    pub fn any_of(items: impl IntoIterator<Item = V>) -> Self {
        Self::AnyOf(BTreeSet::from_iter(items))
    }

    pub fn all(items: impl IntoIterator<Item = V>) -> Option<Self> {
        let set = BTreeSet::from_iter(items);

        (!set.is_empty()).then_some(Self::All(set))
    }

    pub fn satisfies(&self, check: &BTreeSet<V>) -> bool {
        match self {
            Self::AnyOf(values) => !values.is_disjoint(check),
            Self::All(values) => values.is_subset(check),
        }
    }

    pub fn contains(&self, value: &V) -> bool {
        match self {
            Self::AnyOf(values) => values.contains(value),
            Self::All(values) => values.contains(value),
        }
    }

    pub fn exclude(self, value: &V) -> Result<Option<Self>, ItemNotFound> {
        ensure!(self.contains(value), ItemNotFound);

        let set = match self {
            Self::AnyOf(_) => None,
            Self::All(mut values) => {
                values.remove(value);

                if values.is_empty() {
                    None
                } else {
                    Some(Self::All(values))
                }
            }
        };

        Ok(set)
    }

    pub fn transform_by_applying_rule<I, F>(self, f: F) -> BTreeSet<I::Item>
    where
        F: FnMut(V) -> I,
        I: IntoIterator,
        I::Item: Ord,
    {
        match self {
            Self::AnyOf(items) => items.into_iter().flat_map(f).collect(),
            Self::All(items) => {
                let len = items.len();

                items
                    .into_iter()
                    .map(f)
                    .kmerge()
                    .dedup_with_count()
                    .filter_map(|(count, value)| (count == len).then_some(value))
                    .collect()
            }
        }
    }
}
