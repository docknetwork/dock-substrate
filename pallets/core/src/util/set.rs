use codec::{Decode, Encode};
use frame_support::ensure;
use itertools::Itertools;
use sp_std::collections::btree_set::BTreeSet;

/// A data structure that holds up to two optional `BTreeSet` instances.
///
/// This structure allows for computing set operations (like intersection and union)
/// on potentially absent sets.
pub struct MaybeDoubleSet<V: Ord>(pub Option<BTreeSet<V>>, pub Option<BTreeSet<V>>);

impl<V: Ord + Clone> MaybeDoubleSet<V> {
    /// Computes the intersection of the two sets.
    ///
    /// # Returns
    ///
    /// - `Some(BTreeSet<V>)`: If either or both sets are present, returns a `BTreeSet`
    ///   containing the intersection of the sets.
    /// - `None`: If both sets are `None`.
    ///
    /// # Examples
    ///
    /// ```
    /// extern crate alloc;
    ///
    /// use alloc::collections::BTreeSet;
    /// use dock_core::util::MaybeDoubleSet;
    ///
    /// let set1: BTreeSet<i32> = [1, 2, 3].iter().cloned().collect();
    /// let set2: BTreeSet<i32> = [2, 3, 4].iter().cloned().collect();
    ///
    /// let maybe_set = MaybeDoubleSet(Some(set1), Some(set2));
    /// let intersection = maybe_set.intersection();
    /// assert_eq!(intersection, Some([2, 3].iter().cloned().collect()));
    /// ```
    pub fn intersection(self) -> Option<BTreeSet<V>> {
        let Self(first, second) = self;

        Some(match (first, second) {
            (Some(first), Some(second)) => first.intersection(&second).cloned().collect(),
            (Some(first), None) => first,
            (None, Some(second)) => second,
            (None, None) => None?,
        })
    }

    /// Computes the union of the two sets.
    ///
    /// # Returns
    ///
    /// - `Some(BTreeSet<V>)`: If either or both sets are present, returns a `BTreeSet`
    ///   containing the union of the sets.
    /// - `None`: If both sets are `None`.
    ///
    /// # Examples
    ///
    /// ```
    /// extern crate alloc;
    ///
    /// use alloc::collections::BTreeSet;
    /// use dock_core::util::MaybeDoubleSet;
    ///
    /// let set1: BTreeSet<i32> = [1, 2, 3].iter().cloned().collect();
    /// let set2: BTreeSet<i32> = [2, 3, 4].iter().cloned().collect();
    ///
    /// let maybe_set = MaybeDoubleSet(Some(set1), Some(set2));
    /// let union = maybe_set.union();
    /// assert_eq!(union, Some([1, 2, 3, 4].iter().cloned().collect()));
    /// ```
    pub fn union(self) -> Option<BTreeSet<V>> {
        let Self(first, second) = self;

        Some(match (first, second) {
            (Some(first), Some(second)) => first.union(&second).cloned().collect(),
            (Some(first), None) => first,
            (None, Some(second)) => second,
            (None, None) => None?,
        })
    }
}

/// Defines the rules for including items in a set.
#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[derive(scale_info_derive::TypeInfo)]
#[scale_info(omit_prefix)]
pub enum InclusionRule<V: Ord> {
    AnyOf(BTreeSet<V>),
    All(BTreeSet<V>),
}

/// An error indicating that the supplied item wasn't found.
#[derive(PartialEq, Eq, Debug, Clone, Copy)]
pub struct ItemNotFound;

impl<V: Ord> InclusionRule<V> {
    /// Instantiates `Self::AnyOf` using supplied items.
    pub fn any_of(items: impl IntoIterator<Item = V>) -> Self {
        Self::AnyOf(BTreeSet::from_iter(items))
    }

    /// Instantiates `Self::ALl` using supplied items if size is greater than 1, otherwise returns `None`.
    pub fn all(items: impl IntoIterator<Item = V>) -> Option<Self> {
        let set = BTreeSet::from_iter(items);

        (!set.is_empty()).then_some(Self::All(set))
    }

    /// Checks if provided set satisfies the inclusion rule.
    pub fn satisfies(&self, to_check: &BTreeSet<V>) -> bool {
        match self {
            Self::AnyOf(values) => !values.is_disjoint(to_check),
            Self::All(values) => values.is_subset(to_check),
        }
    }

    /// Checks if the underlying rule values set contains supplied value.
    pub fn contains(&self, value: &V) -> bool {
        match self {
            Self::AnyOf(values) => values.contains(value),
            Self::All(values) => values.contains(value),
        }
    }

    /// Excludes supplied value and returns resulting inclusion rule.
    pub fn exclude(self, value: &V) -> Result<Option<Self>, ItemNotFound> {
        ensure!(self.contains(value), ItemNotFound);

        let next = match self {
            Self::AnyOf(_) => None,
            Self::All(mut values) => {
                values.remove(value);

                (!values.is_empty()).then_some(Self::All(values))
            }
        };

        Ok(next)
    }

    /// Applies the specified inclusion rule to a set of items.
    ///
    /// This method processes the items according to the inclusion criteria defined by the rule (`AnyOf` or `All`).
    /// It transforms the items using the provided function `f` and collects them into a `BTreeSet`.
    ///
    pub fn apply_rule<I, F>(self, f: F) -> BTreeSet<I::Item>
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
