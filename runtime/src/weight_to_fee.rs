use frame_support::weights::{
    WeightToFeeCoefficient, WeightToFeeCoefficients, WeightToFeePolynomial,
};
use smallvec::smallvec;
use sp_arithmetic::{
    traits::{BaseArithmetic, Unsigned},
    Perbill,
};

/// Implementor of `WeightToFeePolynomial` that maps weight to fee. The fee would be 0.5% of the weight, 5 million parts per billion
pub struct TxnFee<T>(sp_std::marker::PhantomData<T>);

impl<T> WeightToFeePolynomial for TxnFee<T>
where
    T: BaseArithmetic + From<u32> + Copy + Unsigned,
{
    type Balance = T;

    /// Degree 1 polynomial as 0.005 * x
    fn polynomial() -> WeightToFeeCoefficients<Self::Balance> {
        smallvec!(WeightToFeeCoefficient {
            coeff_integer: 0u32.into(),
            // 5 million parts per billion
            coeff_frac: Perbill::from_parts(5000000),
            negative: false,
            degree: 1,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::TxnFee;
    use frame_support::weights::WeightToFee;
    type Balance = u64;

    #[test]
    fn fee_works() {
        assert_eq!(TxnFee::<Balance>::weight_to_fee(&0), 0);
        assert_eq!(TxnFee::<Balance>::weight_to_fee(&400), 2);
        assert_eq!(TxnFee::<Balance>::weight_to_fee(&500), 2);
        assert_eq!(TxnFee::<Balance>::weight_to_fee(&600), 3);
        assert_eq!(TxnFee::<Balance>::weight_to_fee(&1000), 5);
        assert_eq!(TxnFee::<Balance>::weight_to_fee(&2000), 10);
        assert_eq!(TxnFee::<Balance>::weight_to_fee(&10000), 50);
        assert_eq!(TxnFee::<Balance>::weight_to_fee(&20000), 100);
    }
}
