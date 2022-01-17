use ark_ff::fields::{FpParameters, PrimeField};
use num_bigint::BigInt as NumBigInt;
use num_integer::{ExtendedGcd, Integer};

use std::{
    borrow::Borrow,
    convert::TryInto,
    error::Error as ErrorTrait,
    fmt::{self, Debug},
};
use num_traits::Signed;
use tracing::debug;

use crate::Error;

pub mod constraints;
pub type BigInt = NumBigInt;

pub fn extended_euclidean_gcd(a: &BigInt, b: &BigInt) -> ((BigInt, BigInt), BigInt) {
    let ExtendedGcd { gcd, x, y, .. } = a.extended_gcd(b);
    ((x, y), gcd)
}

/// Convert a field element to a natural number
pub fn f_to_nat<F: PrimeField>(f: &F) -> BigInt {
    BigInt::from(f.into_repr().into())
}

/// Convert a natural number to a field element.
pub fn nat_to_f<F: PrimeField>(n: &BigInt) -> Result<F, Error> {
    let bit_capacity = <F::Params as FpParameters>::CAPACITY as usize;
    F::from_repr(
        n.to_biguint()
            .ok_or(Box::new(BigIntError::Negative))?
            .try_into()
            .or(Err(Box::new(BigIntError::Conversion(1, bit_capacity))))?,
    )
    .ok_or(Box::new(BigIntError::Conversion(1, bit_capacity)))
}

/// Compute the natural number represented by an array of limbs.
/// The limbs are assumed to be based the `limb_width` power of 2.
pub fn limbs_to_nat<F: PrimeField>(limbs: &Vec<F>, limb_width: usize) -> BigInt {
    limbs.iter().rev().fold(BigInt::from(0), |mut acc, limb| {
        acc <<= limb_width as u32;
        acc += f_to_nat(limb.borrow());
        acc
    })
}

/// Compute the limbs encoding a natural number.
/// The limbs are assumed to be based the `limb_width` power of 2.
pub fn nat_to_limbs<'a, F: PrimeField>(
    nat: &BigInt,
    limb_width: usize,
    n_limbs: usize,
) -> Result<Vec<F>, Error> {
    assert!(!nat.is_negative());
    assert!(limb_width <= <F::Params as FpParameters>::CAPACITY as usize);
    let mask = int_with_n_ones(limb_width);
    let mut nat = nat.clone();
    if nat.bits() as usize <= n_limbs * limb_width {
        Ok((0..n_limbs)
            .map(|_| {
                let r = &nat & &mask;
                nat >>= limb_width as u32;
                nat_to_f(&r).unwrap()
            })
            .collect())
    } else {
        debug!(
            nat_bits = nat.bits(),
            n_limbs = n_limbs,
            limb_width = limb_width,
            "nat does not fit in limbs"
        );
        Err(Box::new(BigIntError::Conversion(n_limbs, limb_width)))
    }
}

// Fits a natural number to the minimum number limbs of given width
pub fn fit_nat_to_limbs<F: PrimeField>(n: &BigInt, limb_width: usize) -> Result<Vec<F>, Error> {
    nat_to_limbs(n, limb_width, n.bits() as usize / limb_width + 1)
}

// Fits a natural number to the minimum number limbs
pub fn fit_nat_to_limb_capacity<F: PrimeField>(n: &BigInt) -> Result<Vec<F>, Error> {
    let bit_capacity = <F::Params as FpParameters>::CAPACITY as usize;
    nat_to_limbs(n, bit_capacity, n.bits() as usize / bit_capacity + 1)
}

fn int_with_n_ones(n: usize) -> BigInt {
    let mut m = BigInt::from(1);
    m <<= n as u32;
    m -= 1;
    m
}

#[derive(Debug)]
pub enum BigIntError {
    Conversion(usize, usize),
    Negative,
}

impl ErrorTrait for BigIntError {
    fn source(self: &Self) -> Option<&(dyn ErrorTrait + 'static)> {
        None
    }
}

impl fmt::Display for BigIntError {
    fn fmt(self: &Self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            BigIntError::Conversion(n_limbs, limb_width) => format!(
                "Integer does not fit in {} limbs of width {}",
                n_limbs, limb_width
            ),
            BigIntError::Negative => format!("Expected non-negative integer"),
        };
        write!(f, "{}", msg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ed_on_bls12_381::Fq;
    use ark_ff::UniformRand;
    use rand::{rngs::StdRng, SeedableRng};
    use std::str::FromStr;

    const RSA_MODULO: &str = "2519590847565789349402718324004839857142928212620403202777713783604366202070\
                          7595556264018525880784406918290641249515082189298559149176184502808489120072\
                          8449926873928072877767359714183472702618963750149718246911650776133798590957\
                          0009733045974880842840179742910064245869181719511874612151517265463228221686\
                          9987549182422433637259085141865462043576798423387184774447920739934236584823\
                          8242811981638150106748104516603773060562016196762561338441436038339044149526\
                          3443219011465754445417842402092461651572335077870774981712577246796292638635\
                          6373289912154831438167899885040445364023527381951378636564391212010397122822\
                          120720357";

    #[test]
    fn convert_to_field_test() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let f = <Fq>::rand(&mut rng);
        let f2 = nat_to_f::<Fq>(&f_to_nat(&f)).unwrap();
        assert_eq!(f, f2);

        let m = BigInt::from_str(RSA_MODULO).unwrap();
        let bit_capacity = <<Fq as PrimeField>::Params as FpParameters>::CAPACITY as usize;
        let m2 = limbs_to_nat::<Fq>(
            &nat_to_limbs::<Fq>(&m, bit_capacity, m.bits() as usize / bit_capacity + 1).unwrap(),
            bit_capacity,
        );
        assert_eq!(m, m2);
    }
}
