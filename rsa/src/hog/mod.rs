use crate::bigint::{
    BigInt,
    extended_euclidean_gcd,
};

use once_cell::sync::Lazy;
use num_traits::{One, Signed, Zero};
use std::{
    hash::{Hash, Hasher},
    error::Error as ErrorTrait,
    marker::PhantomData,
    cmp::min,
    fmt::{self, Debug},
    ops::Deref,
};

use crate::Error;

//pub mod constraints;

//TODO: https://github.com/rust-num/num-bigint/issues/181
pub trait RsaGroupParams: Clone + Eq + Debug + Send + Sync {
    const G: Lazy<BigInt>;
    const M: Lazy<BigInt>;
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RsaHiddenOrderGroup<P: RsaGroupParams> {
    pub n: BigInt,
    _params: PhantomData<P>,
}

impl<P: RsaGroupParams> Default for RsaHiddenOrderGroup<P> {
    fn default() -> Self {
        Self::from_nat(BigInt::from(2))
    }
}

impl<P: RsaGroupParams> Hash for RsaHiddenOrderGroup<P> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.n.hash(state)
    }
}

impl<P: RsaGroupParams> RsaHiddenOrderGroup<P> {
    pub fn from_nat(n: BigInt) -> Self {
        let mut a = n;
        assert!(a > BigInt::zero());
        a %= P::M.deref();
        let mut ma = P::M.deref().clone();
        ma -= &a;
        RsaHiddenOrderGroup{ n: min(a, ma), _params: PhantomData }
    }

    pub fn op(&self, other: &Self) -> Self {
        let mut a = self.n.clone();
        a *= &other.n;
        a %= P::M.deref();
        let mut ma = P::M.deref().clone();
        ma -= &a;
        RsaHiddenOrderGroup{ n: min(a, ma), _params: PhantomData }
    }

    pub fn identity() -> Self {
        RsaHiddenOrderGroup{ n: BigInt::one(), _params: PhantomData }
    }

    pub fn generator() -> Self {
        RsaHiddenOrderGroup{ n: P::G.deref().clone(), _params: PhantomData }
    }

    pub fn power(&self, e: &BigInt) -> Self {
        let r = self.n.modpow(e, P::M.deref());
        let mut mr = P::M.deref().clone();
        mr -= &r;
        RsaHiddenOrderGroup{ n: min(r, mr), _params: PhantomData }
    }

    //TODO: Optimization for only calculating needed Bezout coefficient
    pub fn inverse(&self) -> Result<Self, Error> {
        let ((mut inv, _), gcd) = extended_euclidean_gcd(&self.n, P::M.deref());
        if gcd.abs() > BigInt::one() {
            return Err(Box::new(RsaHOGError::NotInvertible))
        }
        if inv < BigInt::zero() {
            inv += P::M.deref();
        }
        Ok(Self::from_nat(inv))
    }
}

#[derive(Debug)]
pub enum RsaHOGError {
    NotInvertible,
}

impl ErrorTrait for RsaHOGError {
    fn source(self: &Self) -> Option<&(dyn ErrorTrait + 'static)> {
        None
    }
}

impl fmt::Display for RsaHOGError {
    fn fmt(self: &Self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            RsaHOGError::NotInvertible => format!("Group element not invertible"),
        };
        write!(f, "{}", msg)
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[derive(Clone, PartialEq, Eq, Debug)]
    pub struct TestRsaParams;

    impl RsaGroupParams for TestRsaParams {
        const G: Lazy<BigInt> = Lazy::new(|| BigInt::from(2));
        const M: Lazy<BigInt> = Lazy::new(|| {
            BigInt::from_str("2519590847565789349402718324004839857142928212620403202777713783604366202070\
                          7595556264018525880784406918290641249515082189298559149176184502808489120072\
                          8449926873928072877767359714183472702618963750149718246911650776133798590957\
                          0009733045974880842840179742910064245869181719511874612151517265463228221686\
                          9987549182422433637259085141865462043576798423387184774447920739934236584823\
                          8242811981638150106748104516603773060562016196762561338441436038339044149526\
                          3443219011465754445417842402092461651572335077870774981712577246796292638635\
                          6373289912154831438167899885040445364023527381951378636564391212010397122822\
                          120720357").unwrap()
        });
    }

    pub type Hog = RsaHiddenOrderGroup<TestRsaParams>;

    #[test]
    fn inverse_test() {
        let a = Hog::from_nat(BigInt::from(30));
        let inv_a = a.inverse().unwrap();
        assert_eq!(a.op(&inv_a).n, BigInt::from(1));

        let a = Hog::from_nat(BigInt::from(-30) + TestRsaParams::M.deref());
        let inv_a = a.inverse().unwrap();
        assert_eq!(a.op(&inv_a).n, BigInt::from(1));
    }

}
