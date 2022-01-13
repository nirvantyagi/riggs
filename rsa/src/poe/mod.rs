//! Implements Wesolowski's Proof of Exponentiation

use crate::{
    bigint::BigInt,
    hog::{RsaGroupParams, RsaHiddenOrderGroup},
    poe::hash_to_prime::{
        check_pocklington_certificate, hash_to_pocklington_prime, PocklingtonCertificate,
    },
    Error,
};
use digest::Digest;

use num_integer::Integer;
use std::{fmt::Debug, marker::PhantomData};

pub mod hash_to_prime;

pub type Hog<P> = RsaHiddenOrderGroup<P>;

pub trait PoEParams: Clone {
    const HASH_TO_PRIME_ENTROPY: usize;
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PoE<P: PoEParams, RsaP: RsaGroupParams, D: Digest> {
    _params: PhantomData<P>,
    _rsa_params: PhantomData<RsaP>,
    _hash: PhantomData<D>,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Proof<P: RsaGroupParams, D: Digest> {
    pub q: Hog<P>,
    pub cert: PocklingtonCertificate<D>,
}

// v = u^{2^t}
impl<P: PoEParams, RsaP: RsaGroupParams, D: Digest> PoE<P, RsaP, D> {
    pub fn prove(u: &Hog<RsaP>, v: &Hog<RsaP>, t: u32) -> Result<Proof<RsaP, D>, Error> {
        // Hash to challenge
        let mut hash_input = vec![];
        hash_input.append(&mut u.n.to_bytes_le().1);
        hash_input.append(&mut v.n.to_bytes_le().1);
        hash_input.extend_from_slice(&t.to_le_bytes());
        let cert = hash_to_pocklington_prime::<D>(&hash_input, P::HASH_TO_PRIME_ENTROPY)?;
        let l = cert.result();

        // Compute quotient of exponent with challenge prime
        let q = BigInt::from(2).pow(t).div_floor(l);

        // Compute proof elements
        Ok(Proof {
            q: u.power(&q),
            cert,
        })
    }

    pub fn verify(
        u: &Hog<RsaP>,
        v: &Hog<RsaP>,
        t: u32,
        proof: &Proof<RsaP, D>,
    ) -> Result<bool, Error> {
        let mut hash_input = vec![];
        hash_input.append(&mut u.n.to_bytes_le().1);
        hash_input.append(&mut v.n.to_bytes_le().1);
        hash_input.extend_from_slice(&t.to_le_bytes());
        let b =
            check_pocklington_certificate::<D>(&hash_input, P::HASH_TO_PRIME_ENTROPY, &proof.cert)?;
        let l = proof.cert.result();
        let r = BigInt::from(2).modpow(&BigInt::from(t), l);

        // Verify proof
        Ok(b && v == &proof.q.power(l).op(&u.power(&r)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use once_cell::sync::Lazy;
    use sha3::Sha3_256;
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

    #[derive(Clone, PartialEq, Eq, Debug)]
    pub struct TestPoEParams;
    impl PoEParams for TestPoEParams {
        const HASH_TO_PRIME_ENTROPY: usize = 128;
    }

    pub type Hog = RsaHiddenOrderGroup<TestRsaParams>;
    pub type TestWesolowski = PoE<TestPoEParams, TestRsaParams, Sha3_256>;

    #[test]
    fn proof_of_exponentiation_test() {
        let u = Hog::from_nat(BigInt::from(20));
        let t = 40;
        let v = u.power(&BigInt::from(2).pow(t));

        let proof = TestWesolowski::prove(&u, &v, t).unwrap();
        let is_valid = TestWesolowski::verify(&u, &v, t, &proof).unwrap();
        assert!(is_valid);

        let is_valid = TestWesolowski::verify(&u, &v, 30, &proof).unwrap();
        assert!(!is_valid);
    }
}
