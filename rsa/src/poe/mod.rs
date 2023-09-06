//! Implements Wesolowski's Proof of Exponentiation
use crate::{
    bigint::{extended_euclidean_gcd, BigInt},
    hash_to_prime::HashToPrime,
    hog::{RsaGroupParams, RsaHiddenOrderGroup},
    Error,
};
use num_traits::{One, Zero};
use std::io::{self, Write};

use num_integer::Integer;
use std::{fmt::Debug, marker::PhantomData};

pub type Hog<P> = RsaHiddenOrderGroup<P>;

pub trait PoEParams: Clone + Eq + Debug {
    const HASH_TO_PRIME_ENTROPY: usize;
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PoE<P: PoEParams, RsaP: RsaGroupParams, H: HashToPrime> {
    _params: PhantomData<P>,
    _rsa_params: PhantomData<RsaP>,
    _hash: PhantomData<H>,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Proof<P: RsaGroupParams, H: HashToPrime> {
    pub q: Hog<P>,
    pub l: BigInt,
    pub cert: H::Certificate,
}

// v = u^{2^t}
impl<P: PoEParams, RsaP: RsaGroupParams, H: HashToPrime> PoE<P, RsaP, H> {
    pub fn prove(u: &Hog<RsaP>, v: &Hog<RsaP>, t: u64) -> Result<Proof<RsaP, H>, Error> {
        // Hash to challenge
        let mut hash_input = vec![];
        hash_input.append(&mut pad_to_32_byte_offset(u.n.to_bytes_be().1));
        hash_input.append(&mut pad_to_32_byte_offset(v.n.to_bytes_be().1));
        hash_input.extend_from_slice(&t.to_be_bytes());
        let (l, cert) = H::hash_to_prime(P::HASH_TO_PRIME_ENTROPY, &hash_input)?;

        // Compute quotient of exponent with challenge prime
        let q = BigInt::from(2).pow(t as u32).div_floor(&l);

        // Compute proof elements
        Ok(Proof {
            q: u.power(&q),
            l,
            cert,
        })
    }

    pub fn prove_cheating(
        u: &Hog<RsaP>,
        v: &Hog<RsaP>,
        t: u64,
        order: &BigInt,
    ) -> Result<Proof<RsaP, H>, Error> {
        // Hash to challenge
        let mut hash_input = vec![];
        hash_input.append(&mut pad_to_32_byte_offset(u.n.to_bytes_be().1));
        hash_input.append(&mut pad_to_32_byte_offset(v.n.to_bytes_be().1));
        hash_input.extend_from_slice(&t.to_be_bytes());

        let (l, cert) = H::hash_to_prime(P::HASH_TO_PRIME_ENTROPY, &hash_input)?;

        // Compute quotient of exponent with challenge prime
        //let q = BigInt::from(2).pow(t).div_floor(&l);

        let q = (BigInt::one() << t).div_floor(&l).mod_floor(order);

        //let (_, q) = (BigInt::from(2).pow(t).div_floor(&l)).div_rem(&order);

        // Compute proof elements
        Ok(Proof {
            q: u.power(&q),
            l,
            cert,
        })
    }

    pub fn verify(
        u: &Hog<RsaP>,
        v: &Hog<RsaP>,
        t: u64,
        proof: &Proof<RsaP, H>,
    ) -> Result<bool, Error> {
        let mut hash_input = vec![];
        hash_input.append(&mut pad_to_32_byte_offset(u.n.to_bytes_be().1));
        hash_input.append(&mut pad_to_32_byte_offset(v.n.to_bytes_be().1));
        hash_input.extend_from_slice(&t.to_be_bytes());
        let b =
            H::verify_hash_to_prime(P::HASH_TO_PRIME_ENTROPY, &hash_input, &proof.l, &proof.cert)?;
        let r = BigInt::from(2).modpow(&BigInt::from(t), &proof.l);

        // Verify proof
        Ok(b && v == &proof.q.power(&proof.l).op(&u.power(&r)))
    }
}

// Needed to match solidity functionality
fn pad_to_32_byte_offset(mut bytes: Vec<u8>) -> Vec<u8> {
    let pad_len = 32 * ((bytes.len() - 1) / 32 + 1);
    bytes.reverse();
    bytes.resize(pad_len, 0);
    debug_assert_eq!(bytes.len() % 32, 0);
    bytes.reverse();
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;
    use once_cell::sync::Lazy;
    use sha3::Sha3_256;
    use std::str::FromStr;

    use crate::hash_to_prime::pocklington::{PocklingtonCertParams, PocklingtonHash};

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

    #[derive(Clone, PartialEq, Eq, Debug)]
    pub struct TestPocklingtonParams;
    impl PocklingtonCertParams for TestPocklingtonParams {
        const NONCE_SIZE: usize = 16;
        const MAX_STEPS: usize = 5;
        const INCLUDE_SOLIDITY_WITNESSES: bool = false;
    }

    pub type Hog = RsaHiddenOrderGroup<TestRsaParams>;
    pub type TestWesolowski =
        PoE<TestPoEParams, TestRsaParams, PocklingtonHash<TestPocklingtonParams, Sha3_256>>;

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
