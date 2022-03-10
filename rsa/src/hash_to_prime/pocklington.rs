use crate::{
    bigint::{BigInt, extended_euclidean_gcd},
    hash_to_prime::{
        HashToPrime,
        HashToPrimeError,
        hash_to_integer,
        miller_rabin,
        miller_rabin_32b,
    },
    Error,
};
use digest::Digest;
use num_integer::{Integer};
use num_traits::{One, Zero};
use std::{
    fmt::{Debug},
    marker::PhantomData,
};

use pari_factor::factor;

/// https://www-sop.inria.fr/members/Benjamin.Gregoire/Publi/pock.pdf
pub trait PocklingtonCertParams: Clone + Eq + Debug + Send + Sync {
    const NONCE_SIZE: usize;  // nonce size in bits
    const MAX_STEPS: usize;  // max number of pocklington steps in certificate
    const INCLUDE_SOLIDITY_WITNESSES: bool;  // flag to include witnesses for solidity verification
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PocklingtonHash<P: PocklingtonCertParams, D: Digest>{
    _params: PhantomData<P>,
    _hash: PhantomData<D>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StepCert{
    pub f: BigInt,
    pub n: u32,
    pub n2: u32,
    pub a: BigInt,
    pub bu: BigInt,
    pub bv: BigInt,
    pub v: Option<BigInt>,
    pub s: Option<BigInt>,
    pub expr_sqrt: Option<BigInt>,
    pub p_less_one_div_f: Option<BigInt>,
    pub p_less_one_div_two: Option<BigInt>,
    pub b_p_div_f1: Option<BigInt>,
    pub b_p_div_f2: Option<BigInt>,
    pub b_p_div_two1: Option<BigInt>,
    pub b_p_div_two2: Option<BigInt>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PocklingtonCert{
    pub step_certificates: Vec<StepCert>,
    pub nonce: u32,
}

impl<P: PocklingtonCertParams, D: Digest> HashToPrime for PocklingtonHash<P, D> {
    type Certificate = PocklingtonCert;

    fn hash_to_prime(entropy: usize, input: &[u8]) -> Result<(BigInt, Self::Certificate), Error> {
        let mut inputs: Vec<u8> = input.iter().copied().collect();
        inputs.extend_from_slice(&0u32.to_le_bytes()); // Dummy to be removed on first iter
        'nonce_loop: for nonce in 0..(1u32 << P::NONCE_SIZE) {
            inputs.truncate(inputs.len() - 4);
            inputs.extend_from_slice(&nonce.to_be_bytes());
            let p_candidate = hash_to_integer::<D>(&inputs, Self::prime_bits(entropy));
            if !miller_rabin(&p_candidate, 30) {
                continue 'nonce_loop;
            }
            match Self::generate_pocklington_certificate_path(&p_candidate) {
                Some(certs) => {
                    if certs.len() <= P::MAX_STEPS {
                        return Ok((p_candidate, PocklingtonCert{ step_certificates: certs, nonce }))
                    } else {
                        continue 'nonce_loop
                    }
                },
                None => continue 'nonce_loop,
            }
        }
        Err(Box::new(HashToPrimeError::NoValidNonce))
    }

    fn verify_hash_to_prime(entropy: usize, input: &[u8], p: &BigInt, cert: &Self::Certificate) -> Result<bool, Error> {
        let mut inputs: Vec<u8> = input.iter().copied().collect();
        inputs.extend_from_slice(&cert.nonce.to_be_bytes());
        let p_curr= hash_to_integer::<D>(&inputs, Self::prime_bits(entropy));
        let check1 = &p_curr == p;
        let p_path = vec![p_curr].iter().chain(cert.step_certificates.iter().map(|c| c.f.clone()).collect::<Vec<BigInt>>().iter()).cloned().collect::<Vec<BigInt>>();
        let check2 = cert.step_certificates.iter().zip(p_path.iter())
            .all(|(c, p)| Self::verify_pocklington_step(p, c));
        let p_last = p_path.last().unwrap();
        let check3 = p_last.bits() < 32 && miller_rabin_32b(&p_last);
        Ok(check1 && check2 && check3)
    }
}

impl<P: PocklingtonCertParams, D: Digest> PocklingtonHash<P, D> {
    fn prime_bits(entropy: usize) -> usize {
        let n_bits = ((entropy as f64) + (entropy as f64).ln()) as usize;
        // Size of prime needed if any nonce of valid length is allowed
        n_bits + P::NONCE_SIZE
    }

    fn generate_pocklington_certificate_path(p: &BigInt) -> Option<Vec<StepCert>> {
        let mut certs = Vec::new();
        let mut p = p.clone();
        //TODO: Support other small prime limits, e.g., 40 bits, 48 bits
        while p > BigInt::one() << 32 {
            let cert = Self::pocklington_step(&p)?;
            p = cert.f.clone();
            certs.push(cert);
        }
        Some(certs)
    }

    fn pocklington_step(p: &BigInt) -> Option<StepCert> {
        //TODO: gmp-ecm factor is faster than PARI
        //TODO: Instead of factor 280-bit integer, construct from 140-bit prime
        let factors = factor(&(p - BigInt::one()));
        debug_assert_eq!(factors[0].0, BigInt::from(2));
        let n2 = factors[0].1;
        let (f, n, u, v, s, expr_sqrt) = factors.iter().find_map(|(f, n)| Self::test_pocklington_f(p, f, *n, n2))?;
        let ((bu, bv), gcd) = extended_euclidean_gcd(&u, &v);
        debug_assert_eq!(gcd, BigInt::one());
        let (a, (p_less_one_div_f, p_less_one_div_two, b_p_div_f1, b_p_div_f2, b_p_div_two1, b_p_div_two2)) = {
            let mut out = None;
            let mut a_candidate = BigInt::from(2);
            while a_candidate < p - BigInt::one() {
                if let Some(solidity_witnesses) = Self::test_pocklington_a(p, &f, &a_candidate) {
                    out = Some((a_candidate.clone(), solidity_witnesses));
                    break;
                }
                a_candidate += BigInt::one();
            }
            out
        }?;
        Some(StepCert {
            f,n, n2, a, bu, bv,
            v: if P::INCLUDE_SOLIDITY_WITNESSES { Some(v) } else { None },
            s: if P::INCLUDE_SOLIDITY_WITNESSES { Some(s) } else { None },
            expr_sqrt: if P::INCLUDE_SOLIDITY_WITNESSES { Some(expr_sqrt) } else { None },
            p_less_one_div_f: if P::INCLUDE_SOLIDITY_WITNESSES { Some(p_less_one_div_f) } else { None },
            p_less_one_div_two: if P::INCLUDE_SOLIDITY_WITNESSES { Some(p_less_one_div_two) } else { None },
            b_p_div_f1: if P::INCLUDE_SOLIDITY_WITNESSES { Some(b_p_div_f1) } else { None },
            b_p_div_f2: if P::INCLUDE_SOLIDITY_WITNESSES { Some(b_p_div_f2) } else { None },
            b_p_div_two1: if P::INCLUDE_SOLIDITY_WITNESSES { Some(b_p_div_two1) } else { None },
            b_p_div_two2: if P::INCLUDE_SOLIDITY_WITNESSES { Some(b_p_div_two2) } else { None },
        })
    }

    fn verify_pocklington_step(p: &BigInt, cert: &StepCert) -> bool {
        match (Self::test_pocklington_f(p, &cert.f, cert.n, cert.n2), Self::test_pocklington_a(p, &cert.f, &cert.a)) {
            (Some((_, _, u, v, _, _)), Some(_)) => {
                let test_parity = u.is_even() && v.is_odd();
                let test_prod = &u * &v == p - BigInt::one();
                let test_coprime = &cert.bu * &u + &cert.bv * &v == BigInt::one();
                test_parity && test_prod && test_coprime
            },
            _ => false,
        }
    }

    fn test_pocklington_f(p: &BigInt, f: &BigInt, n: u32, n2: u32) -> Option<(BigInt, u32, BigInt, BigInt, BigInt, BigInt)> {
        let u = BigInt::from(2).pow(n2) * f.pow(n);
        let v = (p - BigInt::one()).div_floor(&u);
        let r = v.mod_floor(&(BigInt::from(2) * &u));
        let s = v.div_floor(&(BigInt::from(2) * &u));

        let expr = r.pow(2) - BigInt::from(8) * &s;
        let expr_sqrt = if expr >= BigInt::zero() { expr.sqrt() } else { BigInt::zero() };
        let test1 = &((&u + BigInt::one()) * (BigInt::from(2) * u.pow(2) + (&r - BigInt::one()) * &u + BigInt::one())) > p;
        let test2 = (s == BigInt::zero()) || (expr >= BigInt::zero() && !(expr_sqrt.pow(2) == expr));
        if test1 && test2 {
            Some((f.clone(), n, u, v, s, expr_sqrt))
        } else {
            None
        }
    }

    fn test_pocklington_a(p: &BigInt, f: &BigInt, a: &BigInt) -> Option<(BigInt, BigInt, BigInt, BigInt, BigInt, BigInt)> {
        let p_less_one = p - BigInt::one();
        let p_less_one_div_f = p_less_one.div_floor(f);
        let p_less_one_div_two = p_less_one.div_floor(&BigInt::from(2));
        let test1 = a.modpow(&p_less_one, p) == BigInt::one();
        let ((b_p_div_f1, b_p_div_f2), gcd_div_f) = extended_euclidean_gcd(&(a.modpow(&p_less_one_div_f, p) - BigInt::one()), p);
        let test2 = gcd_div_f == BigInt::one();
        let ((b_p_div_two1, b_p_div_two2), gcd_div_two) = extended_euclidean_gcd(&(a.modpow(&p_less_one_div_two, p) - BigInt::one()), p);
        let test3 = gcd_div_two == BigInt::one();
        if test1 && test2 && test3 {
            Some((p_less_one_div_f, p_less_one_div_two, b_p_div_f1, b_p_div_f2, b_p_div_two1, b_p_div_two2))
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha3::Sha3_256;

    #[derive(Clone, PartialEq, Eq, Debug)]
    pub struct TestPocklingtonParams;
    impl PocklingtonCertParams for TestPocklingtonParams {
        const NONCE_SIZE: usize = 16;
        const MAX_STEPS: usize = 5;
        const INCLUDE_SOLIDITY_WITNESSES: bool = false;
    }

    type TestPocklingtonHash = PocklingtonHash<TestPocklingtonParams, Sha3_256>;

    #[test]
    fn pocklington_prime_test() {
        let (h, cert) = TestPocklingtonHash::hash_to_prime(128, &vec![0]).unwrap();
        println!("h: {}", h);
        println!("nonce: {}", &cert.nonce);
        assert!(TestPocklingtonHash::verify_hash_to_prime(128, &vec![0], &h, &cert).unwrap());
    }
}
