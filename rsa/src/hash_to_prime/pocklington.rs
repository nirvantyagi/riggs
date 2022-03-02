use crate::{
    bigint::{BigInt, extended_euclidean_gcd},
    hash_to_prime::{
        HashToPrime,
        HashToPrimeError,
        hash_to_integer,
        miller_rabin,
        miller_rabin_32b,
        factor,
    },
    Error,
};
use digest::Digest;
use num_bigint::Sign;
use num_integer::{Integer, gcd};
use num_traits::{One, Zero};
use std::{
    cmp::min,
    fmt::{Debug},
    marker::PhantomData,
};
use tracing::{debug, warn};

/// https://www-sop.inria.fr/members/Benjamin.Gregoire/Publi/pock.pdf
pub trait PocklingtonCertParams: Clone + Eq + Debug + Send + Sync {
    const NONCE_SIZE: usize;  // nonce size in bits
    const MAX_STEPS: usize;  // max number of pocklington steps in certificate
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
            inputs.extend_from_slice(&nonce.to_le_bytes());
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
        unimplemented!();
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
        let factors = factor(p);
        debug_assert_eq!(factors[0].0, BigInt::from(2));
        let n2 = factors[0].1;
        let (f, n, u, v) = factors.iter().find_map(|(f, n)| Self::test_pocklington_f(p, f, *n, n2))?;
        let ((bu, bv), gcd) = extended_euclidean_gcd(&u, &v);
        debug_assert_eq!(gcd, BigInt::one());
        let a = {
            let mut a = None;
            let mut a_candidate = BigInt::from(2);
            while a_candidate < p - BigInt::one() {
                if Self::test_pocklington_a(p, &f, &a_candidate) {
                    a = Some(a_candidate.clone());
                    break;
                }
                a_candidate += BigInt::one();
            }
            a
        }?;
        Some(StepCert { f, n, n2, a, bu, bv })
    }

    fn test_pocklington_f(p: &BigInt, f: &BigInt, n: u32, n2: u32) -> Option<(BigInt, u32, BigInt, BigInt)> {
        let u = BigInt::from(2).pow(n2) * f.pow(n);
        let v = p.div_floor(&u);
        let r = v.mod_floor(&(BigInt::from(2) * &u));
        let s = v.div_floor(&(BigInt::from(2) * &u));

        let expr = r.pow(2) - BigInt::from(8) * &s;
        let test1 = expr >= BigInt::zero();
        let test2 = &((&u + BigInt::one()) * (BigInt::from(2) * u.pow(2) + (&r - BigInt::one()) * &u + BigInt::one())) > p;
        let test3 = (s == BigInt::zero()) || !(expr.sqrt().pow(2) == expr);
        if test1 && test2 && test3 {
            Some((f.clone(), n, u, v))
        } else {
            None
        }
    }

    fn test_pocklington_a(p: &BigInt, f: &BigInt, a: &BigInt) -> bool {
        let p_less_one = p - BigInt::one();
        let test1 = a.modpow(&p_less_one, p) == BigInt::one();
        let test2 = gcd(a.modpow(&p_less_one.div_floor(f), p) - BigInt::one(), p.clone()) == BigInt::one();
        let test3 = gcd(a.modpow(&p_less_one.div_floor(&BigInt::from(2)), p) - BigInt::one(), p.clone()) == BigInt::one();
        test1 && test2 && test3
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha3::Sha3_256;

    //#[test]
    //fn pocklington_prime_test() {
    //    let (h, cert) = PlannedPocklingtonHash::<Sha3_256>::hash_to_prime(128, &vec![0]).unwrap();
    //    assert!(PlannedPocklingtonHash::<Sha3_256>::verify_hash_to_prime(128, &vec![0], &h, &cert).unwrap());
    //}
}
