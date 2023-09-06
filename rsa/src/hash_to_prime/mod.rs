use crate::{bigint::BigInt, Error};
use digest::Digest;
use num_bigint::Sign;
use num_integer::Integer;
use num_traits::One;
use std::{
    error::Error as ErrorTrait,
    fmt::{self, Debug},
    marker::PhantomData,
};

pub mod pocklington;

pub trait HashToPrime: Clone + Eq {
    type Certificate: Clone + Eq + Debug;

    fn hash_to_prime(entropy: usize, input: &[u8]) -> Result<(BigInt, Self::Certificate), Error>;

    fn verify_hash_to_prime(
        entropy: usize,
        input: &[u8],
        p: &BigInt,
        cert: &Self::Certificate,
    ) -> Result<bool, Error>;
}

pub struct MillerRabinRejectionSample<D: Digest> {
    _hash: PhantomData<D>,
}

impl<D: Digest> Clone for MillerRabinRejectionSample<D> {
    fn clone(&self) -> Self {
        Self { _hash: PhantomData }
    }
}

impl<D: Digest> PartialEq<Self> for MillerRabinRejectionSample<D> {
    fn eq(&self, _other: &Self) -> bool {
        true
    }
}

impl<D: Digest> Eq for MillerRabinRejectionSample<D> {}

impl<D: Digest> HashToPrime for MillerRabinRejectionSample<D> {
    type Certificate = u32;

    fn hash_to_prime(entropy: usize, input: &[u8]) -> Result<(BigInt, Self::Certificate), Error> {
        hash_to_prime::<D>(input, Self::prime_bits(entropy))
    }

    fn verify_hash_to_prime(
        entropy: usize,
        input: &[u8],
        p: &BigInt,
        cert: &Self::Certificate,
    ) -> Result<bool, Error> {
        let mut input = input.to_vec();
        input.extend_from_slice(&cert.to_le_bytes());
        let p_comp = hash_to_integer::<D>(&input, Self::prime_bits(entropy));
        Ok(p == &p_comp && miller_rabin(p, 30))
    }
}

impl<D: Digest> MillerRabinRejectionSample<D> {
    fn prime_bits(entropy: usize) -> usize {
        // Size of prime needed if nonce is chosen deterministically from nonce space
        let n_bits = ((entropy as f64) + (entropy as f64).ln()) as usize;
        let n_rounds = -128f64 * 2f64.ln() / (1f64 - 2f64 / n_bits as f64).ln();
        let nonce_bits = (n_rounds.log2().ceil() + 0.1) as usize;

        // Size of prime needed if any nonce of valid length is allowed
        n_bits + nonce_bits
    }
}

/// Returns whether `n` passes Miller-Rabin checks with the first `rounds` primes as bases
pub fn miller_rabin(n: &BigInt, rounds: usize) -> bool {
    fn primes(n: usize) -> Vec<usize> {
        let mut ps = vec![2];
        let mut next = 3;
        while ps.len() < n {
            if !ps.iter().any(|p| next % p == 0) {
                ps.push(next);
            }
            next += 1;
        }
        ps
    }
    let ps = primes(rounds);
    !ps.into_iter()
        .any(|p| !miller_rabin_round(n, &BigInt::from(p)))
}

/// Returns whether `n` passes a Miller-Rabin check with base `b`.
fn miller_rabin_round(n: &BigInt, b: &BigInt) -> bool {
    if n.is_even() {
        return false;
    };
    let n_less_one = n - BigInt::one();
    let s = n_less_one.trailing_zeros().expect("Input must be > 1");
    let d = &n_less_one >> s as u32;
    let mut pow = b.modpow(&d, &n);
    if pow == BigInt::one() || pow == n_less_one {
        return true;
    }
    for _ in 0..(s - 1) {
        pow = pow.pow(2);
        pow %= n;
        if pow == n_less_one {
            return true;
        }
    }
    return false;
}

pub fn miller_rabin_32b(n: &BigInt) -> bool {
    miller_rabin_round(n, &BigInt::from(2usize))
        && miller_rabin_round(n, &BigInt::from(7usize))
        && miller_rabin_round(n, &BigInt::from(61usize))
}

/// Returns `(result, nonce)` for first nonce that passes Miller-Rabin primality check
pub fn hash_to_prime<D: Digest>(inputs: &[u8], n_bits: usize) -> Result<(BigInt, u32), Error> {
    let n_rounds = -128f64 * 2f64.ln() / (1f64 - 2f64 / n_bits as f64).ln();
    let nonce_bits = (n_rounds.log2().ceil() + 0.1) as usize;
    debug_assert!(nonce_bits < 32);
    let mut inputs: Vec<u8> = inputs.iter().copied().collect();
    for nonce in 0..(1u32 << nonce_bits) {
        inputs.extend_from_slice(&nonce.to_le_bytes());
        let hash = hash_to_integer::<D>(&inputs, n_bits);
        if miller_rabin(&hash, 30) {
            return Ok((hash, nonce));
        }
        inputs.truncate(inputs.len() - 4);
    }
    Err(Box::new(HashToPrimeError::NoValidNonce))
}

pub fn hash_to_integer<D: Digest>(inputs: &[u8], n_bits: usize) -> BigInt {
    assert!(n_bits > 0);
    let mut n = BigInt::from_bytes_be(
        Sign::Plus,
        &hash_to_variable_output_length::<D>(inputs, ((n_bits - 1) / 8) + 1),
    );
    // Clear high order bits
    let mask = (BigInt::one() << n_bits) - BigInt::one();
    n &= mask;
    n.set_bit(n_bits as u64 - 1, true);
    n
}

pub fn hash_to_variable_output_length<D: Digest>(inputs: &[u8], n_bytes: usize) -> Vec<u8> {
    let bytes_per_hash = D::output_size();
    let n_hashes = (n_bytes - 1) / bytes_per_hash + 1;

    // Hash the inputs with a different counter for each output
    let mut out = Vec::new();
    let mut inputs: Vec<u8> = inputs.iter().copied().collect();
    if n_hashes == 1 {
        out.extend_from_slice(D::digest(&inputs).as_slice());
    } else {
        for i in 0..n_hashes {
            inputs.extend_from_slice(&(i as u32).to_be_bytes());
            out.extend_from_slice(D::digest(&inputs).as_slice());
            inputs.truncate(inputs.len() - 4);
        }
    }

    out.reverse();
    out.truncate(n_bytes);
    out.reverse(); // For ease of big endian solidity encoding
    out
}

#[derive(Debug)]
pub enum HashToPrimeError {
    NoValidNonce,
}

impl ErrorTrait for HashToPrimeError {
    fn source(self: &Self) -> Option<&(dyn ErrorTrait + 'static)> {
        None
    }
}

impl fmt::Display for HashToPrimeError {
    fn fmt(self: &Self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            HashToPrimeError::NoValidNonce => format!("No valid nonce found"),
        };
        write!(f, "{}", msg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha3::Sha3_256;
    use std::str::FromStr;

    #[test]
    fn hash_to_integer_test() {
        let h = hash_to_integer::<Sha3_256>(&vec![0], 24);
        assert!(h >= BigInt::one() << 23);
        assert!(h < BigInt::one() << 24);

        let h = hash_to_integer::<Sha3_256>(&vec![0], 13);
        assert!(h >= BigInt::one() << 12);
        assert!(h < BigInt::one() << 13);
    }

    #[test]
    fn miller_rabin_rejection_sample_prime_test() {
        let (h, cert) =
            MillerRabinRejectionSample::<Sha3_256>::hash_to_prime(128, &vec![0]).unwrap();
        println!("mr: {}", h);
        println!("nonce: {}", cert);
        assert!(
            MillerRabinRejectionSample::<Sha3_256>::verify_hash_to_prime(128, &vec![0], &h, &cert)
                .unwrap()
        );
    }

    #[test]
    fn miller_rabin_32b_test() {
        let p = BigInt::from_str("42589817").unwrap();
        assert!(miller_rabin_32b(&p));
    }
}
