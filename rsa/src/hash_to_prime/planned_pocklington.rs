use crate::{
    bigint::BigInt,
    hash_to_prime::{
        HashToPrime,
        HashToPrimeError,
        hash_to_variable_output_length,
        miller_rabin_32b,
    },
    Error,
};
use digest::Digest;
use num_bigint::Sign;
use num_integer::Integer;
use num_traits::One;
use std::{
    cmp::min,
    fmt::{Debug},
    marker::PhantomData,
};
use tracing::debug;

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PlannedPocklingtonHash<D: Digest>{
    _hash: PhantomData<D>,
}

impl<D: Digest> HashToPrime for PlannedPocklingtonHash<D> {
    type Certificate = PocklingtonCertificate;

    fn hash_to_prime(entropy: usize, input: &[u8]) -> Result<(BigInt, Self::Certificate), Error> {
        let cert = hash_to_pocklington_prime::<D>(input, entropy)?;
        Ok((cert.result().clone(), cert))
    }

    fn verify_hash_to_prime(entropy: usize, input: &[u8], p: &BigInt, cert: &Self::Certificate) -> Result<bool, Error> {
        let cert_valid = check_pocklington_certificate::<D>(input, entropy, cert)?;
        Ok(p == cert.result() && cert_valid)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PocklingtonPlan {
    /// Number of nonce bits in the base prime
    pub base_nonce_bits: usize,
    /// Number of random bits in the base prime
    pub base_random_bits: usize,
    pub extensions: Vec<PlannedExtension>,
}

/// Stores one extension: the size of `r` and `n`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PlannedExtension {
    pub nonce_bits: usize,
    pub random_bits: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtensionCertificate {
    pub plan: PlannedExtension,
    pub nonce: u64,
    pub checking_base: BigInt,
    pub result: BigInt,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PocklingtonCertificate {
    pub base_plan: PlannedExtension,
    pub base_prime: BigInt,
    pub base_nonce: usize,
    pub extensions: Vec<ExtensionCertificate>,
}

impl PlannedExtension {
    pub fn max_value(&self) -> BigInt {
        (BigInt::one() << (self.nonce_bits + self.random_bits + 1) as u32) - 1
    }
    pub fn min_value(&self) -> BigInt {
        BigInt::one() << (self.nonce_bits + self.random_bits) as u32
    }
    pub fn evaluate(&self, random_value: &BigInt, nonce_value: u64) -> BigInt {
        assert!(self.nonce_bits <= 64);
        self.min_value() + BigInt::from(random_value << self.nonce_bits as u32) + nonce_value
    }
}

/// Returns the probability that a number with `bits` bits is prime
fn prime_density(bits: usize) -> f64 {
    let log2e = std::f64::consts::E.log2();
    let b = bits as f64;
    log2e / b - log2e * log2e / b / b
}

/// Returns the number of random `bits`-bit numbers that must be checked to find a prime with
/// all but `p_fail` probability
pub fn prime_trials(bits: usize, p_fail: f64) -> usize {
    let p = prime_density(bits);
    (p_fail.log(1.0 - p).ceil() + 0.1) as usize
}

/// The number of nonce bits needed to generate a `bits`-bit prime with all but 2**-64
/// probability.
pub fn nonce_bits_needed(bits: usize) -> usize {
    let trials = prime_trials(bits, 2.0f64.powi(-64));
    ((trials as f64).log2().ceil() + 0.1) as usize
}

impl PocklingtonPlan {
    /// Given a target entropy, constructs a plan for how to make a prime number of that
    /// entropy that can be certified using a recursive Pocklington test
    pub fn new(entropy: usize) -> Self {
        // Both low bits of the base prime are fixed to 1
        // We require an extra nonce bit, since the 2's place bit is artificially fixed
        let nonce_bits_needed_in_base = nonce_bits_needed(32) + 1;
        let mut plan = Self {
            base_nonce_bits: nonce_bits_needed_in_base,
            // High bit is fixed to 1, so 31 bits for the nonce + random bits.
            base_random_bits: min(entropy, 31 - nonce_bits_needed_in_base),
            extensions: Vec::new(),
        };

        // Construct extensions until desired entropy is reached
        while plan.entropy() < entropy {
            // Extension must be less than current base
            let max_extension_bits = plan.min_value().bits() as usize - 1;
            // Determine number of required nonce bits
            let max_nonce_bits_needed = nonce_bits_needed(max_extension_bits + plan.max_bits());
            assert!(max_nonce_bits_needed < max_extension_bits);
            // High bit is fixed to 1
            let max_random_bits = max_extension_bits - max_nonce_bits_needed - 1;
            let random_bits = min(entropy - plan.entropy(), max_random_bits);
            plan.extensions.push(PlannedExtension {
                nonce_bits: max_nonce_bits_needed,
                random_bits: random_bits,
            })
        }
        plan
    }

    pub fn entropy(&self) -> usize {
        self.extensions.iter().map(|i| i.random_bits).sum::<usize>() + self.base_random_bits
    }

    pub fn max_value(&self) -> BigInt {
        self.extensions.iter().fold(
            (BigInt::one() << (self.base_random_bits + self.base_nonce_bits + 1) as u32) - 1,
            |acc, ext| acc * ext.max_value() + 1,
        )
    }

    pub fn min_value(&self) -> BigInt {
        self.extensions.iter().fold(
            BigInt::one() << (self.base_random_bits + self.base_nonce_bits) as u32,
            |acc, ext| acc * ext.min_value() + 1,
        )
    }

    pub fn max_bits(&self) -> usize {
        self.max_value().bits() as usize
    }
}

impl PocklingtonCertificate {
    pub fn result(&self) -> &BigInt {
        if let Some(l) = self.extensions.last() {
            &l.result
        } else {
            &self.base_prime
        }
    }
}

pub fn attempt_pocklington_base(
    plan: &PocklingtonPlan,
    random_bits: &BigInt,
) -> Result<PocklingtonCertificate, Error> {
    debug_assert!(random_bits.bits() <= plan.base_random_bits as u64);
    for nonce in 0..(1u64 << plan.base_nonce_bits) {
        if (nonce & 0b11) == 0b11 {
            let mut base = BigInt::one() << (plan.base_nonce_bits + plan.base_random_bits) as u32;
            base |= (random_bits.clone() << plan.base_nonce_bits as u32) + nonce;
            if miller_rabin_32b(&base) {
                return Ok(PocklingtonCertificate {
                    base_plan: PlannedExtension {
                        nonce_bits: plan.base_nonce_bits,
                        random_bits: plan.base_random_bits,
                    },
                    base_prime: base,
                    base_nonce: nonce as usize,
                    extensions: Vec::new(),
                });
            }
        }
    }
    Err(Box::new(HashToPrimeError::NoValidNonce))
}

pub fn attempt_pocklington_extension(
    mut p: PocklingtonCertificate,
    plan: &PlannedExtension,
    random_bits: &BigInt,
) -> Result<PocklingtonCertificate, Error> {
    debug_assert!(random_bits.bits() <= plan.random_bits as u64);
    for nonce in 0..(1u64 << plan.nonce_bits) {
        let extension = plan.evaluate(random_bits, nonce); // Sets high bit
        let candidate = BigInt::from(p.result() * &extension) + 1;
        let mut base = BigInt::from(2);
        while base < candidate {
            let part = base.modpow(&extension, &candidate);
            if part.modpow(p.result(), &candidate) != BigInt::one() {
                break;
            }
            if (&part - BigInt::one()).gcd(&candidate) == BigInt::one() {
                p.extensions.push(ExtensionCertificate {
                    plan: plan.clone(),
                    checking_base: base,
                    result: candidate,
                    nonce,
                });
                return Ok(p);
            }
            base += 1;
        }
    }
    Err(Box::new(HashToPrimeError::NoValidNonce))
}

pub fn hash_to_pocklington_prime<D: Digest>(
    inputs: &[u8],
    entropy: usize,
) -> Result<PocklingtonCertificate, Error> {
    let plan = PocklingtonPlan::new(entropy);
    debug_assert_eq!(plan.entropy(), entropy);

    // Compute needed randomness
    let mut random_bits = BigInt::from_bytes_le(
        Sign::Plus,
        &hash_to_variable_output_length::<D>(inputs, entropy),
    );

    // Construct Pocklington base
    let base_random_bits =
        random_bits.clone() & ((BigInt::from(1) << plan.base_random_bits as u32) - BigInt::from(1));
    let mut cert = attempt_pocklington_base(&plan, &base_random_bits)?;
    random_bits >>= plan.base_random_bits as u32;

    // Perform each extension
    for extension in &plan.extensions {
        let ext_random_bits = random_bits.clone()
            & ((BigInt::from(1) << extension.random_bits as u32) - BigInt::from(1));
        cert = attempt_pocklington_extension(cert, extension, &ext_random_bits)?;
        random_bits >>= extension.random_bits as u32;
    }
    Ok(cert)
}

//TODO: Swap asserts for returns (used for testing)
pub fn check_pocklington_certificate<D: Digest>(
    inputs: &[u8],
    entropy: usize,
    cert: &PocklingtonCertificate,
) -> Result<bool, Error> {
    // Compute needed randomness
    let mut random_bits = BigInt::from_bytes_le(
        Sign::Plus,
        &hash_to_variable_output_length::<D>(inputs, entropy),
    );

    // Construct Pocklington base
    let base_random_bits = random_bits.clone()
        & ((BigInt::from(1) << cert.base_plan.random_bits as u32) - BigInt::from(1));
    random_bits >>= cert.base_plan.random_bits as u32;
    let mut base =
        BigInt::from(1) << (cert.base_plan.nonce_bits + cert.base_plan.random_bits) as u32;
    base |= (base_random_bits.clone() << cert.base_plan.nonce_bits as u32)
        + BigInt::from(cert.base_nonce as u32);
    debug_assert_eq!(cert.base_plan.nonce_bits + cert.base_plan.random_bits, 31);
    debug!(base = base.to_str_radix(10).as_str());
    if !miller_rabin_32b(&base) {
        debug!("base prime fails primality check");
        return Ok(false);
    }

    // Check each extension
    let mut prime = cert.base_prime.clone();
    for (i, extension) in cert.extensions.iter().enumerate() {
        let ext_random_bits = random_bits.clone()
            & ((BigInt::from(1) << extension.plan.random_bits as u32) - BigInt::from(1));
        random_bits >>= extension.plan.random_bits as u32;
        let extension_term = extension.plan.evaluate(&ext_random_bits, extension.nonce);

        let n_less_one = &extension_term * &prime;
        let n = &n_less_one + BigInt::one();
        let part = extension.checking_base.modpow(&extension_term, &n);
        let part_less_one = &part - BigInt::one();
        debug!(
            round = i,
            extension_term = extension_term.to_str_radix(10).as_str(),
            n = n.to_str_radix(10).as_str(),
            part = i,
        );

        // Enforce coprimality
        let gcd = part_less_one.gcd(&n);
        if gcd != BigInt::one() {
            debug!(
                gcd = gcd.to_str_radix(10).as_str(),
                "failed coprimality test"
            );
            return Ok(false);
        }

        // Check Fermat's little theorem
        let power = part.modpow(&prime, &n);
        if power != BigInt::one() {
            debug!(
                power = power.to_str_radix(10).as_str(),
                "failed Fermat's primality test"
            );
            return Ok(false);
        }

        prime = n;
    }
    Ok(prime == cert.result().clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha3::Sha3_256;

    #[test]
    fn pocklington_prime_test() {
        let (h, cert) = PlannedPocklingtonHash::<Sha3_256>::hash_to_prime(128, &vec![0]).unwrap();
        assert!(PlannedPocklingtonHash::<Sha3_256>::verify_hash_to_prime(128, &vec![0], &h, &cert).unwrap());
    }
}
