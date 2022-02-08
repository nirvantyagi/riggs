use ark_ec::ProjectiveCurve;
use ark_ff::{Field, PrimeField, UniformRand, BitIteratorLE};
use ark_serialize::CanonicalSerialize;

use digest::Digest;
use rand::{CryptoRng, Rng};
use num_traits::{One, Zero};

use std::{
    marker::PhantomData,
    ops::Neg,
};
use crate::Error;

use rsa::{
    bigint::{BigInt},
    poe::hash_to_prime::hash_to_variable_output_length,
};
use timed_commitments::{PedersenComm, PedersenParams};

pub struct Bulletproofs<G: ProjectiveCurve, D: Digest> {
    _g: PhantomData<G>,
    _hash: PhantomData<D>,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Params<G: ProjectiveCurve> {
    g: Vec<G>,
    h: Vec<G>,
    u: G,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Proof<G: ProjectiveCurve> {
    comm_bits: G,
    //comm_blind: G,
    //comm_lc1: G,
    //comm_lc2: G,
    //a: Vec<G>,
    //b: Vec<G>,
    //t_x: G::ScalarField,
    //r_t_x: G::ScalarField,
    //r_ab: G::ScalarField,
}

impl<G: ProjectiveCurve, D: Digest> Bulletproofs<G, D> {
    pub fn gen_params<R: CryptoRng + Rng>(rng: &mut R, n: u64) -> Params<G> {
        Params {
            g: (0..n).map(|_| G::rand(rng)).collect(),
            h: (0..n).map(|_| G::rand(rng)).collect(),
            u: G::rand(rng),
        }
    }

    /// Prove comm = g^v * h^opening AND v \in [0, 2^n)
    pub fn prove_range<R: CryptoRng + Rng>(
        rng: &mut R,
        pp: &Params<G>,
        ped_pp: &PedersenParams<G>,
        comm: &G,
        v: &BigInt,
        opening: &G::ScalarField,
        n: u64,
    ) -> Result<Proof<G>, Error> {
        // Check validity of statement
        // TODO: Support padding n to a power of 2
        debug_assert!(v.bits() <= n);
        debug_assert!(PedersenComm::ver_open(ped_pp, comm, &v.to_bytes_le().1, opening)?);

        // Range proof encoding for inner product argument
        let mut v_bits = BitIteratorLE::new(&v.to_u64_digits().1).collect::<Vec<bool>>();
        v_bits.resize(n as usize, false);
        let r_bits = G::ScalarField::rand(rng);
        let f_bits = v_bits.iter()
            .map(|b| if *b { G::ScalarField::one() } else { G::ScalarField::zero() })
            .collect::<Vec<G::ScalarField>>();
        let f_minus_bits = f_bits.iter()
            .map(|f_bit| f_bit.clone() - G::ScalarField::one())
            .collect::<Vec<G::ScalarField>>();
        let comm_bits = f_bits.iter().zip(f_minus_bits.iter())
            .zip(pp.g.iter().zip(pp.h.iter()))
            .map(|((f_bit, f_minus_bit), (g, h))| {
                g.mul(&f_bit.into_repr()) + h.mul(&f_minus_bit.into_repr())
        })
            .fold(pp.u.mul(&r_bits.into_repr()), |acc, g| acc + g);

        // TODO: Optimization with logarithmic blinds (https://eprint.iacr.org/2019/944)
        let blind_bits = (0..n).map(|_| G::ScalarField::rand(rng)).collect::<Vec<G::ScalarField>>();
        let blind_minus_bits = (0..n).map(|_| G::ScalarField::rand(rng)).collect::<Vec<G::ScalarField>>();
        let r_blind = G::ScalarField::rand(rng);
        let comm_blind = blind_bits.iter().zip(blind_minus_bits.iter())
            .zip(pp.g.iter().zip(pp.h.iter()))
            .map(|((s, s_minus), (g, h))| {
                g.mul(&s.into_repr()) + h.mul(&s_minus.into_repr())
            })
            .fold(pp.u.mul(&r_blind.into_repr()), |acc, g| acc + g);

        // Compute linear combination for single inner product challenges
        let mut hash_input = Vec::<u8>::new();
        comm.serialize(&mut hash_input)?;
        v.to_bytes_be().1.serialize(&mut hash_input)?;
        n.serialize(&mut hash_input)?;
        ped_pp.g.serialize(&mut hash_input)?;
        ped_pp.h.serialize(&mut hash_input)?;
        pp.g.serialize(&mut hash_input)?;
        pp.h.serialize(&mut hash_input)?;
        pp.u.serialize(&mut hash_input)?;
        comm_bits.serialize(&mut hash_input)?;
        comm_blind.serialize(&mut hash_input)?;
        // TODO: Solidity optimization: Pass in hash of input to variable output
        let chal = hash_to_variable_output_length::<D>(&hash_input, 96);
        let chal_y = G::ScalarField::from_random_bytes(&chal[..32]).unwrap();
        let chal_z = G::ScalarField::from_random_bytes(&chal[32..64]).unwrap();
        let mut fs_aux = chal[64..].to_vec();

        // Commit to linear combination coefficients
        let chal_y_powers = scalar_powers(n, &chal_y);
        let two_powers = scalar_powers(n, &G::ScalarField::from(2u128));
        let a_0 = f_bits.iter()
            .map(|f_bit| f_bit.clone() - &chal_z)
            .collect::<Vec<G::ScalarField>>();
        let a_1 = blind_bits.clone();
        let b_0 = f_minus_bits.iter().zip(chal_y_powers.iter().zip(two_powers.iter()))
            .map(|(f_minus_bit, (y_power, two_power))| y_power.clone() * (f_minus_bit.clone() + &chal_z) + two_power.clone() * &(chal_z.clone() * &chal_z) )
            .collect::<Vec<G::ScalarField>>();
        let b_1 = blind_minus_bits.iter().zip(chal_y_powers.iter())
            .map(|(blind_minus_bit, y_power)| blind_minus_bit.clone() * y_power)
            .collect::<Vec<G::ScalarField>>();

        let t_0_vec = a_0.iter().zip(b_0.iter())
            .map(|(a_0, b_0)| a_0.clone() * b_0)
            .collect::<Vec<G::ScalarField>>();
        let t_2_vec = a_1.iter().zip(b_1.iter())
            .map(|(a_1, b_1)| a_1.clone() * b_1)
            .collect::<Vec<G::ScalarField>>();
        let t_1 = a_0.iter().zip(b_0.iter())
            .zip(a_1.iter().zip(b_1.iter()))
            .zip(t_0_vec.iter().zip(t_2_vec.iter()))
            .map(|(((a_0, b_0), (a_1, b_1)), (t_0, t_2))| (a_0.clone() + a_1) * (b_0.clone() + b_1) - t_0 - t_2)
            .reduce(|acc, x| acc.clone() + x).unwrap();
        let t_0 = t_0_vec.iter().cloned().reduce(|acc, x| acc.clone() + x).unwrap();
        let t_2 = t_2_vec.iter().cloned().reduce(|acc, x| acc.clone() + x).unwrap();
        let r_lc1 = G::ScalarField::rand(rng);
        let r_lc2 = G::ScalarField::rand(rng);
        let comm_lc1 = ped_pp.g.mul(&t_1.into_repr()) + ped_pp.h.mul(&r_lc1.into_repr());
        let comm_lc2 = ped_pp.g.mul(&t_2.into_repr()) + ped_pp.h.mul(&r_lc2.into_repr());

        // Compute random challenge to test linear combination
        let mut hash_input = Vec::<u8>::new();
        fs_aux.serialize(&mut hash_input)?;
        comm_lc1.serialize(&mut hash_input)?;
        comm_lc2.serialize(&mut hash_input)?;
        let chal = hash_to_variable_output_length::<D>(&hash_input, 64);
        let chal_x = G::ScalarField::from_random_bytes(&chal[..32]).unwrap();
        fs_aux = chal[32..].to_vec();

        // Compute vectors for inner product argument
        let a_vec = a_0.iter().zip(a_1.iter())
            .map(|(a_0, a_1)| a_1.clone() * &chal_x + a_0)
            .collect::<Vec<G::ScalarField>>();
        let b_vec = b_0.iter().zip(b_1.iter())
            .map(|(b_0, b_1)| b_1.clone() * &chal_x + b_0)
            .collect::<Vec<G::ScalarField>>();
        let t_x = t_0.clone() + t_1.clone() * &chal_x + t_2.clone() * &chal_x * &chal_x;
        let r_t_x = r_lc2 * &chal_x * &chal_x + r_lc1 * &chal_x + opening.clone() * &chal_z * &chal_z;
        let r_comm_bits = r_bits + r_blind * &chal_x;

        // Tmp verification
        let inverse_y_powers = scalar_powers(n, &chal_y.inverse().unwrap());
        let h_shift = pp.h.iter().zip(inverse_y_powers.iter())
            .map(|(h, y_power)| h.mul(&y_power.into_repr()))
            .collect::<Vec<G>>();

        // Check 1
        let v_reconstruct: G::ScalarField = f_bits.iter().zip(two_powers.iter()).map(|(f_bit, two_power)| f_bit.clone() * two_power).sum();
        debug_assert_eq!(v_reconstruct, G::ScalarField::from(1000u128));
        let delta =  (chal_z.clone() - chal_z.clone() * &chal_z) * &chal_y_powers.iter().sum() - &(two_powers.iter().sum::<G::ScalarField>() * &chal_z * &chal_z * &chal_z);
        debug_assert_eq!(t_0, G::ScalarField::from(1000u128) * &chal_z * &chal_z + &delta);
        let ver1_left = ped_pp.g.mul(&t_x.into_repr()) + ped_pp.h.mul(&r_t_x.into_repr());
        let ver1_right = comm.mul(&(chal_z.clone() * &chal_z).into_repr()) + ped_pp.g.mul(&delta.into_repr()) + comm_lc1.mul(&chal_x.into_repr()) + comm_lc2.mul(&(chal_x.clone() * &chal_x).into_repr());
        debug_assert_eq!(ver1_left, ver1_right);

        // Check 2
        let tmp_ver2_left = comm_bits + comm_blind.mul(&chal_x.into_repr());
        let tmp_ver2_right = pp.u.mul(&r_comm_bits.into_repr())
            + &pp.g.iter().zip(f_bits.iter()).map(|(g, a)| g.clone().mul(&a.into_repr())).sum()
            + &h_shift.iter().zip(f_minus_bits.iter().zip(chal_y_powers.iter())).map(|(g, (a, y))| g.clone().mul(&(a.clone() * y).into_repr())).sum()
            + &pp.g.iter().zip(blind_bits.iter()).map(|(g, a)| g.clone().mul(&(a.clone() * &chal_x).into_repr())).sum()
            + &h_shift.iter().zip(blind_minus_bits.iter().zip(chal_y_powers.iter())).map(|(g, (a, y))| g.clone().mul(&(a.clone() * &chal_x * y).into_repr())).sum();
        debug_assert_eq!(tmp_ver2_left, tmp_ver2_right);

        let ver2_left = comm_bits + comm_blind.mul(&chal_x.into_repr())
            + &pp.g.iter().map(|g| g.clone().mul(&chal_z.neg().into_repr())).sum()
            + &h_shift.iter().zip(chal_y_powers.iter().zip(two_powers.iter())).map(|(h, (y_power, two_power))| h.clone().mul(&(chal_z.clone() * y_power + chal_z.clone() * &chal_z * two_power).into_repr())).sum();
        let ver2_right = pp.u.mul(&r_comm_bits.into_repr())
            + &pp.g.iter().zip(a_vec.iter()).map(|(g, a)| g.clone().mul(&a.into_repr())).sum()
            + &h_shift.iter().zip(b_vec.iter()).map(|(h, b)| h.clone().mul(&b.into_repr())).sum();
        debug_assert_eq!(ver2_left.into_affine(), ver2_right.into_affine());
        debug_assert_eq!(ver2_left, ver2_right);

        // Check 3
        let ver3_left: G::ScalarField = a_vec.iter().zip(b_vec.iter()).map(|(a, b)| a.clone() * b).sum();
        debug_assert_eq!(ver3_left, t_x);


        Ok(Proof{comm_bits: ped_pp.g.clone()})
    }
}

pub fn scalar_powers<F: PrimeField>(
    num: u64,
    s: &F,
) -> Vec<F> {
    debug_assert!(num > 0);
    let mut powers_of_scalar = vec![];
    let mut pow_s = F::one();
    for _ in 0..num {
        powers_of_scalar.push(pow_s);
        pow_s *= s;
    }
    powers_of_scalar
}


#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::G1Projective as G;
    use sha3::Sha3_256;

    use rand::{rngs::StdRng, SeedableRng};

    #[test]
    fn bulletproofs_verify_test() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let ped_pp = PedersenComm::<G>::gen_pedersen_params(&mut rng);
        let pp = Bulletproofs::<G, Sha3_256>::gen_params(&mut rng, 32);
        let v = BigInt::from(1000);
        let (comm, opening) = PedersenComm::<G>::commit(&mut rng, &ped_pp, &v.to_bytes_le().1).unwrap();
        Bulletproofs::<G, Sha3_256>::prove_range(&mut rng, &pp, &ped_pp, &comm, &v, &opening, 32).unwrap();
    }
}
