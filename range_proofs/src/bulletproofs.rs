use ark_ec::{msm::VariableBaseMSM, ProjectiveCurve};
use ark_ff::{BitIteratorLE, Field, PrimeField, UniformRand};
use ark_serialize::CanonicalSerialize;

use digest::Digest;
use num_traits::{One, Zero};
use rand::{CryptoRng, Rng};

use crate::Error;
use std::{marker::PhantomData, ops::Neg};

use rsa::{bigint::BigInt, poe::hash_to_prime::hash_to_variable_output_length};
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
    comm_blind: G,
    comm_lc1: G,
    comm_lc2: G,
    t_x: G::ScalarField,
    r_t_x: G::ScalarField,
    r_ab: G::ScalarField,
    comm_ipa: Vec<(G, G)>,
    base_a: G::ScalarField,
    base_b: G::ScalarField,
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
        debug_assert!(PedersenComm::ver_open(
            ped_pp,
            comm,
            &v.to_bytes_le().1,
            opening
        )?);

        // Range proof encoding for inner product argument
        let mut v_bits = BitIteratorLE::new(&v.to_u64_digits().1).collect::<Vec<bool>>();
        v_bits.resize(n as usize, false);
        let r_bits = G::ScalarField::rand(rng);
        let f_bits = v_bits
            .iter()
            .map(|b| {
                if *b {
                    G::ScalarField::one()
                } else {
                    G::ScalarField::zero()
                }
            })
            .collect::<Vec<G::ScalarField>>();
        let f_minus_bits = f_bits
            .iter()
            .map(|f_bit| f_bit.clone() - G::ScalarField::one())
            .collect::<Vec<G::ScalarField>>();
        let comm_bits = f_bits
            .iter()
            .zip(f_minus_bits.iter())
            .zip(pp.g.iter().zip(pp.h.iter()))
            .map(|((f_bit, f_minus_bit), (g, h))| {
                g.mul(&f_bit.into_repr()) + h.mul(&f_minus_bit.into_repr())
            })
            .fold(pp.u.mul(&r_bits.into_repr()), |acc, g| acc + g);

        // TODO: Optimization with logarithmic blinds (https://eprint.iacr.org/2019/944)
        let blind_bits = (0..n)
            .map(|_| G::ScalarField::rand(rng))
            .collect::<Vec<G::ScalarField>>();
        let blind_minus_bits = (0..n)
            .map(|_| G::ScalarField::rand(rng))
            .collect::<Vec<G::ScalarField>>();
        let r_blind = G::ScalarField::rand(rng);
        let comm_blind = blind_bits
            .iter()
            .zip(blind_minus_bits.iter())
            .zip(pp.g.iter().zip(pp.h.iter()))
            .map(|((s, s_minus), (g, h))| g.mul(&s.into_repr()) + h.mul(&s_minus.into_repr()))
            .fold(pp.u.mul(&r_blind.into_repr()), |acc, g| acc + g);

        let (chal_y, chal_z, fs_aux) = {
            let mut hash_input = Vec::<u8>::new();
            comm.serialize(&mut hash_input)?;
            n.serialize(&mut hash_input)?;
            ped_pp.g.serialize(&mut hash_input)?;
            ped_pp.h.serialize(&mut hash_input)?;
            pp.g.serialize(&mut hash_input)?;
            pp.h.serialize(&mut hash_input)?;
            pp.u.serialize(&mut hash_input)?;
            comm_bits.serialize(&mut hash_input)?;
            comm_blind.serialize(&mut hash_input)?;
            // TODO: Solidity optimization: Pass in hash of input to variable output
            let chal = hash_to_variable_output_length::<D>(&hash_input, 32);
            let chal_y = G::ScalarField::from_random_bytes(&chal[..16]).unwrap();
            let chal_z = G::ScalarField::from_random_bytes(&chal[16..]).unwrap();
            let fs_aux = chal[16..].to_vec();
            (chal_y, chal_z, fs_aux)
        };

        // Commit to linear combination coefficients
        let chal_y_powers = scalar_powers(n, &chal_y);
        let two_powers = scalar_powers(n, &G::ScalarField::from(2u128));
        let a_0 = f_bits
            .iter()
            .map(|f_bit| f_bit.clone() - &chal_z)
            .collect::<Vec<G::ScalarField>>();
        let a_1 = blind_bits.clone();
        let b_0 = f_minus_bits
            .iter()
            .zip(chal_y_powers.iter().zip(two_powers.iter()))
            .map(|(f_minus_bit, (y_power, two_power))| {
                y_power.clone() * (f_minus_bit.clone() + &chal_z)
                    + two_power.clone() * &(chal_z.clone() * &chal_z)
            })
            .collect::<Vec<G::ScalarField>>();
        let b_1 = blind_minus_bits
            .iter()
            .zip(chal_y_powers.iter())
            .map(|(blind_minus_bit, y_power)| blind_minus_bit.clone() * y_power)
            .collect::<Vec<G::ScalarField>>();

        let t_0_vec = a_0
            .iter()
            .zip(b_0.iter())
            .map(|(a_0, b_0)| a_0.clone() * b_0)
            .collect::<Vec<G::ScalarField>>();
        let t_2_vec = a_1
            .iter()
            .zip(b_1.iter())
            .map(|(a_1, b_1)| a_1.clone() * b_1)
            .collect::<Vec<G::ScalarField>>();
        let t_1 = a_0
            .iter()
            .zip(b_0.iter())
            .zip(a_1.iter().zip(b_1.iter()))
            .zip(t_0_vec.iter().zip(t_2_vec.iter()))
            .map(|(((a_0, b_0), (a_1, b_1)), (t_0, t_2))| {
                (a_0.clone() + a_1) * (b_0.clone() + b_1) - t_0 - t_2
            })
            .reduce(|acc, x| acc.clone() + x)
            .unwrap();
        let t_0 = t_0_vec
            .iter()
            .cloned()
            .reduce(|acc, x| acc.clone() + x)
            .unwrap();
        let t_2 = t_2_vec
            .iter()
            .cloned()
            .reduce(|acc, x| acc.clone() + x)
            .unwrap();
        let r_lc1 = G::ScalarField::rand(rng);
        let r_lc2 = G::ScalarField::rand(rng);
        let comm_lc1 = ped_pp.g.mul(&t_1.into_repr()) + ped_pp.h.mul(&r_lc1.into_repr());
        let comm_lc2 = ped_pp.g.mul(&t_2.into_repr()) + ped_pp.h.mul(&r_lc2.into_repr());

        let (chal_x, fs_aux) = {
            let mut hash_input = Vec::<u8>::new();
            fs_aux.serialize(&mut hash_input)?;
            comm_lc1.serialize(&mut hash_input)?;
            comm_lc2.serialize(&mut hash_input)?;
            let chal = hash_to_variable_output_length::<D>(&hash_input, 16);
            let chal_x = G::ScalarField::from_random_bytes(&chal[..]).unwrap();
            let fs_aux = chal;
            (chal_x, fs_aux)
        };

        let a_vec = a_0
            .iter()
            .zip(a_1.iter())
            .map(|(a_0, a_1)| a_1.clone() * &chal_x + a_0)
            .collect::<Vec<G::ScalarField>>();
        let b_vec = b_0
            .iter()
            .zip(b_1.iter())
            .map(|(b_0, b_1)| b_1.clone() * &chal_x + b_0)
            .collect::<Vec<G::ScalarField>>();
        let t_x = t_0.clone() + t_1.clone() * &chal_x + t_2.clone() * &chal_x * &chal_x;
        let r_t_x =
            r_lc2 * &chal_x * &chal_x + r_lc1 * &chal_x + opening.clone() * &chal_z * &chal_z;
        let r_comm_bits = r_bits + r_blind * &chal_x;

        // Perform inner product argument ( <a, b> = t  AND comm = g^a * h^b * u^t )
        let inverse_y_powers = scalar_powers(n, &chal_y.inverse().unwrap());
        let h_shift =
            pp.h.iter()
                .zip(inverse_y_powers.iter())
                .map(|(h, y_power)| h.mul(&y_power.into_repr()))
                .collect::<Vec<G>>();
        let mut a = a_vec;
        let mut b = b_vec;
        let mut g = pp.g.clone();
        let mut h = h_shift;
        let mut recurse_commitments = Vec::<(G, G)>::new();
        let (mut fs_aux, chal_u) = {
            let mut hash_input = fs_aux;
            t_x.serialize(&mut hash_input)?;
            r_t_x.serialize(&mut hash_input)?;
            r_comm_bits.serialize(&mut hash_input)?;
            let chal = hash_to_variable_output_length::<D>(&hash_input, 16);
            let chal_u = G::ScalarField::from_random_bytes(&chal[..]).unwrap();
            (chal, chal_u)
        };

        'recurse: loop {
            // TODO: Increase base case to avoid small recursions
            if a.len() == 1 {
                // base case
                break 'recurse;
            } else {
                // recursive step
                let s = a.len() / 2;
                let (a_1, a_2) = (&a[s..], &a[..s]);
                let (g_1, g_2) = (&g[..s], &g[s..]);
                let (b_1, b_2) = (&b[..s], &b[s..]);
                let (h_1, h_2) = (&h[s..], &h[..s]);

                let comm_1: G = g_1
                    .iter()
                    .zip(a_1.iter())
                    .map(|(g, a)| g.clone().mul(&a.into_repr()))
                    .sum::<G>()
                    + &h_1
                        .iter()
                        .zip(b_1.iter())
                        .map(|(h, b)| h.clone().mul(&b.into_repr()))
                        .sum()
                    + pp.u.mul(
                        &(a_1
                            .iter()
                            .zip(b_1.iter())
                            .map(|(a, b)| a.clone() * b)
                            .sum::<G::ScalarField>()
                            * &chal_u)
                            .into_repr(),
                    );
                let comm_2: G = g_2
                    .iter()
                    .zip(a_2.iter())
                    .map(|(g, a)| g.clone().mul(&a.into_repr()))
                    .sum::<G>()
                    + &h_2
                        .iter()
                        .zip(b_2.iter())
                        .map(|(h, b)| h.clone().mul(&b.into_repr()))
                        .sum()
                    + pp.u.mul(
                        &(a_2
                            .iter()
                            .zip(b_2.iter())
                            .map(|(a, b)| a.clone() * b)
                            .sum::<G::ScalarField>()
                            * &chal_u)
                            .into_repr(),
                    );

                let chal_x = {
                    let mut hash_input = Vec::<u8>::new();
                    fs_aux.serialize(&mut hash_input)?;
                    comm_1.serialize(&mut hash_input)?;
                    comm_2.serialize(&mut hash_input)?;
                    let chal = hash_to_variable_output_length::<D>(&hash_input, 16);
                    let chal_x = G::ScalarField::from_random_bytes(&chal[..]).unwrap();
                    fs_aux = chal;
                    chal_x
                };
                let chal_x_inv = chal_x.inverse().unwrap();

                a = a_1
                    .iter()
                    .zip(a_2.iter())
                    .map(|(a_1, a_2)| chal_x.clone() * a_1 + a_2)
                    .collect::<Vec<G::ScalarField>>();
                b = b_1
                    .iter()
                    .zip(b_2.iter())
                    .map(|(b_1, b_2)| chal_x_inv.clone() * b_2 + b_1)
                    .collect::<Vec<G::ScalarField>>();
                g = g_1
                    .iter()
                    .zip(g_2.iter())
                    .map(|(g_1, g_2)| g_2.clone().mul(&chal_x_inv.into_repr()) + g_1)
                    .collect::<Vec<G>>();
                h = h_1
                    .iter()
                    .zip(h_2.iter())
                    .map(|(h_1, h_2)| h_1.clone().mul(&chal_x.into_repr()) + h_2)
                    .collect::<Vec<G>>();

                recurse_commitments.push((comm_1, comm_2));
            }
        }

        Ok(Proof {
            comm_bits,
            comm_blind,
            comm_lc1,
            comm_lc2,
            t_x,
            r_t_x,
            r_ab: r_comm_bits,
            comm_ipa: recurse_commitments,
            base_a: a[0],
            base_b: b[0],
        })
    }

    /// Verify comm = g^v * h^opening AND v \in [0, 2^n)
    pub fn verify_range(
        pp: &Params<G>,
        ped_pp: &PedersenParams<G>,
        comm: &G,
        n: u64,
        proof: &Proof<G>,
    ) -> Result<bool, Error> {
        // Verify range encoding to inner product argument
        let (chal_y, chal_z, fs_aux) = {
            let mut hash_input = Vec::<u8>::new();
            comm.serialize(&mut hash_input)?;
            n.serialize(&mut hash_input)?;
            ped_pp.g.serialize(&mut hash_input)?;
            ped_pp.h.serialize(&mut hash_input)?;
            pp.g.serialize(&mut hash_input)?;
            pp.h.serialize(&mut hash_input)?;
            pp.u.serialize(&mut hash_input)?;
            proof.comm_bits.serialize(&mut hash_input)?;
            proof.comm_blind.serialize(&mut hash_input)?;
            // TODO: Solidity optimization: Pass in hash of input to variable output
            let chal = hash_to_variable_output_length::<D>(&hash_input, 32);
            let chal_y = G::ScalarField::from_random_bytes(&chal[..16]).unwrap();
            let chal_z = G::ScalarField::from_random_bytes(&chal[16..]).unwrap();
            let fs_aux = chal[16..].to_vec();
            (chal_y, chal_z, fs_aux)
        };

        let (chal_x, fs_aux) = {
            let mut hash_input = Vec::<u8>::new();
            fs_aux.serialize(&mut hash_input)?;
            proof.comm_lc1.serialize(&mut hash_input)?;
            proof.comm_lc2.serialize(&mut hash_input)?;
            let chal = hash_to_variable_output_length::<D>(&hash_input, 16);
            let chal_x = G::ScalarField::from_random_bytes(&chal[..]).unwrap();
            let fs_aux = chal;
            (chal_x, fs_aux)
        };

        // Verify inner product argument
        let (mut fs_aux, chal_u) = {
            let mut hash_input = fs_aux;
            proof.t_x.serialize(&mut hash_input)?;
            proof.r_t_x.serialize(&mut hash_input)?;
            proof.r_ab.serialize(&mut hash_input)?;
            let chal = hash_to_variable_output_length::<D>(&hash_input, 16);
            let chal_u = G::ScalarField::from_random_bytes(&chal[..]).unwrap();
            (chal, chal_u)
        };
        let mut recursive_challenges = Vec::new();
        for (comm_1, comm_2) in proof.comm_ipa.iter() {
            let chal_x = {
                let mut hash_input = Vec::<u8>::new();
                fs_aux.serialize(&mut hash_input)?;
                comm_1.serialize(&mut hash_input)?;
                comm_2.serialize(&mut hash_input)?;
                let chal = hash_to_variable_output_length::<D>(&hash_input, 16);
                let chal_x = G::ScalarField::from_random_bytes(&chal[..]).unwrap();
                fs_aux = chal;
                chal_x
            };
            recursive_challenges.push(chal_x);
        }

        // Prepare single variable base multiexponentiation verification check
        let inverse_y_powers = scalar_powers(n, &chal_y.inverse().unwrap());
        let chal_y_powers = scalar_powers(n, &chal_y);
        let two_powers = scalar_powers(n, &G::ScalarField::from(2u128));

        // Linear combination check
        let delta = (chal_z.clone() - chal_z.clone() * &chal_z) * &chal_y_powers.iter().sum()
            - &(two_powers.iter().sum::<G::ScalarField>() * &chal_z * &chal_z * &chal_z);
        let ver1_left =
            ped_pp.g.mul(&proof.t_x.into_repr()) + ped_pp.h.mul(&proof.r_t_x.into_repr());
        let ver1_right = comm.mul(&(chal_z.clone() * &chal_z).into_repr())
            + ped_pp.g.mul(&delta.into_repr())
            + proof.comm_lc1.mul(&chal_x.into_repr())
            + proof.comm_lc2.mul(&(chal_x.clone() * &chal_x).into_repr());
        debug_assert_eq!(ver1_left, ver1_right);

        let lc_check_bases = vec![ped_pp.g.clone(), ped_pp.h.clone(), comm.clone(), proof.comm_lc1.clone(), proof.comm_lc2.clone()];
        let lc_check_exps = vec![
            proof.t_x.clone() - &delta,
            proof.r_t_x.clone(),
            (chal_z.clone() * &chal_z).neg(),
            chal_x.clone().neg(),
            (chal_x.clone() * &chal_x).neg()
        ];

        let lc_check = VariableBaseMSM::multi_scalar_mul(
            &G::batch_normalization_into_affine(&lc_check_bases),
            &lc_check_exps
                .iter()
                .map(|s| s.into_repr())
                .collect::<Vec<_>>(),
        );
        debug_assert_eq!(lc_check, G::zero());


        let (comm_1, comm_2): (Vec<G>, Vec<G>) = proof.comm_ipa.iter().cloned().unzip();
        let mut ipa_check_bases = pp.g.clone().into_iter()
            .chain(pp.h.clone().into_iter())
            .chain(comm_1.into_iter())
            .chain(comm_2.into_iter())
            .collect::<Vec<G>>();
        ipa_check_bases.append(&mut vec![pp.u.clone(), proof.comm_bits.clone(), proof.comm_blind.clone()]);

        let mut g_agg_chal_exponents = vec![G::ScalarField::one()];
        let mut h_agg_chal_exponents = vec![G::ScalarField::one()];
        for (i, chal_x) in recursive_challenges.iter().rev().enumerate() {
            let chal_x_inv = chal_x.inverse().unwrap();
            for j in 0..(2_usize).pow(i as u32) {
                g_agg_chal_exponents.push(g_agg_chal_exponents[j] * &chal_x_inv);
                h_agg_chal_exponents.push(h_agg_chal_exponents[j] * chal_x);
            }
        }
        debug_assert_eq!(g_agg_chal_exponents.len(), pp.g.len());

        let g_comm_exps = (0..n).map(|_| chal_z.clone().neg()).collect::<Vec<G::ScalarField>>();
        let h_comm_exps = chal_y_powers.iter().zip(two_powers.iter())
            .map(|(y_power, two_power)| chal_z.clone() * y_power + chal_z.clone() * &chal_z * two_power)
            .collect::<Vec<G::ScalarField>>();
        let g_exps = g_agg_chal_exponents.into_iter().zip(g_comm_exps.into_iter())
            .map(|(agg_exp, comm_exp)| agg_exp * &proof.base_a - comm_exp)
            .collect::<Vec<G::ScalarField>>();
        let h_exps = h_agg_chal_exponents.into_iter().zip(h_comm_exps.into_iter()).zip(inverse_y_powers.iter())
            .map(|((agg_exp, comm_exp), y_inv_power)| (agg_exp * &proof.base_b - comm_exp) * y_inv_power)
            .collect::<Vec<G::ScalarField>>();
        let comm_1_exps = recursive_challenges.iter().map(|x| x.clone().neg()).collect::<Vec<G::ScalarField>>();
        let comm_2_exps = recursive_challenges.iter().map(|x| x.clone().inverse().unwrap().neg()).collect::<Vec<G::ScalarField>>();
        let mut ipa_check_exps = g_exps.into_iter()
            .chain(h_exps.into_iter())
            .chain(comm_1_exps.into_iter())
            .chain(comm_2_exps.into_iter())
            .collect::<Vec<G::ScalarField>>();
        ipa_check_exps.append(&mut vec![
            (proof.base_a.clone() * &proof.base_b * &chal_u) - (proof.t_x.clone() * &chal_u - &proof.r_ab),
            G::ScalarField::one().neg(),
            chal_x.clone().neg()
        ]);
        debug_assert_eq!(ipa_check_bases.len(), ipa_check_exps.len());

        let ipa_check = VariableBaseMSM::multi_scalar_mul(
            &G::batch_normalization_into_affine(&ipa_check_bases),
            &ipa_check_exps
                .iter()
                .map(|s| s.into_repr())
                .collect::<Vec<_>>(),
        );
        debug_assert_eq!(ipa_check, G::zero());
        Ok(true)
    }
}

pub fn scalar_powers<F: PrimeField>(num: u64, s: &F) -> Vec<F> {
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
        let (comm, opening) =
            PedersenComm::<G>::commit(&mut rng, &ped_pp, &v.to_bytes_le().1).unwrap();
        let proof = Bulletproofs::<G, Sha3_256>::prove_range(
            &mut rng, &pp, &ped_pp, &comm, &v, &opening, 32,
        )
        .unwrap();
        assert!(
            Bulletproofs::<G, Sha3_256>::verify_range(&pp, &ped_pp, &comm, 32, &proof).unwrap()
        );
    }
}
