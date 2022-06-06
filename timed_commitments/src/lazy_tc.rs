use crate::{
    basic_tc::{BasicTC, Comm as TCComm, Opening as TCOpening, TimeParams},
    Error, PedersenComm, PedersenParams,
};
use ark_ec::ProjectiveCurve;
use ark_ff::{biginteger::BigInteger, PrimeField};
use digest::Digest;
use num_bigint::Sign;
use rand::{CryptoRng, Rng};
use rsa::{
    bigint::{nat_to_f, BigInt},
    hash_to_prime::HashToPrime,
    hog::RsaGroupParams,
    poe::{PoEParams, Proof as PoEProof},
};
use std::{
    hash::{Hash, Hasher},
    marker::PhantomData,
};

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Comm<G: ProjectiveCurve, RsaP: RsaGroupParams> {
    pub ped_comm: G,
    pub tc_comm: TCComm<RsaP>,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Opening<G: ProjectiveCurve, RsaP: RsaGroupParams, H2P: HashToPrime> {
    pub tc_opening: TCOpening<RsaP, H2P>,
    pub tc_m: Option<Vec<u8>>,
    _ped_g: PhantomData<G>,
}

impl<G: ProjectiveCurve, P: RsaGroupParams> Hash for Comm<G, P> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.ped_comm.hash(state);
        self.tc_comm.hash(state);
    }
}

impl<G: ProjectiveCurve, RsaP: RsaGroupParams, H2P: HashToPrime> Opening<G, RsaP, H2P> {
    // Parses Pedersen opening from opening and panics if invalid
    pub fn get_ped_opening(&self) -> G::ScalarField {
        let mut m = self.tc_m.as_ref().unwrap().to_vec();
        let f_bytes = <G::ScalarField as PrimeField>::BigInt::NUM_LIMBS * 8;
        let ped_opening = nat_to_f(&BigInt::from_bytes_be(
            Sign::Plus,
            &m.split_off(m.len() - f_bytes),
        ))
        .unwrap();
        ped_opening
    }
}

pub struct LazyTC<
    G: ProjectiveCurve,
    PoEP: PoEParams,
    RsaP: RsaGroupParams,
    H: Digest,
    H2P: HashToPrime,
> {
    _pedersen_g: PhantomData<G>,
    _tc: PhantomData<BasicTC<PoEP, RsaP, H, H2P>>,
}

impl<G: ProjectiveCurve, PoEP: PoEParams, RsaP: RsaGroupParams, H: Digest, H2P: HashToPrime>
    LazyTC<G, PoEP, RsaP, H, H2P>
{
    pub fn gen_pedersen_params<R: CryptoRng + Rng>(rng: &mut R) -> PedersenParams<G> {
        PedersenComm::<G>::gen_pedersen_params(rng)
    }

    pub fn gen_time_params(t: u64) -> Result<(TimeParams<RsaP>, PoEProof<RsaP, H2P>), Error> {
        BasicTC::<PoEP, RsaP, H, H2P>::gen_time_params(t)
    }

    pub fn gen_time_params_cheating(t: u64, order: &BigInt) -> Result<(TimeParams<RsaP>), Error> {
        BasicTC::<PoEP, RsaP, H, H2P>::gen_time_params_cheating(t, &order)
    }

    pub fn ver_time_params(
        pp: &TimeParams<RsaP>,
        proof: &PoEProof<RsaP, H2P>,
    ) -> Result<bool, Error> {
        BasicTC::<PoEP, RsaP, H, H2P>::ver_time_params(pp, proof)
    }

    pub fn commit<R: CryptoRng + Rng>(
        rng: &mut R,
        time_pp: &TimeParams<RsaP>,
        ped_pp: &PedersenParams<G>,
        m: &[u8],
    ) -> Result<(Comm<G, RsaP>, Opening<G, RsaP, H2P>), Error> {
        let (ped_comm, ped_opening) = PedersenComm::<G>::commit(rng, ped_pp, m)?;
        let mut tc_m = m.to_vec();
        tc_m.append(&mut ped_opening.into_repr().to_bytes_be());
        let (tc_comm, tc_opening) = BasicTC::<PoEP, RsaP, H, H2P>::commit(rng, time_pp, &tc_m)?;
        Ok((
            Comm { ped_comm, tc_comm },
            Opening {
                tc_opening,
                tc_m: Some(tc_m),
                _ped_g: PhantomData,
            },
        ))
    }

    pub fn force_open(
        time_pp: &TimeParams<RsaP>,
        ped_pp: &PedersenParams<G>,
        comm: &Comm<G, RsaP>,
    ) -> Result<(Option<Vec<u8>>, Opening<G, RsaP, H2P>), Error> {
        let (tc_m, tc_opening) = BasicTC::<PoEP, RsaP, H, H2P>::force_open(time_pp, &comm.tc_comm)?;
        match &tc_m {
            Some(tc_m_inner) => {
                let mut m = tc_m_inner.to_vec();
                let f_bytes = <G::ScalarField as PrimeField>::BigInt::NUM_LIMBS * 8;
                match nat_to_f(&BigInt::from_bytes_be(
                    Sign::Plus,
                    &m.split_off(m.len() - f_bytes),
                )) {
                    Ok(ped_opening) => {
                        let ped_valid =
                            PedersenComm::<G>::ver_open(ped_pp, &comm.ped_comm, &m, &ped_opening)?;
                        if ped_valid {
                            Ok((
                                Some(m),
                                Opening {
                                    tc_opening,
                                    tc_m,
                                    _ped_g: PhantomData,
                                },
                            ))
                        } else {
                            Ok((
                                None,
                                Opening {
                                    tc_opening,
                                    tc_m,
                                    _ped_g: PhantomData,
                                },
                            ))
                        }
                    }
                    Err(_) => Ok((
                        None,
                        Opening {
                            tc_opening,
                            tc_m,
                            _ped_g: PhantomData,
                        },
                    )),
                }
            }
            None => Ok((
                None,
                Opening {
                    tc_opening,
                    tc_m,
                    _ped_g: PhantomData,
                },
            )),
        }
    }

    pub fn force_open_cheating(
        time_pp: &TimeParams<RsaP>,
        ped_pp: &PedersenParams<G>,
        comm: &Comm<G, RsaP>,
        order: &BigInt
    ) -> Result<(Option<Vec<u8>>, Opening<G, RsaP, H2P>), Error> {
        let (tc_m, tc_opening) = BasicTC::<PoEP, RsaP, H, H2P>::force_open_cheating(time_pp, &comm.tc_comm, &order)?;
        match &tc_m {
            Some(tc_m_inner) => {
                let mut m = tc_m_inner.to_vec();
                let f_bytes = <G::ScalarField as PrimeField>::BigInt::NUM_LIMBS * 8;
                match nat_to_f(&BigInt::from_bytes_be(
                    Sign::Plus,
                    &m.split_off(m.len() - f_bytes),
                )) {
                    Ok(ped_opening) => {
                        let ped_valid =
                            PedersenComm::<G>::ver_open(ped_pp, &comm.ped_comm, &m, &ped_opening)?;
                        if ped_valid {
                            Ok((
                                Some(m),
                                Opening {
                                    tc_opening,
                                    tc_m,
                                    _ped_g: PhantomData,
                                },
                            ))
                        } else {
                            Ok((
                                None,
                                Opening {
                                    tc_opening,
                                    tc_m,
                                    _ped_g: PhantomData,
                                },
                            ))
                        }
                    }
                    Err(_) => Ok((
                        None,
                        Opening {
                            tc_opening,
                            tc_m,
                            _ped_g: PhantomData,
                        },
                    )),
                }
            }
            None => Ok((
                None,
                Opening {
                    tc_opening,
                    tc_m,
                    _ped_g: PhantomData,
                },
            )),
        }
    }

    pub fn ver_open(
        time_pp: &TimeParams<RsaP>,
        ped_pp: &PedersenParams<G>,
        comm: &Comm<G, RsaP>,
        m: &Option<Vec<u8>>,
        opening: &Opening<G, RsaP, H2P>,
    ) -> Result<bool, Error> {
        let tc_valid = BasicTC::<PoEP, RsaP, H, H2P>::ver_open(
            time_pp,
            &comm.tc_comm,
            &opening.tc_m,
            &opening.tc_opening,
        )?;
        match &opening.tc_m {
            Some(tc_m) => {
                let mut m_computed = tc_m.to_vec();
                let f_bytes = <G::ScalarField as PrimeField>::BigInt::NUM_LIMBS * 8;
                let ped_opening = nat_to_f(&BigInt::from_bytes_be(
                    Sign::Plus,
                    &m_computed.split_off(m_computed.len() - f_bytes),
                ))?;
                let ped_valid =
                    PedersenComm::<G>::ver_open(ped_pp, &comm.ped_comm, &m_computed, &ped_opening)?;
                match m {
                    Some(m) => Ok(tc_valid && ped_valid && m_computed == *m),
                    None => Ok(tc_valid && !ped_valid),
                }
            }
            None => Ok(tc_valid && m.is_none()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::G1Projective as G;
    use once_cell::sync::Lazy;
    use rand::{rngs::StdRng, SeedableRng};
    use rsa::hash_to_prime::pocklington::{PocklingtonCertParams, PocklingtonHash};
    use sha3::Keccak256;
    use std::str::FromStr;

    use rsa::hog::RsaHiddenOrderGroup;

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

    pub type TC = LazyTC<
        G,
        TestPoEParams,
        TestRsaParams,
        Keccak256,
        PocklingtonHash<TestPocklingtonParams, Keccak256>,
    >;

    #[test]
    fn lazy_tc_test() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let mut m = [1u8; 8];
        rng.fill(&mut m);

        let (time_pp, _) = TC::gen_time_params(40).unwrap();

        let ped_pp = TC::gen_pedersen_params(&mut rng);

        let (comm, self_opening) = TC::commit(&mut rng, &time_pp, &ped_pp, &m).unwrap();
        assert!(TC::ver_open(&time_pp, &ped_pp, &comm, &Some(m.to_vec()), &self_opening).unwrap());

        let (force_m, force_opening) = TC::force_open(&time_pp, &ped_pp, &comm).unwrap();
        assert!(TC::ver_open(&time_pp, &ped_pp, &comm, &force_m, &force_opening).unwrap());
        assert_eq!(force_m, Some(m.to_vec()));

        // Bad message
        let mut m_bad = m.to_vec();
        m_bad[0] = m_bad[0] + 1u8;
        assert!(!TC::ver_open(
            &time_pp,
            &ped_pp,
            &comm,
            &Some(m_bad.to_vec()),
            &self_opening
        )
        .unwrap());
        assert!(!TC::ver_open(
            &time_pp,
            &ped_pp,
            &comm,
            &Some(m_bad.to_vec()),
            &force_opening
        )
        .unwrap());
        assert!(!TC::ver_open(&time_pp, &ped_pp, &comm, &None, &self_opening).unwrap());
        assert!(!TC::ver_open(&time_pp, &ped_pp, &comm, &None, &force_opening).unwrap());

        // Bad commitment
        let mut tc_input_group_element_bad = comm.clone();
        tc_input_group_element_bad.tc_comm.x = RsaHiddenOrderGroup::from_nat(BigInt::from(2));
        let (force_m_bad, force_opening_bad) =
            TC::force_open(&time_pp, &ped_pp, &tc_input_group_element_bad).unwrap();
        assert!(force_m_bad.is_none());
        assert!(TC::ver_open(
            &time_pp,
            &ped_pp,
            &tc_input_group_element_bad,
            &force_m_bad,
            &force_opening_bad
        )
        .unwrap());

        let mut tc_ae_ct_bad = comm.clone();
        tc_ae_ct_bad.tc_comm.ct[0] += 1u8;
        let (force_m_bad, force_opening_bad) =
            TC::force_open(&time_pp, &ped_pp, &tc_ae_ct_bad).unwrap();
        assert!(force_m_bad.is_none());
        assert!(TC::ver_open(
            &time_pp,
            &ped_pp,
            &tc_ae_ct_bad,
            &force_m_bad,
            &force_opening_bad
        )
        .unwrap());

        let mut ped_comm_bad = comm.clone();
        ped_comm_bad.ped_comm = ped_pp.g.clone();
        let (force_m_bad, force_opening_bad) =
            TC::force_open(&time_pp, &ped_pp, &ped_comm_bad).unwrap();
        assert!(force_m_bad.is_none());
        assert!(TC::ver_open(
            &time_pp,
            &ped_pp,
            &ped_comm_bad,
            &force_m_bad,
            &force_opening_bad
        )
        .unwrap());
    }
}
