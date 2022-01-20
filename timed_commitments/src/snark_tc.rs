use ark_ec::ProjectiveCurve;
use ark_ff::{biginteger::BigInteger, PrimeField, ToConstraintField};
use ark_r1cs_std::{fields::fp::FpVar, prelude::*};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_snark::SNARK;
use ark_sponge::{
    constraints::CryptographicSpongeVar,
    poseidon::{constraints::PoseidonSpongeVar, PoseidonParameters, PoseidonSponge},
    CryptographicSponge,
};

use digest::Digest;
use num_bigint::RandBigInt;
use num_traits::One;
use once_cell::sync::Lazy;
use rand::{CryptoRng, Rng};

use rsa::{
    bigint::{
        constraints::{BigIntCircuitParams, BigIntVar},
        BigInt,
    },
    hog::{constraints::RsaHogVar, RsaGroupParams, RsaHiddenOrderGroup},
    poe::{PoE, PoEParams, Proof as PoEProof},
};

use crate::{
    basic_tc::{BasicTC, TimeParams},
    Error, PedersenComm, PedersenParams,
};
use rsa::bigint::nat_to_limbs;
use std::{fmt::Debug, marker::PhantomData, ops::Deref};

pub type Hog<P> = RsaHiddenOrderGroup<P>;

pub trait SnarkTCParams<F: PrimeField>: Clone + Eq + Debug + Send + Sync {
    const M_LEN: usize; // Length of message in bytes
    const POSEIDON_PARAMS: Lazy<PoseidonParameters<F>>;
    const TC_RANDOMIZER_BIT_LEN: usize; // Length of randomizer in bits (for 64-bit testing)
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Comm<G: ProjectiveCurve, RsaP: RsaGroupParams> {
    ped_comm: G,
    x: Hog<RsaP>,
    ct: Vec<u8>,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Opening<G: ProjectiveCurve, RsaP: RsaGroupParams, D: Digest> {
    SELF(G::ScalarField),
    FORCE(Hog<RsaP>, PoEProof<RsaP, D>),
}

/// Non-malleable timed commitment using key-committing authenticated encryption
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SnarkTC<
    F: PrimeField,
    PS: SNARK<F>,
    P: SnarkTCParams<F>,
    PoEP: PoEParams,
    RsaP: RsaGroupParams,
    IntP: BigIntCircuitParams,
    D: Digest,
    G: ProjectiveCurve,
    GV: CurveVar<G, F>,
> {
    _field: PhantomData<F>,
    _snark: PhantomData<PS>,
    _params: PhantomData<P>,
    _poe_params: PhantomData<PoEP>,
    _rsa_params: PhantomData<RsaP>,
    _int_params: PhantomData<IntP>,
    _hash: PhantomData<D>,
    _pedersen_g: PhantomData<G>,
    _pedersen_g_var: PhantomData<GV>,
}

impl<F, PS, P, PoEP, RsaP, IntP, D, G, GV> SnarkTC<F, PS, P, PoEP, RsaP, IntP, D, G, GV>
where
    F: PrimeField,
    PS: SNARK<F>,
    P: SnarkTCParams<F>,
    PoEP: PoEParams,
    RsaP: RsaGroupParams,
    IntP: BigIntCircuitParams,
    D: Digest,
    G: ProjectiveCurve + ToConstraintField<F>,
    GV: CurveVar<G, F>,
{
    pub fn gen_pedersen_params<R: CryptoRng + Rng>(rng: &mut R) -> PedersenParams<G> {
        PedersenComm::<G>::gen_pedersen_params(rng)
    }

    pub fn gen_time_params(t: u32) -> Result<(TimeParams<RsaP>, PoEProof<RsaP, D>), Error> {
        BasicTC::<PoEP, RsaP, D>::gen_time_params(t)
    }

    pub fn ver_time_params(
        pp: &TimeParams<RsaP>,
        proof: &PoEProof<RsaP, D>,
    ) -> Result<bool, Error> {
        BasicTC::<PoEP, RsaP, D>::ver_time_params(pp, proof)
    }

    pub fn commit<R: CryptoRng + Rng>(
        rng: &mut R,
        time_pp: &TimeParams<RsaP>,
        ped_pp: &PedersenParams<G>,
        snark_pp: &PS::ProvingKey,
        m: &[u8],
    ) -> Result<(Comm<G, RsaP>, Opening<G, RsaP, D>, PS::Proof), Error> {
        let mut m = m.to_vec();
        m.resize(P::M_LEN, 0u8);
        let (ped_comm, ped_opening) = PedersenComm::<G>::commit(rng, ped_pp, &m)?;
        let r = BigInt::from(rng.gen_biguint(P::TC_RANDOMIZER_BIT_LEN as u64));
        let x = time_pp.x.power(&r);
        let y = time_pp.y.power(&r);

        // Hash y to get blinding pad
        let mut hasher = PoseidonSponge::<F>::new(&P::POSEIDON_PARAMS);
        hasher.absorb(&y.n.to_bytes_le().1);
        let pad = hasher.squeeze_bytes(P::M_LEN);

        // XOR message with blinding pad
        let ct = pad
            .iter()
            .zip(m.iter())
            .map(|(x1, x2)| x1 ^ x2)
            .collect::<Vec<u8>>();

        // Use SNARK to prove commitment is formed correctly
        let comm = Comm { ped_comm, x, ct };
        let circuit = TCCircuit::<F, P, RsaP, IntP, G, GV> {
            time_params: time_pp.clone(),
            ped_params: ped_pp.clone(),
            comm: comm.clone(),
            ped_opening: ped_opening.clone(),
            time_pp_r: r,
            m: m,
            _params: PhantomData,
            _int_params: PhantomData,
            _field: PhantomData,
            _ped_g_var: PhantomData,
        };

        let proof = PS::prove(snark_pp, circuit, rng)?;
        Ok((comm, Opening::SELF(ped_opening), proof))
    }

    pub fn ver_comm(
        pp: &TimeParams<RsaP>,
        snark_pp: &PS::VerifyingKey,
        comm: &Comm<G, RsaP>,
        proof: &PS::Proof,
    ) -> Result<bool, Error> {
        //TODO: Handle error instead of unwrap
        Ok(PS::verify(
            &snark_pp,
            &TCCircuitPublicInput::<RsaP, IntP, G> {
                time_params: pp.clone(),
                comm: comm.clone(),
                _int_params: PhantomData,
            }
            .to_field_elements()
            .unwrap(),
            proof,
        )
        .unwrap())
    }

    pub fn force_open(
        time_pp: &TimeParams<RsaP>,
        _ped_pp: &PedersenParams<G>,
        comm: &Comm<G, RsaP>,
    ) -> Result<(Vec<u8>, Opening<G, RsaP, D>), Error> {
        // Compute and prove repeated square
        let y = comm.x.power(&BigInt::from(2).pow(time_pp.t));
        let proof = PoE::<PoEP, RsaP, D>::prove(&comm.x, &y, time_pp.t)?;

        // Hash y to get blinding pad
        let mut hasher = PoseidonSponge::<F>::new(&P::POSEIDON_PARAMS);
        hasher.absorb(&y.n.to_bytes_le().1);
        let pad = hasher.squeeze_bytes(P::M_LEN);

        // XOR ciphertext with blinding pad
        assert_eq!(comm.ct.len(), P::M_LEN);
        let m = pad
            .iter()
            .zip(comm.ct.iter())
            .map(|(x1, x2)| x1 ^ x2)
            .collect::<Vec<u8>>();

        let opening = Opening::FORCE(y, proof);
        Ok((m, opening))
    }

    pub fn ver_open(
        time_pp: &TimeParams<RsaP>,
        ped_pp: &PedersenParams<G>,
        comm: &Comm<G, RsaP>,
        m: &[u8],
        opening: &Opening<G, RsaP, D>,
    ) -> Result<bool, Error> {
        match opening {
            Opening::SELF(r) => PedersenComm::ver_open(ped_pp, &comm.ped_comm, m, r),
            Opening::FORCE(y, proof) => {
                let proof_valid = PoE::<PoEP, RsaP, D>::verify(&comm.x, y, time_pp.t, proof)?;

                // Hash y to get blinding pad
                let mut hasher = PoseidonSponge::<F>::new(&P::POSEIDON_PARAMS);
                hasher.absorb(&y.n.to_bytes_le().1);
                let pad = hasher.squeeze_bytes(P::M_LEN);

                // XOR ciphertext with blinding pad
                assert_eq!(comm.ct.len(), P::M_LEN);
                let dec_m = pad
                    .iter()
                    .zip(comm.ct.iter())
                    .map(|(x1, x2)| x1 ^ x2)
                    .collect::<Vec<u8>>();

                Ok(proof_valid && m == &dec_m)
            },
        }
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TCCircuit<F, P, RsaP, IntP, G, GV>
where
    F: PrimeField,
    P: SnarkTCParams<F>,
    RsaP: RsaGroupParams,
    IntP: BigIntCircuitParams,
    G: ProjectiveCurve,
    GV: CurveVar<G, F>,
{
    time_params: TimeParams<RsaP>,
    ped_params: PedersenParams<G>,
    comm: Comm<G, RsaP>,
    ped_opening: G::ScalarField,
    time_pp_r: BigInt,
    m: Vec<u8>,
    _params: PhantomData<P>,
    _int_params: PhantomData<IntP>,
    _field: PhantomData<F>,
    _ped_g_var: PhantomData<GV>,
}

impl<F, P, RsaP, IntP, G, GV> ConstraintSynthesizer<F> for TCCircuit<F, P, RsaP, IntP, G, GV>
where
    F: PrimeField,
    P: SnarkTCParams<F>,
    RsaP: RsaGroupParams,
    IntP: BigIntCircuitParams,
    G: ProjectiveCurve,
    GV: CurveVar<G, F>,
{
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        // Allocate constants
        let modulus = BigIntVar::<F, IntP>::new_constant(
            ark_relations::ns!(cs, "rsa_modulus"),
            RsaP::M.deref(),
        )?;
        let x = RsaHogVar::<F, RsaP, IntP>::new_constant(
            ark_relations::ns!(cs, "rsa_generator"),
            &self.time_params.x,
        )?;
        let g = <GV as AllocVar<G, F>>::new_constant(
            ark_relations::ns!(cs, "ped_generator_g"),
            &self.ped_params.g,
        )?;
        let h = <GV as AllocVar<G, F>>::new_constant(
            ark_relations::ns!(cs, "ped_generator_h"),
            &self.ped_params.h,
        )?;
        let mut hasher = PoseidonSpongeVar::new(
            ark_relations::ns!(cs, "poseidon_hasher").cs(),
            &P::POSEIDON_PARAMS,
        );

        // Allocate public inputs
        let y = RsaHogVar::<F, RsaP, IntP>::new_input(
            ark_relations::ns!(cs, "rsa_time_output"),
            || Ok(&self.time_params.y),
        )?;
        let comm_x =
            RsaHogVar::<F, RsaP, IntP>::new_input(ark_relations::ns!(cs, "comm_x"), || {
                Ok(&self.comm.x)
            })?;
        let comm_ped =
            <GV as AllocVar<G, F>>::new_input(ark_relations::ns!(cs, "comm_ped"), || {
                Ok(&self.comm.ped_comm)
            })?;
        let comm_ct_f =
            <Vec<FpVar<F>>>::new_input(ark_relations::ns!(cs, "comm_ct_as_field"), || {
                Ok(self.comm.ct.to_field_elements().unwrap())
            })?;
        let mut comm_ct = comm_ct_f
            .iter()
            .map(|f_var| f_var.to_bytes())
            .collect::<Result<Vec<Vec<UInt8<F>>>, SynthesisError>>()?
            .into_iter()
            .flatten()
            .collect::<Vec<UInt8<F>>>();
        comm_ct.truncate(P::M_LEN);

        // Allocate witness inputs
        let ped_opening =
            <Vec<Boolean<F>>>::new_witness(ark_relations::ns!(cs, "ped_opening"), || {
                Ok(self.ped_opening.into_repr().to_bits_le())
            })?;
        //TODO: Change witness to bits input
        let tc_r =
            BigIntVar::<F, IntP>::new_witness(ark_relations::ns!(cs, "tc_randomizer"), || {
                Ok(&self.time_pp_r)
            })?;
        debug_assert_eq!(self.m.len(), P::M_LEN);
        let m =
            <Vec<UInt8<F>>>::new_witness(ark_relations::ns!(cs, "tc_randomizer"), || Ok(self.m))?;

        // Generate constraints
        let computed_ped_comm =
            g.scalar_mul_le(m.to_bits_le()?.iter())? + h.scalar_mul_le(ped_opening.iter())?;
        comm_ped.enforce_equal(&computed_ped_comm)?;

        let computed_tc_x = x.power(&tc_r, &modulus, P::TC_RANDOMIZER_BIT_LEN)?;
        comm_x.enforce_equal(&computed_tc_x)?;

        let tc_y = y.power(&tc_r, &modulus, P::TC_RANDOMIZER_BIT_LEN)?;
        hasher.absorb(&tc_y.to_bytes()?)?;
        let pad = hasher.squeeze_bytes(P::M_LEN)?;
        let computed_ct = pad
            .iter()
            .zip(m.iter())
            .map(|(x1, x2)| x1.xor(x2))
            .collect::<Result<Vec<UInt8<F>>, SynthesisError>>()?;
        comm_ct.enforce_equal(&computed_ct)?;
        Ok(())
    }
}

impl<F, P, RsaP, IntP, G, GV> TCCircuit<F, P, RsaP, IntP, G, GV>
where
    F: PrimeField,
    P: SnarkTCParams<F>,
    RsaP: RsaGroupParams,
    IntP: BigIntCircuitParams,
    G: ProjectiveCurve,
    GV: CurveVar<G, F>,
{
    pub fn default(time_pp: &TimeParams<RsaP>, ped_pp: &PedersenParams<G>) -> Self {
        let mut default_m = Vec::new();
        default_m.resize(P::M_LEN, 0u8);

        Self {
            time_params: time_pp.clone(),
            ped_params: ped_pp.clone(),
            comm: Comm {
                ped_comm: Default::default(),
                x: Default::default(),
                ct: default_m.clone(),
            },
            ped_opening: Default::default(),
            time_pp_r: BigInt::one(),
            m: default_m.clone(),
            _params: PhantomData,
            _int_params: PhantomData,
            _field: PhantomData,
            _ped_g_var: PhantomData,
        }
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TCCircuitPublicInput<RsaP, IntP, G>
where
    RsaP: RsaGroupParams,
    IntP: BigIntCircuitParams,
    G: ProjectiveCurve,
{
    time_params: TimeParams<RsaP>,
    comm: Comm<G, RsaP>,
    _int_params: PhantomData<IntP>,
}

impl<F: PrimeField, RsaP, IntP, G> ToConstraintField<F> for TCCircuitPublicInput<RsaP, IntP, G>
where
    RsaP: RsaGroupParams,
    IntP: BigIntCircuitParams,
    G: ProjectiveCurve + ToConstraintField<F>,
{
    fn to_field_elements(&self) -> Option<Vec<F>> {
        //TODO: Handle option instead of unwrap
        let mut out = Vec::<F>::new();
        out.append(
            &mut nat_to_limbs(&self.time_params.y.n, IntP::LIMB_WIDTH, IntP::N_LIMBS).unwrap(),
        );
        out.append(&mut nat_to_limbs(&self.comm.x.n, IntP::LIMB_WIDTH, IntP::N_LIMBS).unwrap());
        out.append(&mut self.comm.ped_comm.to_field_elements().unwrap());
        out.append(&mut self.comm.ct.to_field_elements().unwrap());
        Some(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::{Bls12_381, Fr as F};
    use ark_ed_on_bls12_381::{constraints::EdwardsVar as GV, EdwardsProjective as G};
    use ark_groth16::Groth16;
    use ark_std::{end_timer, start_timer};

    use once_cell::sync::Lazy;
    use rand::{rngs::StdRng, SeedableRng};
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
    pub struct BigNatTestParams;

    impl BigIntCircuitParams for BigNatTestParams {
        const LIMB_WIDTH: usize = 64;
        const N_LIMBS: usize = 32;
    }

    #[derive(Clone, PartialEq, Eq, Debug)]
    pub struct TestRsa512Params;

    impl RsaGroupParams for TestRsa512Params {
        const G: Lazy<BigInt> = Lazy::new(|| BigInt::from(2));
        const M: Lazy<BigInt> = Lazy::new(|| {
            BigInt::from_str(
                "11834783464130424096695514462778\
                                     87028026498993885732873780720562\
                                     30692915355259527228479136942963\
                                     92927890261736769191982212777933\
                                     726583565708193466779811767",
            )
            .unwrap()
        });
    }

    #[derive(Clone, PartialEq, Eq, Debug)]
    pub struct BigNat512TestParams;

    impl BigIntCircuitParams for BigNat512TestParams {
        const LIMB_WIDTH: usize = 32;
        const N_LIMBS: usize = 16;
    }

    #[derive(Clone, PartialEq, Eq, Debug)]
    pub struct TestRsa64Params;

    impl RsaGroupParams for TestRsa64Params {
        const G: Lazy<BigInt> = Lazy::new(|| BigInt::from(2));
        const M: Lazy<BigInt> = Lazy::new(|| BigInt::from_str("17839761582542106619").unwrap());
    }

    #[derive(Clone, PartialEq, Eq, Debug)]
    pub struct BigNat64TestParams;

    impl BigIntCircuitParams for BigNat64TestParams {
        const LIMB_WIDTH: usize = 32;
        const N_LIMBS: usize = 2;
    }

    #[derive(Clone, PartialEq, Eq, Debug)]
    pub struct TestPoEParams;

    impl PoEParams for TestPoEParams {
        const HASH_TO_PRIME_ENTROPY: usize = 128;
    }

    #[derive(Clone, PartialEq, Eq, Debug)]
    pub struct TestSnarkTCParams;

    impl SnarkTCParams<F> for TestSnarkTCParams {
        const M_LEN: usize = 16;
        const POSEIDON_PARAMS: Lazy<PoseidonParameters<F>> =
            Lazy::new(|| poseidon_parameters_for_test());
        const TC_RANDOMIZER_BIT_LEN: usize = 128;
    }

    #[derive(Clone, PartialEq, Eq, Debug)]
    pub struct TestSnarkTC64Params;

    impl SnarkTCParams<F> for TestSnarkTC64Params {
        const M_LEN: usize = 8;
        const POSEIDON_PARAMS: Lazy<PoseidonParameters<F>> =
            Lazy::new(|| poseidon_parameters_for_test());
        const TC_RANDOMIZER_BIT_LEN: usize = 32;
    }


    pub type Circuit = TCCircuit<F, TestSnarkTCParams, TestRsaParams, BigNatTestParams, G, GV>;
    pub type TC = SnarkTC<
        F,
        Groth16<Bls12_381>,
        TestSnarkTCParams,
        TestPoEParams,
        TestRsaParams,
        BigNatTestParams,
        Sha3_256,
        G,
        GV,
    >;

    pub type Circuit512 =
        TCCircuit<F, TestSnarkTCParams, TestRsa512Params, BigNat512TestParams, G, GV>;
    pub type TC512 = SnarkTC<
        F,
        Groth16<Bls12_381>,
        TestSnarkTCParams,
        TestPoEParams,
        TestRsa512Params,
        BigNat512TestParams,
        Sha3_256,
        G,
        GV,
    >;

    pub type Circuit64 =
        TCCircuit<F, TestSnarkTC64Params, TestRsa64Params, BigNat64TestParams, G, GV>;
    pub type TC64 = SnarkTC<
        F,
        Groth16<Bls12_381>,
        TestSnarkTC64Params,
        TestPoEParams,
        TestRsa64Params,
        BigNat64TestParams,
        Sha3_256,
        G,
        GV,
    >;

    #[test]
    fn snark_tc_64_test() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let mut m = [1u8; 8];
        rng.fill(&mut m);

        let (time_pp, _) = TC64::gen_time_params(40).unwrap();
        let ped_pp = TC64::gen_pedersen_params(&mut rng);
        let (pk, vk) = Groth16::<Bls12_381>::circuit_specific_setup(
            Circuit64::default(&time_pp, &ped_pp),
            &mut rng,
        )
        .unwrap();

        let (comm, self_opening, proof) =
            TC64::commit(&mut rng, &time_pp, &ped_pp, &pk, &m).unwrap();
        assert!(TC64::ver_comm(&time_pp, &vk, &comm, &proof,).unwrap());
        assert!(TC64::ver_open(&time_pp, &ped_pp, &comm, &m, &self_opening).unwrap());

        let (force_m, force_opening) = TC64::force_open(&time_pp, &ped_pp, &comm).unwrap();
        assert_eq!(force_m, m.to_vec());
        assert!(TC64::ver_open(&time_pp, &ped_pp, &comm, &m, &force_opening).unwrap());
    }

    #[test]
    #[ignore] // Expensive test, run with ``cargo test snark_tc_512_test --release -- --ignored --nocapture``
    fn snark_tc_512_test() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let mut m = [1u8; 16];
        rng.fill(&mut m);

        let (time_pp, _) = TC512::gen_time_params(40).unwrap();
        let ped_pp = TC512::gen_pedersen_params(&mut rng);
        let (pk, vk) = Groth16::<Bls12_381>::circuit_specific_setup(
            Circuit512::default(&time_pp, &ped_pp),
            &mut rng,
        )
        .unwrap();

        let proof_gen = start_timer!(|| "Compute proof");
        let (comm, self_opening, proof) =
            TC512::commit(&mut rng, &time_pp, &ped_pp, &pk, &m).unwrap();
        end_timer!(proof_gen);
        assert!(TC512::ver_comm(&time_pp, &vk, &comm, &proof,).unwrap());
        assert!(TC512::ver_open(&time_pp, &ped_pp, &comm, &m, &self_opening).unwrap());

        let (force_m, force_opening) = TC512::force_open(&time_pp, &ped_pp, &comm).unwrap();
        assert_eq!(force_m, m.to_vec());
        assert!(TC512::ver_open(&time_pp, &ped_pp, &comm, &m, &force_opening).unwrap());
    }

    #[test]
    #[ignore] // Expensive test, run with ``cargo test snark_tc_2048_test --release -- --ignored --nocapture``
    fn snark_tc_2048_test() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let mut m = [1u8; 16];
        rng.fill(&mut m);

        let (time_pp, _) = TC::gen_time_params(40).unwrap();
        let ped_pp = TC::gen_pedersen_params(&mut rng);
        let (pk, vk) = Groth16::<Bls12_381>::circuit_specific_setup(
            Circuit::default(&time_pp, &ped_pp),
            &mut rng,
        )
        .unwrap();

        let proof_gen = start_timer!(|| "Compute proof");
        let (comm, self_opening, proof) = TC::commit(&mut rng, &time_pp, &ped_pp, &pk, &m).unwrap();
        end_timer!(proof_gen);
        assert!(TC::ver_comm(&time_pp, &vk, &comm, &proof,).unwrap());
        assert!(TC::ver_open(&time_pp, &ped_pp, &comm, &m, &self_opening).unwrap());

        let (force_m, force_opening) = TC::force_open(&time_pp, &ped_pp, &comm).unwrap();
        assert_eq!(force_m, m.to_vec());
        assert!(TC::ver_open(&time_pp, &ped_pp, &comm, &m, &force_opening).unwrap());
    }

    fn poseidon_parameters_for_test<F: PrimeField>() -> PoseidonParameters<F> {
        let alpha = 17;
        let mds = vec![
            vec![
                F::from_str(
                    "43228725308391137369947362226390319299014033584574058394339561338097152657858",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "20729134655727743386784826341366384914431326428651109729494295849276339718592",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "14275792724825301816674509766636153429127896752891673527373812580216824074377",
                )
                .map_err(|_| ())
                .unwrap(),
            ],
            vec![
                F::from_str(
                    "3039440043015681380498693766234886011876841428799441709991632635031851609481",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "6678863357926068615342013496680930722082156498064457711885464611323928471101",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "37355038393562575053091209735467454314247378274125943833499651442997254948957",
                )
                .map_err(|_| ())
                .unwrap(),
            ],
            vec![
                F::from_str(
                    "26481612700543967643159862864328231943993263806649000633819754663276818191580",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "30103264397473155564098369644643015994024192377175707604277831692111219371047",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "5712721806190262694719203887224391960978962995663881615739647362444059585747",
                )
                .map_err(|_| ())
                .unwrap(),
            ],
        ];
        let ark = vec![
            vec![
                F::from_str(
                    "44595993092652566245296379427906271087754779418564084732265552598173323099784",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "23298463296221002559050231199021122673158929708101049474262017406235785365706",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "34212491019164671611180318500074499609633402631511849759183986060951187784466",
                )
                .map_err(|_| ())
                .unwrap(),
            ],
            vec![
                F::from_str(
                    "19098051134080182375553680073525644187968170656591203562523489333616681350367",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "7027675418691353855077049716619550622043312043660992344940177187528247727783",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "47642753235356257928619065424282314733361764347085604019867862722762702755609",
                )
                .map_err(|_| ())
                .unwrap(),
            ],
            vec![
                F::from_str(
                    "24281836129477728386327945482863886685457469794572168729834072693507088619997",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "12624893078331920791384400430193929292743809612452779381349824703573823883410",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "22654862987689323504199204643771547606936339944127455903448909090318619188561",
                )
                .map_err(|_| ())
                .unwrap(),
            ],
            vec![
                F::from_str(
                    "27229172992560143399715985732065737093562061782414043625359531774550940662372",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "13224952063922250960936823741448973692264041750100990569445192064567307041002",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "40380869235216625717296601204704413215735530626882135230693823362552484855508",
                )
                .map_err(|_| ())
                .unwrap(),
            ],
            vec![
                F::from_str(
                    "4245751157938905689397184705633683893932492370323323780371834663438472308145",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "8252156875535418429533049587170755750275631534314711502253775796882240991261",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "32910829712934971129644416249914075073083903821282503505466324428991624789936",
                )
                .map_err(|_| ())
                .unwrap(),
            ],
            vec![
                F::from_str(
                    "49412601297460128335642438246716127241669915737656789613664349252868389975962",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "841661305510340459373323516098909074520942972558284146843779636353111592117",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "37926489020263024391336570420006226544461516787280929232555625742588667303947",
                )
                .map_err(|_| ())
                .unwrap(),
            ],
            vec![
                F::from_str(
                    "18433043696013996573551852847056868761017170818820490351056924728720017242180",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "45376910275288438312773930242803223482318753992595269901397542214841496212310",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "47854349410014339708332226068958253098964727682486278458389508597930796651514",
                )
                .map_err(|_| ())
                .unwrap(),
            ],
            vec![
                F::from_str(
                    "32638426693771251366613055506166587312642876874690861030672730491779486904360",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "19105439281696418043426755774110765432959446684037017837894045255490581318047",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "13484299981373196201166722380389594773562113262309564134825386266765751213853",
                )
                .map_err(|_| ())
                .unwrap(),
            ],
            vec![
                F::from_str(
                    "63360321133852659797114062808297090090814531427710842859827725871241144161",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "42427543035537409467993338717379268954936885184662765745740070438835506287271",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "149101987103211771991327927827692640556911620408176100290586418839323044234",
                )
                .map_err(|_| ())
                .unwrap(),
            ],
            vec![
                F::from_str(
                    "8341764062226826803887898710015561861526081583071950015446833446251359696930",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "45635980415044299013530304465786867101223925975971912073759959440335364441441",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "49833261156201520743834327917353893365097424877680239796845398698940689734850",
                )
                .map_err(|_| ())
                .unwrap(),
            ],
            vec![
                F::from_str(
                    "26764715016591436228000634284249890185894507497739511725029482580508707525029",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "25054530812095491217523557726611612265064441619646263299990388543372685322499",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "47654590955096246997622155031169641628093104787883934397920286718814889326452",
                )
                .map_err(|_| ())
                .unwrap(),
            ],
            vec![
                F::from_str(
                    "16463825890556752307085325855351334996898686633642574805918056141310194135796",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "17473961341633494489168064889016732306117097771640351649096482400214968053040",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "49914603434867854893558366922996753035832008639512305549839666311012232077468",
                )
                .map_err(|_| ())
                .unwrap(),
            ],
            vec![
                F::from_str(
                    "17122578514152308432111470949473865420090463026624297565504381163777697818362",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "34870689836420861427379101859113225049736283485335674111421609473028315711541",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "4622082908476410083286670201138165773322781640914243047922441301693321472984",
                )
                .map_err(|_| ())
                .unwrap(),
            ],
            vec![
                F::from_str(
                    "6079244375752010013798561155333454682564824861645642293573415833483620500976",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "2635090520059500019661864086615522409798872905401305311748231832709078452746",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "19070766579582338321241892986615538320421651429118757507174186491084617237586",
                )
                .map_err(|_| ())
                .unwrap(),
            ],
            vec![
                F::from_str(
                    "12622420533971517050761060317049369208980632120901481436392835424625664738526",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "8965101225657199137904506150282256568170501907667138404080397024857524386266",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "27085091008069524593196374148553176565775450537072498305327481366756159319838",
                )
                .map_err(|_| ())
                .unwrap(),
            ],
            vec![
                F::from_str(
                    "45929056591150668409624595495643698205830429971690813312608217341940499221218",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "50361689160518167880500080025023064746137161030119436080957023803101861300846",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "6722586346537620732668048024627882970582133613352245923413730968378696371065",
                )
                .map_err(|_| ())
                .unwrap(),
            ],
            vec![
                F::from_str(
                    "7340485916200743279276570085958556798507770452421357119145466906520506506342",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "25946733168219652706630789514519162148860502996914241011500280690204368174083",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "9962367658743163006517635070396368828381757404628822422306438427554934645464",
                )
                .map_err(|_| ())
                .unwrap(),
            ],
            vec![
                F::from_str(
                    "7221669722700687417346373353960536661883467014204005276831020252277657076044",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "21487980358388383563030903293359140836304488103090321183948009095669344637431",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "44389482047246878765773958430749333249729101516826571588063797358040130313157",
                )
                .map_err(|_| ())
                .unwrap(),
            ],
            vec![
                F::from_str(
                    "32887270862917330820874162842519225370447850172085449103568878409533683733185",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "15453393396765207016379045014101989306173462885430532298601655955681532648226",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "5478929644476681096437469958231489102974161353940993351588559414552523375472",
                )
                .map_err(|_| ())
                .unwrap(),
            ],
            vec![
                F::from_str(
                    "41981370411247590312677561209178363054744730805951096631186178388981705304138",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "3474136981645476955784428843999869229067282976757744542648188369810577298585",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "26251477770740399889956219915654371915771248171098220204692699710414817081869",
                )
                .map_err(|_| ())
                .unwrap(),
            ],
            vec![
                F::from_str(
                    "51916561889718854106125837319509539220778634838409949714061033196765117231752",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "25355145802812435959748831835587713214179184608408449220418373832038339021974",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "31950684570730625275416731570246297947385359051792335826965013637877068017530",
                )
                .map_err(|_| ())
                .unwrap(),
            ],
            vec![
                F::from_str(
                    "40966378914980473680181850710703295982197782082391794594149984057481543436879",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "1141315130963422417761731263662398620858625339733452795772225916965481730059",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "9812100862165422922235757591915383485338044715409891361026651619010947646011",
                )
                .map_err(|_| ())
                .unwrap(),
            ],
            vec![
                F::from_str(
                    "25276091996614379065765602410190790163396484122487585763380676888280427744737",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "18512694312063606403196469408971540495273694846641903978723927656359350642619",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "5791584766415439694303685437881192048262049244830616851865505314899699012588",
                )
                .map_err(|_| ())
                .unwrap(),
            ],
            vec![
                F::from_str(
                    "34501536331706470927069149344450300773777486993504673779438188495686129846168",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "10797737565565774079718466476236831116206064650762676383469703413649447678207",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "42599392747310354323136214835734307933597896695637215127297036595538235868368",
                )
                .map_err(|_| ())
                .unwrap(),
            ],
            vec![
                F::from_str(
                    "1336670998775417133322626564820911986969949054454812685145275612519924150700",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "2630141283339761901081411552890260088516693208402906795133548756078952896770",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "5206688943117414740600380377278238268309952400341418217132724749372435975215",
                )
                .map_err(|_| ())
                .unwrap(),
            ],
            vec![
                F::from_str(
                    "10739264253827005683370721104077252560524362323422172665530191908848354339715",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "48010640624945719826344492755710886355389194986527731603685956726907395779674",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "47880724693177306044229143357252697148359033158394459365791331000715957339701",
                )
                .map_err(|_| ())
                .unwrap(),
            ],
            vec![
                F::from_str(
                    "51658938856669444737833983076793759752280196674149218924101718974926964118996",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "27558055650076329657496888512074319504342606463881203707330358472954748913263",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "38886981777859313701520424626728402175860609948757992393598285291689196608037",
                )
                .map_err(|_| ())
                .unwrap(),
            ],
            vec![
                F::from_str(
                    "17152756165118461969542990684402410297675979513690903033350206658079448802479",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "43766946932033687220387514221943418338304186408056458476301583041390483707207",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "24324495647041812436929170644873622904287038078113808264580396461953421400343",
                )
                .map_err(|_| ())
                .unwrap(),
            ],
            vec![
                F::from_str(
                    "6935839211798937659784055008131602708847374430164859822530563797964932598700",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "42126767398190942911395299419182514513368023621144776598842282267908712110039",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "5702364486091252903915715761606014714345316580946072019346660327857498603375",
                )
                .map_err(|_| ())
                .unwrap(),
            ],
            vec![
                F::from_str(
                    "28184981699552917714085740963279595942132561155181044254318202220270242523053",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "27078204494010940048327822707224393686245007379331357330801926151074766130790",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "5004172841233947987988267535285080365124079140142987718231874743202918551203",
                )
                .map_err(|_| ())
                .unwrap(),
            ],
            vec![
                F::from_str(
                    "7974360962120296064882769128577382489451060235999590492215336103105134345602",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "48062035869818179910046292951628308709251170031813126950740044942870578526376",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "26361151154829600651603985995297072258262605598910254660032612019129606811983",
                )
                .map_err(|_| ())
                .unwrap(),
            ],
            vec![
                F::from_str(
                    "46973867849986280770641828877435510444176572688208439836496241838832695841519",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "1219439673853113792340300173186247996249367102884530407862469123523013083971",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "8063356002935671186275773257019749639571745240775941450161086349727882957042",
                )
                .map_err(|_| ())
                .unwrap(),
            ],
            vec![
                F::from_str(
                    "8815571992701260640209942886673939234666734294275300852283020522390608544536",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "36384568984671043678320545346945893232044626942887414733675890845013312931948",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "7493936589040764830842760521372106574503511314427857201860148571929278344956",
                )
                .map_err(|_| ())
                .unwrap(),
            ],
            vec![
                F::from_str(
                    "26516538878265871822073279450474977673130300973488209984756372331392531193948",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "3872858659373466814413243601289105962248870842202907364656526273784217311104",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "8291822807524000248589997648893671538524566700364221355689839490238724479848",
                )
                .map_err(|_| ())
                .unwrap(),
            ],
            vec![
                F::from_str(
                    "32842548776827046388198955038089826231531188946525483251252938248379132381248",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "10749428410907700061565796335489079278748501945557710351216806276547834974736",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "43342287917341177925402357903832370099402579088513884654598017447701677948416",
                )
                .map_err(|_| ())
                .unwrap(),
            ],
            vec![
                F::from_str(
                    "29658571352070370791360499299098360881857072189358092237807807261478461425147",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "7805182565862454238315452208989152534554369855020544477885853141626690738363",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "30699555847500141715826240743138908521140760599479365867708690318477369178275",
                )
                .map_err(|_| ())
                .unwrap(),
            ],
            vec![
                F::from_str(
                    "1231951350103545216624376889222508148537733140742167414518514908719103925687",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "24784260089125933876714702247471508077514206350883487938806451152907502751770",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "36563542611079418454711392295126742705798573252480028863133394504154697924536",
                )
                .map_err(|_| ())
                .unwrap(),
            ],
        ];
        let full_rounds = 8;
        let total_rounds = 37;
        let partial_rounds = total_rounds - full_rounds;
        PoseidonParameters::new(full_rounds, partial_rounds, alpha, mds, ark)
    }
}
