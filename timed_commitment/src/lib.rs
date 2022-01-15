use crate::committing_ae::KeyCommittingAE;
use rsa::{
    bigint::BigInt,
    hog::{RsaGroupParams, RsaHiddenOrderGroup},
    poe::{PoE, PoEParams, Proof as PoEProof},
};
use std::{error::Error as ErrorTrait, marker::PhantomData};

use digest::Digest;
use num_bigint::RandBigInt;
use rand::{CryptoRng, Rng};

pub mod committing_ae;

pub type Error = Box<dyn ErrorTrait>;
pub type Hog<P> = RsaHiddenOrderGroup<P>;

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TimeParams<RsaP: RsaGroupParams, D: Digest> {
    t: u32,
    x: Hog<RsaP>,
    y: Hog<RsaP>,
    proof: PoEProof<RsaP, D>,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Comm<RsaP: RsaGroupParams> {
    pub x: Hog<RsaP>,
    pub ct: Vec<u8>,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Opening<RsaP: RsaGroupParams, D: Digest> {
    SELF(BigInt),
    FORCE(Hog<RsaP>, PoEProof<RsaP, D>),
}

/// Non-malleable timed commitment using key-committing authenticated encryption
pub struct BasicTC<PoEP: PoEParams, RsaP: RsaGroupParams, D: Digest> {
    _poe_params: PhantomData<PoEP>,
    _rsa_params: PhantomData<RsaP>,
    _hash: PhantomData<D>,
}

impl<PoEP: PoEParams, RsaP: RsaGroupParams, D: Digest> BasicTC<PoEP, RsaP, D> {
    pub fn gen_time_params(t: u32) -> Result<TimeParams<RsaP, D>, Error> {
        let g = Hog::<RsaP>::generator();
        let y = g.power(&BigInt::from(2).pow(t));
        let proof = PoE::<PoEP, RsaP, D>::prove(&g, &y, t)?;
        Ok(TimeParams { t, x: g, y, proof })
    }

    pub fn ver_time_params(pp: &TimeParams<RsaP, D>) -> Result<bool, Error> {
        PoE::<PoEP, RsaP, D>::verify(&pp.x, &pp.y, pp.t, &pp.proof)
    }

    pub fn commit<R: CryptoRng + Rng>(
        rng: &mut R,
        pp: &TimeParams<RsaP, D>,
        m: &[u8],
        ad: &[u8],
    ) -> Result<(Comm<RsaP>, Opening<RsaP, D>), Error> {
        // Sample randomizing factor
        let r = BigInt::from(rng.gen_biguint(256));
        let x = pp.x.power(&r);
        let y = pp.y.power(&r);

        // Derive key from repeated square
        assert!(D::output_size() >= 16);
        let mut key = D::digest(&y.n.to_bytes_le().1).to_vec();
        key.truncate(16);

        let mut ad = ad.to_vec();
        ad.extend_from_slice(&pp.t.to_le_bytes()); // Append time parameter to associated data
        let ct = KeyCommittingAE::encrypt(rng, &key, &ad, m)?;
        Ok((Comm { x, ct }, Opening::SELF(r)))
    }

    pub fn force_open(
        pp: &TimeParams<RsaP, D>,
        comm: &Comm<RsaP>,
        ad: &[u8],
    ) -> Result<(Option<Vec<u8>>, Opening<RsaP, D>), Error> {
        // Compute and prove repeated square
        let y = comm.x.power(&BigInt::from(2).pow(pp.t));
        let proof = PoE::<PoEP, RsaP, D>::prove(&comm.x, &y, pp.t)?;

        // Derive key from repeated square
        assert!(D::output_size() >= 16);
        let mut key = D::digest(&y.n.to_bytes_le().1).to_vec();
        key.truncate(16);

        let mut ad = ad.to_vec();
        ad.extend_from_slice(&pp.t.to_le_bytes()); // Append time parameter to associated data
        let m = KeyCommittingAE::decrypt(&key, &ad, &comm.ct);

        let opening = Opening::FORCE(y, proof);
        match m {
            Ok(m) => Ok((Some(m), opening)),
            Err(_) => Ok((None, opening)),
        }
    }

    pub fn ver_open(
        pp: &TimeParams<RsaP, D>,
        comm: &Comm<RsaP>,
        ad: &[u8],
        m: &Option<Vec<u8>>,
        opening: &Opening<RsaP, D>,
    ) -> Result<bool, Error> {
        match opening {
            Opening::SELF(r) => {
                let x_valid = pp.x.power(r) == comm.x;
                let y = pp.y.power(r);
                let mut key = D::digest(&y.n.to_bytes_le().1).to_vec();
                key.truncate(16);
                let mut ad = ad.to_vec();
                ad.extend_from_slice(&pp.t.to_le_bytes()); // Append time parameter to associated data
                let dec_m = KeyCommittingAE::decrypt(&key, &ad, &comm.ct);
                match (m, dec_m) {
                    (Some(m), Ok(dec_m)) => Ok(x_valid && m == &dec_m),
                    (None, Err(_)) => Ok(x_valid),
                    _ => Ok(false),
                }
            }
            Opening::FORCE(y, proof) => {
                let proof_valid = PoE::<PoEP, RsaP, D>::verify(&comm.x, y, pp.t, proof)?;
                let mut key = D::digest(&y.n.to_bytes_le().1).to_vec();
                key.truncate(16);
                let mut ad = ad.to_vec();
                ad.extend_from_slice(&pp.t.to_le_bytes()); // Append time parameter to associated data
                let dec_m = KeyCommittingAE::decrypt(&key, &ad, &comm.ct);
                match (m, dec_m) {
                    (Some(m), Ok(dec_m)) => Ok(proof_valid && m == &dec_m),
                    (None, Err(_)) => Ok(proof_valid),
                    _ => Ok(false),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
    pub struct TestPoEParams;

    impl PoEParams for TestPoEParams {
        const HASH_TO_PRIME_ENTROPY: usize = 128;
    }

    pub type TC = BasicTC<TestPoEParams, TestRsaParams, Sha3_256>;

    #[test]
    fn key_committing_tc_test() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let mut m = [1u8; 32];
        rng.fill(&mut m);
        let mut ad = [0u8; 32];
        rng.fill(&mut ad);

        let pp = TC::gen_time_params(40).unwrap();
        assert!(TC::ver_time_params(&pp).unwrap());

        let (comm, self_opening) = TC::commit(&mut rng, &pp, &m, &ad).unwrap();
        assert!(TC::ver_open(&pp, &comm, &ad, &Some(m.to_vec()), &self_opening).unwrap());

        let (force_m, force_opening) = TC::force_open(&pp, &comm, &ad).unwrap();
        assert!(TC::ver_open(&pp, &comm, &ad, &force_m, &force_opening).unwrap());
        assert_eq!(force_m, Some(m.to_vec()));

        let mut ad_bad = ad.to_vec();
        ad_bad[0] = ad_bad[0] + 1u8;
        assert!(!TC::ver_open(&pp, &comm, &ad_bad, &Some(m.to_vec()), &self_opening).unwrap());
        assert!(!TC::ver_open(&pp, &comm, &ad_bad, &force_m, &force_opening).unwrap());
    }
}
