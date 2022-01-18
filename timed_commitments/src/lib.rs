use ark_ec::ProjectiveCurve;
use ark_ff::{PrimeField, UniformRand};
use num_bigint::Sign;
use rand::{CryptoRng, Rng};
use rsa::bigint::{nat_to_f, BigInt};
use std::{error::Error as ErrorTrait, marker::PhantomData};

pub mod basic_tc;
pub mod lazy_tc;
pub mod snark_tc;

pub type Error = Box<dyn ErrorTrait>;

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PedersenParams<G: ProjectiveCurve> {
    g: G,
    h: G,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PedersenComm<G: ProjectiveCurve> {
    _g: PhantomData<G>,
}

impl<G: ProjectiveCurve> PedersenComm<G> {
    pub fn gen_pedersen_params<R: CryptoRng + Rng>(rng: &mut R) -> PedersenParams<G> {
        PedersenParams {
            g: G::rand(rng).into(),
            h: G::rand(rng).into(),
        }
    }

    pub fn commit<R: CryptoRng + Rng>(
        rng: &mut R,
        pp: &PedersenParams<G>,
        m: &[u8],
    ) -> Result<(G, G::ScalarField), Error> {
        let r = G::ScalarField::rand(rng);
        let m_f = nat_to_f::<G::ScalarField>(&BigInt::from_bytes_le(Sign::Plus, m))?;
        let comm = pp.g.mul(&m_f.into_repr()) + &pp.h.mul(&r.into_repr());
        Ok((comm, r))
    }

    pub fn ver_open(
        pp: &PedersenParams<G>,
        comm: &G,
        m: &[u8],
        opening: &G::ScalarField,
    ) -> Result<bool, Error> {
        let m_f = nat_to_f::<G::ScalarField>(&BigInt::from_bytes_le(Sign::Plus, m));
        match m_f {
            Ok(m_f) => Ok(pp.g.mul(&m_f.into_repr()) + &pp.h.mul(opening.into_repr()) == *comm),
            Err(_) => Ok(false),
        }
    }
}
