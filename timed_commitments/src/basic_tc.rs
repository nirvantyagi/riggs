use crate::Error;
use rsa::{
    bigint::BigInt,
    hash_to_prime::HashToPrime,
    hog::{RsaGroupParams, RsaHiddenOrderGroup},
    poe::{PoE, PoEParams, Proof as PoEProof},
};
use std::{
    error::Error as ErrorTrait,
    fmt::{self, Debug},
    hash::{Hash, Hasher},
    marker::PhantomData,
};

use digest::Digest;
use num_bigint::RandBigInt;
use rand::{CryptoRng, Rng};

pub type Hog<P> = RsaHiddenOrderGroup<P>;

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TimeParams<RsaP: RsaGroupParams> {
    pub t: u32,
    pub x: Hog<RsaP>,
    pub y: Hog<RsaP>,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Comm<RsaP: RsaGroupParams> {
    pub x: Hog<RsaP>,
    pub ct: Vec<u8>,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Opening<RsaP: RsaGroupParams, H2P: HashToPrime> {
    SELF(BigInt),
    FORCE(Hog<RsaP>, PoEProof<RsaP, H2P>),
}

impl<P: RsaGroupParams> Hash for Comm<P> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.x.hash(state);
        self.ct.hash(state);
    }
}

/// Non-malleable timed commitment using key-committing authenticated encryption
pub struct BasicTC<PoEP: PoEParams, RsaP: RsaGroupParams, H: Digest, H2P: HashToPrime> {
    _poe_params: PhantomData<PoEP>,
    _rsa_params: PhantomData<RsaP>,
    _hash: PhantomData<H>,
    _hash_to_prime: PhantomData<H2P>,
}

impl<PoEP: PoEParams, RsaP: RsaGroupParams, H: Digest, H2P: HashToPrime>
    BasicTC<PoEP, RsaP, H, H2P>
{
    pub fn gen_time_params(t: u32) -> Result<(TimeParams<RsaP>, PoEProof<RsaP, H2P>), Error> {
        let two = Hog::<RsaP>::generator();
        let g = two.power(&BigInt::from(2).pow(t));
        let y = g.power(&BigInt::from(2).pow(t));
        let proof = PoE::<PoEP, RsaP, H2P>::prove(&g, &y, t)?;
        Ok((TimeParams { t, x: g, y }, proof))
    }

    pub fn ver_time_params(
        pp: &TimeParams<RsaP>,
        proof: &PoEProof<RsaP, H2P>,
    ) -> Result<bool, Error> {
        PoE::<PoEP, RsaP, H2P>::verify(&pp.x, &pp.y, pp.t, proof)
    }

    pub fn commit<R: CryptoRng + Rng>(
        rng: &mut R,
        pp: &TimeParams<RsaP>,
        m: &[u8],
    ) -> Result<(Comm<RsaP>, Opening<RsaP, H2P>), Error> {
        // Sample randomizing factor
        let r = BigInt::from(rng.gen_biguint(128));
        let x = pp.x.power(&r);
        let y = pp.y.power(&r);

        // Derive key from repeated square
        debug_assert_eq!(H::output_size(), 32);
        let key = H::digest(&y.n.to_bytes_be().1).to_vec();
        let ad = pp.t.to_be_bytes(); // Time parameter as associated data
        let ct = OneTimeKeyDeterministicAE::encrypt::<H>(&key, &m, &ad)?;
        Ok((Comm { x, ct }, Opening::SELF(r)))
    }

    pub fn force_open(
        pp: &TimeParams<RsaP>,
        comm: &Comm<RsaP>,
    ) -> Result<(Option<Vec<u8>>, Opening<RsaP, H2P>), Error> {
        // Compute and prove repeated square
        let y = comm.x.power(&BigInt::from(2).pow(pp.t));
        let proof = PoE::<PoEP, RsaP, H2P>::prove(&comm.x, &y, pp.t)?;

        // Derive key from repeated square
        debug_assert_eq!(H::output_size(), 32);
        let key = H::digest(&y.n.to_bytes_be().1).to_vec();
        let ad = pp.t.to_be_bytes(); // Time parameter as associated data
        let m = OneTimeKeyDeterministicAE::decrypt::<H>(&key, &comm.ct, &ad);

        let opening = Opening::FORCE(y, proof);
        match m {
            Ok(m) => Ok((Some(m), opening)),
            Err(_) => Ok((None, opening)),
        }
    }

    pub fn ver_open(
        pp: &TimeParams<RsaP>,
        comm: &Comm<RsaP>,
        m: &Option<Vec<u8>>,
        opening: &Opening<RsaP, H2P>,
    ) -> Result<bool, Error> {
        debug_assert_eq!(H::output_size(), 32);
        match opening {
            Opening::SELF(r) => {
                let x_valid = pp.x.power(r) == comm.x;
                let y = pp.y.power(r);
                let key = H::digest(&y.n.to_bytes_be().1).to_vec();
                let ad = pp.t.to_be_bytes(); // Time parameter as associated data
                let dec_m = OneTimeKeyDeterministicAE::decrypt::<H>(&key, &comm.ct, &ad);
                match (m, dec_m) {
                    (Some(m), Ok(dec_m)) => Ok(x_valid && m == &dec_m),
                    (None, Err(_)) => Ok(x_valid),
                    _ => Ok(false),
                }
            }
            Opening::FORCE(y, proof) => {
                let proof_valid = PoE::<PoEP, RsaP, H2P>::verify(&comm.x, y, pp.t, proof)?;
                let key = H::digest(&y.n.to_bytes_be().1).to_vec();
                let ad = pp.t.to_be_bytes(); // Time parameter as associated data
                let dec_m = OneTimeKeyDeterministicAE::decrypt::<H>(&key, &comm.ct, &ad);
                match (m, dec_m) {
                    (Some(m), Ok(dec_m)) => Ok(proof_valid && m == &dec_m),
                    (None, Err(_)) => Ok(proof_valid),
                    _ => Ok(false),
                }
            }
        }
    }
}

pub struct OneTimeKeyDeterministicAE;

impl OneTimeKeyDeterministicAE {
    pub fn encrypt<H: Digest>(key: &[u8], pt: &[u8], ad: &[u8]) -> Result<Vec<u8>, Error> {
        debug_assert_eq!(key.len(), 32);
        debug_assert_eq!(H::output_size(), 32);
        let enc_key = &key[..16];
        let mac_key = &key[16..];
        let mut ct = Self::one_time_pad::<H>(enc_key, pt);
        let mut mac = H::digest(&[mac_key, &ct, ad].concat()).to_vec();
        ct.append(&mut mac);
        Ok(ct)
    }

    // TODO: Fix timing side channel of decryption error
    pub fn decrypt<H: Digest>(key: &[u8], ct: &[u8], ad: &[u8]) -> Result<Vec<u8>, Error> {
        debug_assert_eq!(key.len(), 32);
        debug_assert_eq!(H::output_size(), 32);
        let enc_key = &key[..16];
        let mac_key = &key[16..];

        let mac = &ct[ct.len() - 32..];
        let ct = &ct[..ct.len() - 32];
        let computed_mac = H::digest(&[mac_key, ct, ad].concat()).to_vec();
        let pt = Self::one_time_pad::<H>(enc_key, ct);
        if mac == &computed_mac[..] {
            Ok(pt)
        } else {
            Err(Box::new(AEError::DecryptionFailed))
        }
    }

    fn one_time_pad<H: Digest>(key: &[u8], bytes: &[u8]) -> Vec<u8> {
        debug_assert_eq!(H::output_size(), 32);
        let num_blocks = (bytes.len() - 1) / 32 + 1;
        let pad = (0..num_blocks)
            .map(|i| H::digest(&[key, &[i as u8]].concat()).to_vec())
            .flatten()
            .collect::<Vec<_>>();
        bytes.iter().zip(pad.iter())
            .map(|(pt_byte, pad_byte)| pt_byte ^ pad_byte)
            .collect::<Vec<_>>()
    }
}

#[derive(Debug)]
pub enum AEError {
    InvalidKeyFormat,
    EncryptionFailed,
    DecryptionFailed,
}

impl ErrorTrait for AEError {
    fn source(self: &Self) -> Option<&(dyn ErrorTrait + 'static)> {
        None
    }
}

impl fmt::Display for AEError {
    fn fmt(self: &Self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            AEError::InvalidKeyFormat => format!("invalid key format"),
            AEError::EncryptionFailed => format!("encryption failed"),
            AEError::DecryptionFailed => format!("decryption failed"),
        };
        write!(f, "{}", msg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use once_cell::sync::Lazy;
    use rand::{rngs::StdRng, SeedableRng};
    use rsa::hash_to_prime::pocklington::{PocklingtonCertParams, PocklingtonHash};
    //use sha3::Sha3_256;
    use sha3::Keccak256;
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

    #[derive(Clone, PartialEq, Eq, Debug)]
    pub struct TestPocklingtonParams;
    impl PocklingtonCertParams for TestPocklingtonParams {
        const NONCE_SIZE: usize = 16;
        const MAX_STEPS: usize = 5;
        const INCLUDE_SOLIDITY_WITNESSES: bool = true;
    }

    pub type TC = BasicTC<
        TestPoEParams,
        TestRsaParams,
        Keccak256,
        PocklingtonHash<TestPocklingtonParams, Keccak256>,
    >;

    #[test]
    fn ae_test() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let mut pt = [1u8; 32];
        rng.fill(&mut pt);
        let mut key = [0u8; 32];
        rng.fill(&mut key);
        let mut ad = [0u8; 32];
        rng.fill(&mut ad);

        let ct = OneTimeKeyDeterministicAE::encrypt::<Keccak256>(&key, &pt, &ad).unwrap();
        let dec_ct = OneTimeKeyDeterministicAE::decrypt::<Keccak256>(&key, &ct, &ad).unwrap();
        assert!(pt.iter().eq(dec_ct.iter()));

        let mut mac_key_bad = key.to_vec();
        mac_key_bad[17] = mac_key_bad[17] + 1u8;
        assert!(OneTimeKeyDeterministicAE::decrypt::<Keccak256>(&mac_key_bad, &ct, &ad).is_err());

        let mut ad_bad = ad.to_vec();
        ad_bad[0] = ad_bad[0] + 1u8;
        assert!(OneTimeKeyDeterministicAE::decrypt::<Keccak256>(&key, &ct, &ad_bad).is_err());

        let mut ct_bad = ct.to_vec();
        let l = ct_bad.len();
        ct_bad[l - 1] = ct_bad[l - 1] + 1u8;
        assert!(OneTimeKeyDeterministicAE::decrypt::<Keccak256>(&key, &ct_bad, &ad).is_err());
    }

    #[test]
    fn basic_tc_test() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let mut m = [1u8; 32];
        rng.fill(&mut m);

        let (pp, pp_proof) = TC::gen_time_params(40).unwrap();
        assert!(TC::ver_time_params(&pp, &pp_proof).unwrap());

        let (comm, self_opening) = TC::commit(&mut rng, &pp, &m).unwrap();
        assert!(TC::ver_open(&pp, &comm, &Some(m.to_vec()), &self_opening).unwrap());

        let (force_m, force_opening) = TC::force_open(&pp, &comm).unwrap();
        assert!(TC::ver_open(&pp, &comm, &force_m, &force_opening).unwrap());
        assert_eq!(force_m, Some(m.to_vec()));
    }
}
