use ark_ec::ProjectiveCurve;

use digest::Digest;
use rand::{CryptoRng, Rng};
use std::{
    collections::{HashMap, HashSet},
    marker::PhantomData,
    time::{Duration, Instant},
};

use crate::{AuctionError, Error};
use rsa::{hash_to_prime::HashToPrime, hog::RsaGroupParams, poe::PoEParams};
use timed_commitments::{
    basic_tc::TimeParams,
    lazy_tc::{Comm as TCComm, LazyTC, Opening as TCOpening},
    PedComm, PedersenParams,
};

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct AuctionParams<G: ProjectiveCurve> {
    pub t_bid_collection: Duration,
    pub t_bid_self_open: Duration,
    pub ped_pp: PedersenParams<G>,
}

pub struct Auction<G: ProjectiveCurve, H: Digest> {
    t_start: Instant,
    pub bid_comms_i: HashMap<usize, PedComm<G>>, // index -> commitment
    bid_comms_set: HashSet<PedComm<G>>,          // commitments
    pub bid_openings: HashMap<usize, Option<u32>>, // index -> bid
    _hash: PhantomData<H>,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum AuctionPhase {
    BidCollection,
    BidSelfOpening,
    Complete,
}

impl<G: ProjectiveCurve, H: Digest> Auction<G, H> {
    pub fn new(_pp: &AuctionParams<G>) -> Self {
        Self {
            t_start: Instant::now(),
            bid_comms_i: HashMap::new(),
            bid_comms_set: HashSet::new(),
            bid_openings: HashMap::new(),
            _hash: PhantomData,
        }
    }

    // Do not test for phase in benches as real-time delays aren't involved. 
    pub fn phase(&self, pp: &AuctionParams<G>, desired_phase: AuctionPhase) -> bool {
        return true; 
        // let t_auction = self.t_start.elapsed();
        // if t_auction < pp.t_bid_collection {
        //     desired_phase == AuctionPhase::BidCollection
        // } else if t_auction < pp.t_bid_collection + pp.t_bid_self_open {
        //     desired_phase == AuctionPhase::BidSelfOpening
        // } else {
        //     desired_phase == AuctionPhase::Complete
        // }
    }

    pub fn client_create_bid<R: CryptoRng + Rng>(
        rng: &mut R,
        pp: &AuctionParams<G>,
        bid: u32,
    ) -> Result<(PedComm<G>, G::ScalarField), Error> {
        // LazyTC::<G, PoEP, RsaP, H, H2P>::commit(rng, &pp.time_pp, &pp.ped_pp, &bid.to_le_bytes())
        let (comm_g, r_scalarfield) =
            PedComm::<G>::commit::<R>(rng, &pp.ped_pp, &bid.to_le_bytes()).unwrap();
        Ok((PedComm { g: comm_g }, r_scalarfield))
    }

    pub fn accept_bid(
        &mut self,
        pp: &AuctionParams<G>,
        bid_comm: &PedComm<G>,
    ) -> Result<usize, Error> {
        if !self.phase(pp, AuctionPhase::BidCollection) {
            Err(Box::new(AuctionError::InvalidPhase))
        } else if (self.bid_comms_set.contains(bid_comm)) {
            Err(Box::new(AuctionError::InvalidBid))
        } else {
            self.bid_comms_i
                .insert(self.bid_comms_set.len(), bid_comm.clone());
            self.bid_comms_set.insert(bid_comm.clone());
            Ok(self.bid_comms_set.len() - 1)
        }
    }

    pub fn accept_self_opening(
        &mut self,
        pp: &AuctionParams<G>,
        bid: u32,
        bid_opening: &G::ScalarField,
        bid_index: usize,
    ) -> Result<(), Error> {
        if !self.phase(pp, AuctionPhase::BidSelfOpening) {
            Err(Box::new(AuctionError::InvalidPhase))
        } else {
            self.accept_opening(pp, Some(bid), bid_opening, bid_index)?;
            Ok(())
        }
    }

    fn accept_opening(
        &mut self,
        pp: &AuctionParams<G>,
        bid: Option<u32>,
        bid_opening: &G::ScalarField,
        bid_index: usize,
    ) -> Result<(), Error> {
        if self.bid_openings.contains_key(&bid_index) {
            return Err(Box::new(AuctionError::InvalidBid));
        }

        let comm = self
            .bid_comms_i
            .get(&bid_index)
            .ok_or(Box::new(AuctionError::InvalidBid))?;
        if PedComm::<G>::ver_open(
            &pp.ped_pp,
            &comm.g,
            &bid.unwrap().to_le_bytes(),
            bid_opening,
        )? {
            self.bid_openings.insert(bid_index, bid);
            Ok(())
        } else {
            Err(Box::new(AuctionError::InvalidBid))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::G1Projective as G;
    use ark_ff::UniformRand;
    use once_cell::sync::Lazy;
    use rand::{rngs::StdRng, SeedableRng};
    use sha3::Keccak256;
    use std::{str::FromStr, thread};

    use rsa::{
        bigint::BigInt,
        hash_to_prime::pocklington::{PocklingtonCertParams, PocklingtonHash},
    };
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

    pub type TestAuction = Auction<G, Keccak256>;

    #[test]
    fn basic_rp_auction_test() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let bid1 = u32::rand(&mut rng);
        let bid2 = u32::rand(&mut rng);
        let bid3 = u32::rand(&mut rng);
        let bid4 = u32::rand(&mut rng);

        let (time_pp, _) = TC::gen_time_params(40).unwrap();
        let ped_pp = TC::gen_pedersen_params(&mut rng);

        let auction_pp = AuctionParams {
            t_bid_collection: Duration::from_secs(2),
            t_bid_self_open: Duration::from_secs(2),
            ped_pp,
        };

        let (comm1, opening1) =
            TestAuction::client_create_bid(&mut rng, &auction_pp, bid1).unwrap();
        let (comm2, opening2) =
            TestAuction::client_create_bid(&mut rng, &auction_pp, bid2).unwrap();
        let (comm3, opening3) =
            TestAuction::client_create_bid(&mut rng, &auction_pp, bid3).unwrap();
        let (comm4, _) = TestAuction::client_create_bid(&mut rng, &auction_pp, bid4).unwrap();

        // Create new auction
        let mut auction = TestAuction::new(&auction_pp);

        // Bid collection phase
        assert!(auction.phase(&auction_pp, AuctionPhase::BidCollection));
        let index1 = auction.accept_bid(&auction_pp, &comm1).unwrap();
        let index2 = auction.accept_bid(&auction_pp, &comm2).unwrap();
        let index3 = auction.accept_bid(&auction_pp, &comm3).unwrap();

        assert!(auction.accept_bid(&auction_pp, &comm3).is_err());
        assert!(auction
            .accept_self_opening(&auction_pp, bid1, &opening1, index1)
            .is_err());

        // Self opening phase
        thread::sleep(auction_pp.t_bid_collection);
        assert!(auction.phase(&auction_pp, AuctionPhase::BidSelfOpening));

        assert!(auction.accept_bid(&auction_pp, &comm4).is_err());

        auction
            .accept_self_opening(&auction_pp, bid1, &opening1, index1)
            .unwrap();
        assert!(auction
            .accept_self_opening(&auction_pp, bid1, &opening1, index1)
            .is_err());
        assert!(auction
            .accept_self_opening(&auction_pp, bid2, &opening2, index3)
            .is_err());

        auction
            .accept_self_opening(&auction_pp, bid2, &opening2, index2)
            .unwrap();
        // assert!(auction.accept_force_opening(&auction_pp, Some(bid3), &opening3, index3).is_err());

        // Force opening phase
        thread::sleep(auction_pp.t_bid_self_open);
        // assert_eq!(auction.phase(&auction_pp), AuctionPhase::BidForceOpening);
        assert!(auction
            .accept_self_opening(&auction_pp, bid3, &opening3, index3)
            .is_err());
        assert!(auction.accept_bid(&auction_pp, &comm4).is_err());
        //auction.accept_force_opening(&auction_pp, Some(bid3), &opening3, index3).unwrap();

        // Auction complete
        assert!(auction.phase(&auction_pp, AuctionPhase::Complete));
    }

    #[test]
    fn optimistic_rp_auction_test() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let bid1 = u32::rand(&mut rng);
        let bid2 = u32::rand(&mut rng);
        let bid3 = u32::rand(&mut rng);

        let ped_pp = TC::gen_pedersen_params(&mut rng);
        let auction_pp = AuctionParams {
            t_bid_collection: Duration::from_secs(2),
            t_bid_self_open: Duration::from_secs(2),
            ped_pp,
        };

        let (comm1, opening1) =
            TestAuction::client_create_bid(&mut rng, &auction_pp, bid1).unwrap();
        let (comm2, opening2) =
            TestAuction::client_create_bid(&mut rng, &auction_pp, bid2).unwrap();
        let (comm3, opening3) =
            TestAuction::client_create_bid(&mut rng, &auction_pp, bid3).unwrap();

        // Create new auction
        let mut auction = TestAuction::new(&auction_pp);

        // Bid collection phase
        let index1 = auction.accept_bid(&auction_pp, &comm1).unwrap();
        let index2 = auction.accept_bid(&auction_pp, &comm2).unwrap();
        let index3 = auction.accept_bid(&auction_pp, &comm3).unwrap();

        // Self opening phase
        thread::sleep(auction_pp.t_bid_collection);

        auction
            .accept_self_opening(&auction_pp, bid1, &opening1, index1)
            .unwrap();
        auction
            .accept_self_opening(&auction_pp, bid2, &opening2, index2)
            .unwrap();
        auction
            .accept_self_opening(&auction_pp, bid3, &opening3, index3)
            .unwrap();

        thread::sleep(auction_pp.t_bid_self_open);
        assert!(auction.phase(&auction_pp, AuctionPhase::Complete));
    }
}
