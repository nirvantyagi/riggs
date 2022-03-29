use ark_ec::ProjectiveCurve;

use digest::Digest;
use rand::{CryptoRng, Rng};
use std::{
    collections::{HashMap, HashSet},
    marker::PhantomData,
    time::{Duration, Instant},
};

use rsa::{
    hog::{RsaGroupParams},
    poe::{PoEParams},
    hash_to_prime::HashToPrime,
};
use timed_commitments::{
    PedersenParams,
    basic_tc::{TimeParams},
    lazy_tc::{LazyTC, Comm as TCComm, Opening as TCOpening},
};
use crate::{Error, AuctionError};

pub struct AuctionParams<G: ProjectiveCurve, RsaP: RsaGroupParams> {
    pub t_bid_collection: Duration,
    pub t_bid_self_open: Duration,
    pub time_pp: TimeParams<RsaP>,
    pub ped_pp: PedersenParams<G>,
}

pub struct Auction<G: ProjectiveCurve, PoEP: PoEParams, RsaP: RsaGroupParams, H: Digest, H2P: HashToPrime> {
    t_start: Instant,
    bid_comms_i: HashMap<usize, TCComm<G, RsaP>>,  // index -> commitment
    bid_comms_set: HashSet<TCComm<G, RsaP>>,  // commitments
    bid_openings: HashMap<usize, Option<u32>>,  // index -> bid
    _poe_params: PhantomData<PoEP>,
    _hash: PhantomData<H>,
    _hash_to_prime: PhantomData<H2P>,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum AuctionPhase {
    BidCollection,
    BidSelfOpening,
    BidForceOpening,
    Complete,
}

impl<G: ProjectiveCurve, PoEP: PoEParams, RsaP: RsaGroupParams, H: Digest, H2P: HashToPrime> Auction<G, PoEP, RsaP, H, H2P> {
    pub fn new(_pp: &AuctionParams<G, RsaP>) -> Self {
        Self {
            t_start: Instant::now(),
            bid_comms_i: HashMap::new(),
            bid_comms_set: HashSet::new(),
            bid_openings: HashMap::new(),
            _poe_params: PhantomData,
            _hash: PhantomData,
            _hash_to_prime: PhantomData,
        }
    }

    pub fn phase(&self, pp: &AuctionParams<G, RsaP>) -> AuctionPhase {
        let t_auction = self.t_start.elapsed();
        if t_auction < pp.t_bid_collection {
            AuctionPhase::BidCollection
        } else if self.bid_comms_i.len() == self.bid_openings.len() {
            AuctionPhase::Complete
        } else if t_auction < pp.t_bid_collection + pp.t_bid_self_open {
            AuctionPhase::BidSelfOpening
        } else {
            AuctionPhase::BidForceOpening
        }
    }

    pub fn client_create_bid<R: CryptoRng + Rng>(rng: &mut R, pp: &AuctionParams<G, RsaP>, bid: u32) -> Result<(TCComm<G, RsaP>, TCOpening<RsaP, H2P>), Error> {
        LazyTC::<G, PoEP, RsaP, H, H2P>::commit(rng, &pp.time_pp, &pp.ped_pp, &bid.to_be_bytes(), &[])
    }

    pub fn force_open_bid<R: CryptoRng + Rng>(&self, pp: &AuctionParams<G, RsaP>, bid_index: usize) -> Result<(Option<u32>, TCOpening<RsaP, H2P>), Error> {
        let (bid_bytes, opening) = LazyTC::<G, PoEP, RsaP, H, H2P>::force_open(
            &pp.time_pp,
            &pp.ped_pp,
            self.bid_comms_i.get(&bid_index).ok_or(Box::new(AuctionError::InvalidBid))?,
            &[],
        )?;
        //TODO: Not robust. Will be enforced to be true with range proof
        Ok((bid_bytes.map(|bytes| u32::from_be_bytes(bytes[bytes.len() - 4..].try_into().unwrap())), opening))
    }

    pub fn accept_bid(&mut self, pp: &AuctionParams<G, RsaP>, bid_comm: &TCComm<G, RsaP>) -> Result<usize, Error> {
        if self.phase(pp) != AuctionPhase::BidCollection {
            Err(Box::new(AuctionError::InvalidPhase))

        } else if self.bid_comms_set.contains(bid_comm) {
            Err(Box::new(AuctionError::InvalidBid))
        } else {
            self.bid_comms_i.insert(self.bid_comms_set.len(), bid_comm.clone());
            self.bid_comms_set.insert(bid_comm.clone());
            Ok(self.bid_comms_set.len() - 1)
        }
    }

    pub fn accept_self_opening(&mut self, pp: &AuctionParams<G, RsaP>, bid: Option<u32>, bid_opening: &TCOpening<RsaP, H2P>, bid_index: usize) -> Result<(), Error> {
        if self.phase(pp) != AuctionPhase::BidSelfOpening {
            Err(Box::new(AuctionError::InvalidPhase))
        } else {
            self.accept_opening(pp, bid, bid_opening, bid_index)?;
            Ok(())
        }
    }

    pub fn accept_force_opening(&mut self, pp: &AuctionParams<G, RsaP>, bid: Option<u32>, bid_opening: &TCOpening<RsaP, H2P>, bid_index: usize) -> Result<(), Error> {
        if self.phase(pp) != AuctionPhase::BidForceOpening {
            Err(Box::new(AuctionError::InvalidPhase))
        } else {
            self.accept_opening(pp, bid, bid_opening, bid_index)?;
            Ok(())
        }
    }

    fn accept_opening(&mut self, pp: &AuctionParams<G, RsaP>, bid: Option<u32>, bid_opening: &TCOpening<RsaP, H2P>, bid_index: usize) -> Result<(), Error> {
        if self.bid_openings.contains_key(&bid_index) {
            return Err(Box::new(AuctionError::InvalidBid));
        }

        let comm = self.bid_comms_i.get(&bid_index).ok_or(Box::new(AuctionError::InvalidBid))?;
        if LazyTC::<G, PoEP, RsaP, H, H2P>::ver_open(
            &pp.time_pp,
            &pp.ped_pp,
            comm,
            &[],
            &bid.map(|b| b.to_be_bytes().to_vec()),
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
    use ark_ff::UniformRand;
    use ark_bls12_381::G1Projective as G;
    use once_cell::sync::Lazy;
    use rand::{rngs::StdRng, SeedableRng};
    use sha3::Keccak256;
    use std::{
        str::FromStr,
        thread,
    };

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

    pub type TestAuction = Auction<
        G,
        TestPoEParams,
        TestRsaParams,
        Keccak256,
        PocklingtonHash<TestPocklingtonParams, Keccak256>,
    >;

    #[test]
    fn basic_auction_test() {
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
            time_pp,
            ped_pp,
        };

        let (comm1, opening1) = TestAuction::client_create_bid(&mut rng, &auction_pp, bid1).unwrap();
        let (comm2, opening2) = TestAuction::client_create_bid(&mut rng, &auction_pp, bid2).unwrap();
        let (comm3, opening3) = TestAuction::client_create_bid(&mut rng, &auction_pp, bid3).unwrap();
        let (comm4, _) = TestAuction::client_create_bid(&mut rng, &auction_pp, bid4).unwrap();


        // Create new auction
        let mut auction = TestAuction::new(&auction_pp);

        // Bid collection phase
        assert_eq!(auction.phase(&auction_pp), AuctionPhase::BidCollection);
        let index1 = auction.accept_bid(&auction_pp, &comm1).unwrap();
        let index2 = auction.accept_bid(&auction_pp, &comm2).unwrap();
        let index3 = auction.accept_bid(&auction_pp, &comm3).unwrap();

        assert!(auction.accept_bid(&auction_pp, &comm3).is_err());
        assert!(auction.accept_self_opening(&auction_pp, Some(bid1), &opening1, index1).is_err());
        assert!(auction.accept_force_opening(&auction_pp, Some(bid1), &opening1, index1).is_err());

        // Self opening phase
        thread::sleep(auction_pp.t_bid_collection);
        assert_eq!(auction.phase(&auction_pp), AuctionPhase::BidSelfOpening);

        assert!(auction.accept_bid(&auction_pp, &comm4).is_err());

        auction.accept_self_opening(&auction_pp, Some(bid1), &opening1, index1).unwrap();
        assert!(auction.accept_self_opening(&auction_pp, Some(bid1), &opening1, index1).is_err());
        assert!(auction.accept_self_opening(&auction_pp, Some(bid2), &opening2, index3).is_err());

        auction.accept_self_opening(&auction_pp, Some(bid2), &opening2, index2).unwrap();
        assert!(auction.accept_force_opening(&auction_pp, Some(bid3), &opening3, index3).is_err());

        // Force opening phase
        thread::sleep(auction_pp.t_bid_self_open);
        assert_eq!(auction.phase(&auction_pp), AuctionPhase::BidForceOpening);
        assert!(auction.accept_self_opening(&auction_pp, Some(bid3), &opening3, index3).is_err());
        assert!(auction.accept_bid(&auction_pp, &comm4).is_err());
        auction.accept_force_opening(&auction_pp, Some(bid3), &opening3, index3).unwrap();

        // Auction complete
        assert_eq!(auction.phase(&auction_pp), AuctionPhase::Complete);
    }

    #[test]
    fn optimistic_auction_test() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let bid1 = u32::rand(&mut rng);
        let bid2 = u32::rand(&mut rng);
        let bid3 = u32::rand(&mut rng);


        let (time_pp, _) = TC::gen_time_params(40).unwrap();
        let ped_pp = TC::gen_pedersen_params(&mut rng);
        let auction_pp = AuctionParams {
            t_bid_collection: Duration::from_secs(2),
            t_bid_self_open: Duration::from_secs(2),
            time_pp,
            ped_pp,
        };

        let (comm1, opening1) = TestAuction::client_create_bid(&mut rng, &auction_pp, bid1).unwrap();
        let (comm2, opening2) = TestAuction::client_create_bid(&mut rng, &auction_pp, bid2).unwrap();
        let (comm3, opening3) = TestAuction::client_create_bid(&mut rng, &auction_pp, bid3).unwrap();


        // Create new auction
        let mut auction = TestAuction::new(&auction_pp);

        // Bid collection phase
        let index1 = auction.accept_bid(&auction_pp, &comm1).unwrap();
        let index2 = auction.accept_bid(&auction_pp, &comm2).unwrap();
        let index3 = auction.accept_bid(&auction_pp, &comm3).unwrap();

        // Self opening phase
        thread::sleep(auction_pp.t_bid_collection);

        auction.accept_self_opening(&auction_pp, Some(bid1), &opening1, index1).unwrap();
        auction.accept_self_opening(&auction_pp, Some(bid2), &opening2, index2).unwrap();
        auction.accept_self_opening(&auction_pp, Some(bid3), &opening3, index3).unwrap();

        // Auction complete - skip force opening
        assert_eq!(auction.phase(&auction_pp), AuctionPhase::Complete);
    }
}
