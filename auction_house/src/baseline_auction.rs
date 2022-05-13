use ark_ff::UniformRand;
use digest::Digest;
use rand::{CryptoRng, Rng};
use std::{
    collections::{HashMap, HashSet},
    marker::PhantomData,
    time::{Duration, Instant},
};

use crate::{AuctionError, Error};

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct AuctionParams {
    pub t_bid_collection: Duration,
    pub t_bid_self_open: Duration,
}

pub struct Auction<H: Digest> {
    t_start: Instant,
    pub bid_comms_i: HashMap<usize, [u8; 32]>, // index -> commitment
    bid_comms_set: HashSet<[u8; 32]>,          // commitments
    pub bid_openings: HashMap<usize, Option<u32>>, // index -> bid
    _hash: PhantomData<H>,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum AuctionPhase {
    BidCollection,
    BidSelfOpening,
    Complete,
}

impl<H: Digest> Auction<H> {
    pub fn new(_pp: &AuctionParams) -> Self {
        Self {
            t_start: Instant::now(),
            bid_comms_i: HashMap::new(),
            bid_comms_set: HashSet::new(),
            bid_openings: HashMap::new(),
            _hash: PhantomData,
        }
    }

    pub fn phase(&self, pp: &AuctionParams) -> AuctionPhase {
        let t_auction = self.t_start.elapsed();
        if t_auction < pp.t_bid_collection {
            AuctionPhase::BidCollection
        } else if t_auction < pp.t_bid_collection + pp.t_bid_self_open {
            AuctionPhase::BidSelfOpening
        } else {
            AuctionPhase::Complete
        }
    }

    fn commit(bid: u32, r: u32) -> [u8; 32] {
        <[u8; 32]>::try_from(
            H::digest([bid.to_be_bytes(), r.to_be_bytes()].concat().as_slice()).as_slice(),
        )
        .unwrap()
    }

    pub fn client_create_bid<R: CryptoRng + Rng>(
        rng: &mut R,
        pp: &AuctionParams,
        bid: u32,
    ) -> Result<([u8; 32], u32), Error> {
        let r = u32::rand(rng);

        let mut bid_bytes = bid.to_be_bytes();

        let mut bid_buffer = [0u8; 32];
        bid_buffer[32-(&bid_bytes.len())..].copy_from_slice(&bid_bytes);


        let r_bytes = r.to_be_bytes();
        let mut r_buffer = [0u8; 32];
        r_buffer[32-(&r_bytes.len())..].copy_from_slice(&r_bytes);

        let comm: [u8; 32] = <[u8; 32]>::try_from(
            H::digest([bid_buffer, r_buffer].concat().as_slice()).as_slice(),
        )
            .unwrap();
        Ok((comm, r))
        }

        pub fn accept_bid(&mut self, pp: &AuctionParams, bid_comm: &[u8; 32]) -> Result<usize, Error> {
            if self.phase(pp) != AuctionPhase::BidCollection {
                Err(Box::new(AuctionError::InvalidPhase))
            } else if self.bid_comms_set.contains(bid_comm) {
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
        pp: &AuctionParams,
        bid: u32,
        bid_opening: u32,
        bid_index: usize,
    ) -> Result<(), Error> {
        if self.phase(pp) != AuctionPhase::BidSelfOpening {
            Err(Box::new(AuctionError::InvalidPhase))
        } else {
            self.accept_opening(pp, Some(bid), bid_opening, bid_index)?;
            Ok(())
        }
    }

    fn accept_opening(
        &mut self,
        pp: &AuctionParams,
        bid: Option<u32>,
        bid_opening: u32,
        bid_index: usize,
    ) -> Result<(), Error> {
        if self.bid_openings.contains_key(&bid_index) {
            return Err(Box::new(AuctionError::InvalidBid));
        }

        let comm = self
            .bid_comms_i
            .get(&bid_index)
            .ok_or(Box::new(AuctionError::InvalidBid))?;

        if comm.clone() == <[u8; 32]>::try_from(
            H::digest([bid.unwrap().to_be_bytes(), bid_opening.to_be_bytes()].concat().as_slice()).as_slice(),
        )
            .unwrap() {
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
    use once_cell::sync::Lazy;
    use rand::{rngs::StdRng, SeedableRng};
    use sha3::Keccak256;
    use std::{str::FromStr, thread};

    pub type TestAuction = Auction<Keccak256>;

    #[test]
    fn basic_baseline_auction_test() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let bid1 = u32::rand(&mut rng);
        let bid2 = u32::rand(&mut rng);
        let bid3 = u32::rand(&mut rng);
        let bid4 = u32::rand(&mut rng);

        let auction_pp = AuctionParams {
            t_bid_collection: Duration::from_secs(2),
            t_bid_self_open: Duration::from_secs(2),
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
        assert_eq!(auction.phase(&auction_pp), AuctionPhase::BidCollection);
        let index1 = auction.accept_bid(&auction_pp, &comm1).unwrap();
        let index2 = auction.accept_bid(&auction_pp, &comm2).unwrap();
        let index3 = auction.accept_bid(&auction_pp, &comm3).unwrap();

        assert!(auction.accept_bid(&auction_pp, &comm3).is_err());
        assert!(auction
            .accept_self_opening(&auction_pp, bid1, opening1, index1)
            .is_err());

        // Self opening phase
        thread::sleep(auction_pp.t_bid_collection);
        assert_eq!(auction.phase(&auction_pp), AuctionPhase::BidSelfOpening);

        assert!(auction.accept_bid(&auction_pp, &comm4).is_err());

        auction
            .accept_self_opening(&auction_pp, bid1, opening1, index1)
            .unwrap();
        assert!(auction
            .accept_self_opening(&auction_pp, bid1, opening1, index1)
            .is_err());
        assert!(auction
            .accept_self_opening(&auction_pp, bid2, opening2, index3)
            .is_err());

        auction
            .accept_self_opening(&auction_pp, bid2, opening2, index2)
            .unwrap();

        // Force opening phase
        thread::sleep(auction_pp.t_bid_self_open);
        assert_eq!(auction.phase(&auction_pp), AuctionPhase::Complete);
        // assert!(auction
        //     .accept_self_opening(&auction_pp, bid3, opening3, index3)
        //     .is_err());
        assert!(auction.accept_bid(&auction_pp, &comm4).is_err());

        // Auction complete
        assert_eq!(auction.phase(&auction_pp), AuctionPhase::Complete);
    }

    #[test]
    fn optimistic_baseline_auction_test() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let bid1 = u32::rand(&mut rng);
        let bid2 = u32::rand(&mut rng);
        let bid3 = u32::rand(&mut rng);

        let auction_pp = AuctionParams {
            t_bid_collection: Duration::from_secs(2),
            t_bid_self_open: Duration::from_secs(2),
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
            .accept_self_opening(&auction_pp, bid1, opening1, index1)
            .unwrap();
        auction
            .accept_self_opening(&auction_pp, bid2, opening2, index2)
            .unwrap();
        auction
            .accept_self_opening(&auction_pp, bid3, opening3, index3)
            .unwrap();

        // Auction complete - skip force opening
        thread::sleep(auction_pp.t_bid_self_open);
        assert_eq!(auction.phase(&auction_pp), AuctionPhase::Complete);
    }
}
