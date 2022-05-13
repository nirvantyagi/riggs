use crate::{
    baseline_auction::{Auction, AuctionParams, AuctionPhase},
    AuctionError, Error,
};
use ark_ff::PrimeField;
use ark_ff::UniformRand;
use digest::Digest;
use num_traits::Zero;
use rand::{rngs::StdRng, SeedableRng};
use rand::{CryptoRng, Rng};

use std::ops::Neg;
use std::{collections::HashMap, marker::PhantomData};

const BID_BITS: u32 = 32;

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct AccountSummary {
pub balance: u32,
}

//TODO: PedersenParams should be here instead of in per-auction params (currently duplicated)
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct HouseParams<> {
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct HouseAuctionParams<> {
    pub auction_pp: AuctionParams<>,
}


pub struct AuctionHouse<H: Digest> {
    active_auctions: HashMap<u32, (Auction<H>, HashMap<u32, u32>)>, // auction_id -> (auction, (user_id -> bid_id))
    accounts: HashMap<u32, AccountSummary<>>,                      // user_id -> account_info
    //TODO: Will eventually overflow, use hash or replace finished auction ids
    ctr_auction: u32,
    ctr_account: u32,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct AccountPrivateState<H: Digest> {
    pub public_summary: AccountSummary<>,
    pub active_bids: HashMap<u32, (u32, u32, u32, [u8; 32])>, // auction_id -> (bid, opening, collateral, comm)
    // pub sum_active_bids: u32,
    // pub opening_active_bids: G::ScalarField,
    _auction: PhantomData<Auction<H>>,
}

pub struct BidProposal<> {
    pub comm_bid: [u8; 32],
    pub collateral: u32,
}

impl<H: Digest>  AccountPrivateState<H>
{
    pub fn new() -> Self {
        Self {
            public_summary: AccountSummary {
                balance: 0
            },
            active_bids: HashMap::new(),
            _auction: PhantomData,
        }
    }

    pub fn propose_bid<R: CryptoRng + Rng>(
        &self,
        rng: &mut R,
        house_pp: &HouseParams<>,
        auction_pp: &HouseAuctionParams<>,
        bid: u32,
        collateral: u32,
    ) -> Result<(BidProposal<>, u32), Error> {
        if collateral > self.public_summary.balance || bid > collateral {
            return Err(Box::new(AuctionError::InvalidBid));
        }

        let (comm_bid, opening_bid) =
            Auction::<H>::client_create_bid(rng, &auction_pp.auction_pp, bid)?;

        Ok((BidProposal { comm_bid, collateral }, opening_bid))
    }

    pub fn confirm_bid(
        &mut self,
        _house_pp: &HouseParams<>,
        auction_pp: &HouseAuctionParams<>,
        auction_id: u32,
        bid: u32,
        proposal: &BidProposal,
        opening: u32,
    ) -> Result<(), Error> {
        // Update balance to remove collateral
        self.public_summary.balance -= proposal.collateral;
        // Update active bids
        self.active_bids.insert(
            auction_id,
            (bid, opening.clone(),
             proposal.collateral,
             proposal.comm_bid.clone()),
        );
        Ok(())
    }

    pub fn confirm_bid_self_open(
        &mut self,
        _house_pp: &HouseParams<>,
        auction_pp: &HouseAuctionParams<>,
        auction_id: u32,
    ) -> Result<(), Error> {
        let (bid, _, collateral, _) = self
            .active_bids
            .get(&auction_id)
            .ok_or(Box::new(AuctionError::InvalidID))?;

        self.public_summary.balance += (collateral-bid);
        Ok(())
    }

    pub fn confirm_auction_win(
        &mut self,
        _house_pp: &HouseParams<>,
        _auction_pp: &HouseAuctionParams<>,
        auction_id: u32,
        price: u32,
    ) -> Result<(), Error> {
        {
            let (bid, opening, collateral, bid_comm) = self
                .active_bids
                .get(&auction_id)
                .ok_or(Box::new(AuctionError::InvalidID))?;
            self.public_summary.balance += (bid - price);
        }
        self.active_bids.remove(&auction_id);
        Ok(())
    }

    pub fn confirm_auction_loss(
        &mut self,
        _house_pp: &HouseParams<>,
        _auction_pp: &HouseAuctionParams<>,
        auction_id: u32,
    ) -> Result<(), Error> {
        {
            let (bid, opening, collateral, bid_comm) = self
                .active_bids
                .get(&auction_id)
                .ok_or(Box::new(AuctionError::InvalidID))?;
            self.public_summary.balance += collateral;
        }
        self.active_bids.remove(&auction_id);
        Ok(())
    }

    pub fn confirm_deposit(&mut self, _house_pp: &HouseParams<>, amt: u32) -> Result<(), Error> {
        self.public_summary.balance += amt;
        Ok(())
    }

    pub fn propose_withdrawal<R: CryptoRng + Rng>(
        &self,
        rng: &mut R,
        house_pp: &HouseParams<>,
        amt: u32,
    ) -> Result<(), Error> {
        if amt > self.public_summary.balance {
            return Err(Box::new(AuctionError::InvalidBid));
        }
        Ok(())
    }

    pub fn confirm_withdrawal(
        &mut self,
        _house_pp: &HouseParams<>,
        amt: u32,
    ) -> Result<(), Error> {
        self.public_summary.balance -= amt;
        Ok(())
    }
}

impl<H: Digest> AuctionHouse<H> {
    pub fn new(_house_pp: &HouseParams<>) -> Self {
        Self {
            active_auctions: HashMap::new(),
            accounts: HashMap::new(),
            ctr_auction: 0,
            ctr_account: 0,
        }
    }

    pub fn new_account(&mut self, _house_pp: &HouseParams<>) -> (u32, AccountSummary<>) {
        let user_id = self.ctr_account;
        let user_summary = AccountSummary {
            balance: 0,
        };
        self.accounts.insert(user_id, user_summary.clone());
        self.ctr_account += 1;
        (user_id, user_summary)
    }

    pub fn account_deposit(
        &mut self,
        _house_pp: &HouseParams<>,
        user_id: u32,
        amt: u32,
    ) -> Result<(), Error> {
        let summary = self
            .accounts
            .get_mut(&user_id)
            .ok_or(Box::new(AuctionError::InvalidID))?;
        summary.balance += amt;
        Ok(())
    }

    pub fn account_withdrawal(
        &mut self,
        house_pp: &HouseParams<>,
        user_id: u32,
        amt: u32,
    ) -> Result<(), Error> {
        let user_summary = self
            .accounts
            .get_mut(&user_id)
            .ok_or(Box::new(AuctionError::InvalidID))?;
        let balance_less_amt = user_summary.balance - amt;
        if balance_less_amt < 0 {
            return Err(Box::new(AuctionError::InvalidBid));
        }
        user_summary.balance -= amt;
        Ok(())
    }

    pub fn new_auction(
        &mut self,
        _house_pp: &HouseParams<>,
        auction_pp: &HouseAuctionParams<>,
    ) -> u32 {
        let auction_id = self.ctr_auction;
        //TODO: Assert Pedersen parameters between auction and house are the same
        self.active_auctions.insert(
            auction_id,
            (Auction::new(&auction_pp.auction_pp), HashMap::new()),
        );
        self.ctr_auction += 1;
        auction_id
    }

    pub fn account_bid(
        &mut self,
        house_pp: &HouseParams<>,
        auction_pp: &HouseAuctionParams<>,
        auction_id: u32,
        user_id: u32,
        bid: &BidProposal<>,
        collateral: u32,
    ) -> Result<(), Error> {
        let user_summary = self
            .accounts
            .get_mut(&user_id)
            .ok_or(Box::new(AuctionError::InvalidID))?;
        let (auction, bid_map) = self
            .active_auctions
            .get_mut(&auction_id)
            .ok_or(Box::new(AuctionError::InvalidID))?;
        // TODO: Allow multiple bids from a single user
        if bid_map.contains_key(&user_id) {
            return Err(Box::new(AuctionError::InvalidBid));
        }
        // Verify balance - reward - bid - active_bids > 0
        let balance_less_collateral = user_summary.balance - collateral;
        if collateral <= 0 || balance_less_collateral < 0 {
            return Err(Box::new(AuctionError::InvalidBid));
        }

        // Update state
        let bid_id = auction.accept_bid(&auction_pp.auction_pp, &bid.comm_bid)?;
        bid_map.insert(user_id, bid_id as u32);
        user_summary.balance -= collateral;

        Ok(())
    }

    pub fn account_self_open(
        &mut self,
        _house_pp: &HouseParams<>,
        auction_pp: &HouseAuctionParams<>,
        auction_id: u32,
        user_id: u32,
        bid: u32,
        opening: u32,
    ) -> Result<(), Error> {
        let user_summary = self
            .accounts
            .get_mut(&user_id)
            .ok_or(Box::new(AuctionError::InvalidID))?;
        let (auction, bid_map) = self
            .active_auctions
            .get_mut(&auction_id)
            .ok_or(Box::new(AuctionError::InvalidID))?;
        let bid_id = bid_map
            .get(&user_id)
            .ok_or(Box::new(AuctionError::InvalidID))?;
        // Update state
        auction.accept_self_opening(&auction_pp.auction_pp, bid, opening, *bid_id as usize)?;
        Ok(())
    }

    // Completes auction and returns (price, winners)
    pub fn complete_kplusone_price_auction(
        &mut self,
        _house_pp: &HouseParams<>,
        auction_pp: &HouseAuctionParams<>,
        auction_id: u32,
        k: usize,
    ) -> Result<(u32, Vec<u32>), Error> {
        let (price, winners) = {
            let (auction, bid_map) = self
                .active_auctions
                .get(&auction_id)
                .ok_or(Box::new(AuctionError::InvalidID))?;
            if auction.phase(&auction_pp.auction_pp) != AuctionPhase::Complete {
                return Err(Box::new(AuctionError::InvalidPhase));
            }
            let mut bids = bid_map
                .iter()
                // .map(|(uid, bid_id)| (*uid,
                //                       if auction.bid_openings.contains_key(&(*bid_id as usize)) {
                //                           (auction.bid_openings.get(&(*bid_id as usize))).unwrap()
                //                       } else {
                //                           Some(&0)
                //                       }))
                .map(|(uid, bid_id)| (*uid, auction.bid_openings.get(&(*bid_id as usize))))
                .filter(|(_uid, bid)| bid.is_some())
                .map(|(uid, bid)| (uid, bid.unwrap()))
                .collect::<Vec<_>>();

            assert!(bids.len() > k as usize);

            // TODO: Does not handle tie bids. Currently tie is broken by unstable selection algo.
            let k1_index = bids.len() - (k + 1);
            bids.select_nth_unstable_by_key(k1_index, |(_, bid)| *bid);
            let price = bids[k1_index].1.unwrap();
            let winners = bids[k1_index + 1..]
                .iter()
                .map(|(uid, _)| *uid)
                .collect::<Vec<_>>();

            for (uid, bid_id) in bid_map.iter() {
                let bid_comm = auction.bid_comms_i.get(&(*bid_id as usize)).unwrap();
                // self.accounts.get_mut(uid).unwrap().comm_active_bids -= bid_comm.ped_comm;
            }
            for uid in winners.iter() {
                self.accounts.get_mut(uid).unwrap().balance -= price;
            }
            (price, winners)
        };
        self.active_auctions.remove(&auction_id);
        Ok((price, winners))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use once_cell::sync::Lazy;
    use rand::{rngs::StdRng, SeedableRng};
    use sha3::Keccak256;
    use std::{str::FromStr, thread, time::Duration};

    pub type TestAuctionHouse = AuctionHouse<Keccak256>;
    pub type TestUser = AccountPrivateState<Keccak256>;

    #[test]
    #[ignore] // Expensive test, run with ``cargo test basic_baseline_auction_house_test -- --ignored --nocapture``
    fn basic_baseline_auction_house_test() {
        let mut rng = StdRng::seed_from_u64(0u64);

        let auction1_pp = HouseAuctionParams {
            auction_pp: AuctionParams {
                t_bid_collection: Duration::from_secs(2),
                t_bid_self_open: Duration::from_secs(6),
            },
        };

        let house_pp = HouseParams {};

        let mut auction_house = TestAuctionHouse::new(&house_pp);
        let mut users = (0..10)
            .map(|i| {
                let mut user = TestUser::new();
                let (uid, _) = auction_house.new_account(&house_pp);
                assert_eq!(uid, i);
                auction_house
                    .account_deposit(&house_pp, uid, 10000)
                    .unwrap();
                user.confirm_deposit(&house_pp, 10000).unwrap();
                user
            })
            .collect::<Vec<TestUser>>();

        // Start auctions
        let auction1_id = auction_house.new_auction(&house_pp, &auction1_pp);
        // let auction2_id = auction_house.new_auction(&house_pp, &auction2_pp);
        // let auction3_id = auction_house.new_auction(&house_pp, &auction3_pp);

        // Bid on auction 1
        let auction1_openings = users
            .iter_mut()
            .enumerate()
            .map(|(uid, user)| {
                let bid = (uid as u32 + 1) * 100;
                let collateral = bid;
                let (proposal, opening) = user
                    .propose_bid(&mut rng, &house_pp, &auction1_pp, bid, collateral)
                    .unwrap();
                println!("Auction 1 bid: uid: {}", uid);
                auction_house
                    .account_bid(&house_pp, &auction1_pp, auction1_id, uid as u32, &proposal, collateral)
                    .unwrap();
                user.confirm_bid(
                    &house_pp,
                    &auction1_pp,
                    auction1_id,
                    bid,
                    &proposal,
                    opening,
                )
                .unwrap();
                opening
            })
            .collect::<Vec<_>>();

        // User 9 cannot make a second bid
        let (dup_bid, dup_collateral) = (100, 100);
        let (dup_proposal, _) = users.get(9).unwrap()
            .propose_bid(&mut rng, &house_pp, &auction1_pp, dup_bid, dup_collateral)
            .unwrap();

        assert!(auction_house
            .account_bid(&house_pp, &auction1_pp, auction1_id, 9 as u32, &dup_proposal, dup_collateral).is_err());
        println!("Auction 1 bid: uid: 9 failed");


        // Valid withdrawal
        let withdraw_proof = users
            .get(9)
            .unwrap()
            .propose_withdrawal(&mut rng, &house_pp, 4000)
            .unwrap();
        auction_house
            .account_withdrawal(&house_pp, 9, 4000)
            .unwrap();
        users
            .get_mut(9)
            .unwrap()
            .confirm_withdrawal(&house_pp, 4000)
            .unwrap();

        println!("Withdrawal from uid 9 succeeded");

        // Return self-opening rewards of auction 1
        println!(
            "Sleeping for Auction 1 bid collection: {} seconds",
            auction1_pp.auction_pp.t_bid_collection.as_secs()
        );
        thread::sleep(auction1_pp.auction_pp.t_bid_collection);

        users
            .iter_mut()
            .zip(auction1_openings.iter())
            .enumerate()
            .skip(1)
            .for_each(|(uid, (user, &opening))| {
                println!("Auction 1 self-open: uid: {}", uid);
                let bid = (uid as u32 + 1) * 100;
                auction_house
                    .account_self_open(
                        &house_pp,
                        &auction1_pp,
                        auction1_id,
                        uid as u32,
                        bid,
                        opening,
                    )
                    .unwrap();
                user.confirm_bid_self_open(&house_pp, &auction1_pp, auction1_id).unwrap();
            });

        // Complete auction 1
        println!(
            "Sleeping for Auction 1 bid self-open: {} seconds",
            auction1_pp.auction_pp.t_bid_self_open.as_secs()
        );
        thread::sleep(auction1_pp.auction_pp.t_bid_self_open);

        let (price, winners) = auction_house
            .complete_kplusone_price_auction(&house_pp, &auction1_pp, auction1_id, 3)
            .unwrap();

        for uid in 0..10u32 {
            if winners.contains(&uid) {
                users
                    .get_mut(uid as usize)
                    .unwrap()
                    .confirm_auction_win(&house_pp, &auction1_pp, auction1_id, price)
                    .unwrap();
            } else {
                users
                    .get_mut(uid as usize)
                    .unwrap()
                    .confirm_auction_loss(&house_pp, &auction1_pp, auction1_id)
                    .unwrap();
            }
        }
        assert_eq!(winners.len(), 3);
        assert!(winners.contains(&7));
        assert!(winners.contains(&8));
        assert!(winners.contains(&9));
        assert_eq!(price, 700);
    }
}
