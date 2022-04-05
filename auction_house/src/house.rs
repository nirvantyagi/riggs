use ark_ec::ProjectiveCurve;

use num_traits::{Zero};
use digest::Digest;
use rand::{CryptoRng, Rng};
use std::{
    collections::{HashMap},
    marker::PhantomData,
};
use std::ops::{Neg};
use ark_ff::PrimeField;

use rsa::{
    bigint::{BigInt, nat_to_f},
    hog::{RsaGroupParams},
    poe::{PoEParams},
    hash_to_prime::HashToPrime,
};
use timed_commitments::{
    PedersenParams,
    lazy_tc::{Comm as TCComm, Opening as TCOpening},
};
use range_proofs::bulletproofs::{
    Bulletproofs, Params as RangeProofParams, Proof as RangeProof,
};
use crate::{
    Error, AuctionError,
    auction::{AuctionPhase, AuctionParams, Auction},
};

const BID_BITS: u32 = 32;

//TODO: PedersenParams should be here instead of in per-auction params (currently duplicated)
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct HouseParams<G: ProjectiveCurve> {
    range_proof_pp: RangeProofParams<G>,
    ped_pp: PedersenParams<G>,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct HouseAuctionParams<G: ProjectiveCurve, RsaP: RsaGroupParams> {
    pub auction_pp: AuctionParams<G, RsaP>,
    pub reward_self_open: u32,
    pub reward_force_open: u32,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct AccountSummary<G: ProjectiveCurve> {
    pub balance: u32,
    pub comm_active_bids: G,
}

pub struct AuctionHouse<G: ProjectiveCurve, PoEP: PoEParams, RsaP: RsaGroupParams, H: Digest, H2P: HashToPrime> {
    active_auctions: HashMap<u32, (Auction<G, PoEP, RsaP, H, H2P>, HashMap<u32, u32>)>,  // auction_id -> (auction, (user_id -> bid_id))
    accounts: HashMap<u32, AccountSummary<G>>,  // user_id -> account_info
    //TODO: Will eventually overflow, use hash or replace finished auction ids
    ctr_auction: u32,
    ctr_account: u32,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct AccountPrivateState<G: ProjectiveCurve, PoEP: PoEParams, RsaP: RsaGroupParams, H: Digest, H2P: HashToPrime> {
    public_summary: AccountSummary<G>,
    active_bids: HashMap<u32, (u32, TCOpening<G, RsaP, H2P>)>,  // auction_id -> (bid, opening)
    sum_active_bids: u32,
    opening_active_bids: G::ScalarField,
    _auction: PhantomData<Auction<G, PoEP, RsaP, H, H2P>>,
}

pub struct BidProposal<G: ProjectiveCurve, RsaP: RsaGroupParams> {
    comm_bid: TCComm<G, RsaP>,
    range_proof_bid: RangeProof<G>,
    range_proof_balance: RangeProof<G>,
}

impl<G: ProjectiveCurve, PoEP: PoEParams, RsaP: RsaGroupParams, H: Digest, H2P: HashToPrime> AccountPrivateState<G, PoEP, RsaP, H, H2P> {
    pub fn new() -> Self {
        Self {
            public_summary: AccountSummary { balance: 0, comm_active_bids: G::zero() },
            active_bids: HashMap::new(),
            sum_active_bids: 0,
            opening_active_bids: G::ScalarField::zero(),
            _auction: PhantomData,
        }
    }

    pub fn propose_bid<R: CryptoRng + Rng>(
        &self,
        rng: &mut R,
        house_pp: &HouseParams<G>,
        auction_pp: &HouseAuctionParams<G, RsaP>,
        bid: u32,
    ) -> Result<(BidProposal<G, RsaP>, TCOpening<G, RsaP, H2P>), Error> {
        if self.sum_active_bids + bid + auction_pp.reward_self_open + auction_pp.reward_force_open > self.public_summary.balance {
            return Err(Box::new(AuctionError::InvalidBid))
        }
        let (comm_bid, opening_bid) = Auction::<G, PoEP, RsaP, H, H2P>::client_create_bid(rng, &auction_pp.auction_pp, bid)?;
        // Prove bid > 0
        let range_proof_bid = Bulletproofs::<G, H>::prove_range(
            rng,
            &house_pp.range_proof_pp,
            &auction_pp.auction_pp.ped_pp,
            &comm_bid.ped_comm,
            &BigInt::from(bid),
            &opening_bid.get_ped_opening(),
            BID_BITS as u64,
        )?;
        // Prove balance - reward - bid - active_bids > 0
        let balance_less_reward = self.public_summary.balance - auction_pp.reward_self_open - auction_pp.reward_force_open;
        let f_balance_less_reward = nat_to_f::<G::ScalarField>(&BigInt::from(balance_less_reward))?;
        let comm_balance = auction_pp.auction_pp.ped_pp.g.mul(&f_balance_less_reward.into_repr()) - &comm_bid.ped_comm - &self.public_summary.comm_active_bids;
        let range_proof_balance = Bulletproofs::<G, H>::prove_range(
            rng,
            &house_pp.range_proof_pp,
            &auction_pp.auction_pp.ped_pp,
            &comm_balance,
            &BigInt::from(balance_less_reward - bid - self.sum_active_bids),
            &(opening_bid.get_ped_opening().neg() - &self.opening_active_bids),
            BID_BITS as u64,
        )?;
        Ok((
            BidProposal {
                comm_bid,
                range_proof_bid,
                range_proof_balance,
            },
            opening_bid,
        ))
    }

    pub fn confirm_bid<R: CryptoRng + Rng>(
        &mut self,
        _house_pp: &HouseParams<G>,
        auction_pp: &HouseAuctionParams<G, RsaP>,
        auction_id: u32,
        bid: u32,
        proposal: &BidProposal<G, RsaP>,
        opening: &TCOpening<G, RsaP, H2P>,
    ) -> Result<(), Error> {
        // Update balance to remove reward
        self.public_summary.balance -= auction_pp.reward_self_open + auction_pp.reward_force_open;
        // Update active bids
        self.sum_active_bids += bid;
        self.opening_active_bids += opening.get_ped_opening();
        self.public_summary.comm_active_bids += proposal.comm_bid.ped_comm;
        self.active_bids.insert(auction_id, (bid, opening.clone()));
        Ok(())
    }

    pub fn confirm_bid_self_open(
        &mut self,
        _house_pp: &HouseParams<G>,
        auction_pp: &HouseAuctionParams<G, RsaP>,
    ) -> Result<(), Error> {
        self.public_summary.balance += auction_pp.reward_self_open + auction_pp.reward_force_open;
        Ok(())
    }

    pub fn confirm_bid_force_open(
        &mut self,
        _house_pp: &HouseParams<G>,
        auction_pp: &HouseAuctionParams<G, RsaP>,
    ) -> Result<(), Error> {
        self.public_summary.balance += auction_pp.reward_force_open;
        Ok(())
    }

    pub fn confirm_deposit(
        &mut self,
        _house_pp: &HouseParams<G>,
        amt: u32,
    ) -> Result<(), Error> {
        self.public_summary.balance += amt;
        Ok(())
    }

    pub fn propose_withdrawal<R: CryptoRng + Rng>(
        &self,
        rng: &mut R,
        house_pp: &HouseParams<G>,
        amt: u32,
    ) -> Result<RangeProof<G>, Error> {
        if self.sum_active_bids > self.public_summary.balance - amt {
            return Err(Box::new(AuctionError::InvalidBid))
        }
        // Prove balance - amt - active_bids > 0
        let balance_less_amt = self.public_summary.balance - amt;
        let f_balance_less_amt = nat_to_f::<G::ScalarField>(&BigInt::from(balance_less_amt))?;
        let comm_balance = house_pp.ped_pp.g.mul(&f_balance_less_amt.into_repr()) - &self.public_summary.comm_active_bids;
        let range_proof_balance = Bulletproofs::<G, H>::prove_range(
            rng,
            &house_pp.range_proof_pp,
            &house_pp.ped_pp,
            &comm_balance,
            &BigInt::from(balance_less_amt - self.sum_active_bids),
            &self.opening_active_bids.neg(),
            BID_BITS as u64,
        )?;
        Ok(range_proof_balance)
    }

    pub fn confirm_withdrawal(
        &mut self,
        _house_pp: &HouseParams<G>,
        amt: u32,
    ) -> Result<(), Error> {
        self.public_summary.balance -= amt;
        Ok(())
    }
}


impl<G: ProjectiveCurve, PoEP: PoEParams, RsaP: RsaGroupParams, H: Digest, H2P: HashToPrime> AuctionHouse<G, PoEP, RsaP, H, H2P> {
    pub fn new(_house_pp: &HouseParams<G>) -> Self {
        Self {
            active_auctions: HashMap::new(),
            accounts: HashMap::new(),
            ctr_auction: 0,
            ctr_account: 0
        }
    }

    pub fn new_account(&mut self, _house_pp: &HouseParams<G>) -> (u32, AccountSummary<G>) {
        let user_id = self.ctr_account;
        let user_summary = AccountSummary {
            balance: 0,
            comm_active_bids: G::zero(),
        };
        self.accounts.insert(user_id, user_summary.clone());
        self.ctr_account += 1;
        (user_id, user_summary)
    }

    pub fn account_deposit(&mut self, _house_pp: &HouseParams<G>, user_id: u32, amt: u32) -> Result<(), Error> {
        let summary = self.accounts.get_mut(&user_id)
            .ok_or(Box::new(AuctionError::InvalidID))?;
        summary.balance += amt;
        Ok(())
    }

    pub fn account_withdrawal(
        &mut self,
        house_pp: &HouseParams<G>,
        user_id: u32,
        amt: u32,
        proof: &RangeProof<G>,
    ) -> Result<(), Error> {
        let user_summary = self.accounts.get_mut(&user_id)
            .ok_or(Box::new(AuctionError::InvalidID))?;
        let balance_less_amt = user_summary.balance - amt;
        let f_balance_less_amt = nat_to_f::<G::ScalarField>(&BigInt::from(balance_less_amt))?;
        let comm_balance = house_pp.ped_pp.g.mul(&f_balance_less_amt.into_repr()) - &user_summary.comm_active_bids;
        if !Bulletproofs::<G, H>::verify_range(
            &house_pp.range_proof_pp,
            &house_pp.ped_pp,
            &comm_balance,
            BID_BITS as u64,
            proof,
        )? {
            return Err(Box::new(AuctionError::InvalidBid));
        }
        user_summary.balance -= amt;
        Ok(())
    }

    pub fn new_auction(
        &mut self,
        _house_pp: &HouseParams<G>,
        auction_pp: &HouseAuctionParams<G, RsaP>,
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
        house_pp: &HouseParams<G>,
        auction_pp: &HouseAuctionParams<G, RsaP>,
        auction_id: u32,
        user_id: u32,
        bid: &BidProposal<G, RsaP>,
    ) -> Result<(), Error> {
        let user_summary = self.accounts.get_mut(&user_id)
            .ok_or(Box::new(AuctionError::InvalidID))?;
        let (auction, bid_map) = self.active_auctions.get_mut(&auction_id)
            .ok_or(Box::new(AuctionError::InvalidID))?;
        // TODO: Allow multiple bids from a single user
        if bid_map.contains_key(&user_id) {
            return Err(Box::new(AuctionError::InvalidBid));
        }
        // Verify bid > 0
        if !Bulletproofs::<G, H>::verify_range(
            &house_pp.range_proof_pp,
            &house_pp.ped_pp,
            &bid.comm_bid.ped_comm,
            BID_BITS as u64,
            &bid.range_proof_bid,
        )? {
            return Err(Box::new(AuctionError::InvalidBid));
        }
        // Verify balance - reward - bid - active_bids > 0
        let balance_less_reward = user_summary.balance - auction_pp.reward_self_open - auction_pp.reward_force_open;
        let f_balance_less_reward = nat_to_f::<G::ScalarField>(&BigInt::from(balance_less_reward))?;
        let comm_balance = house_pp.ped_pp.g.mul(&f_balance_less_reward.into_repr()) - &bid.comm_bid.ped_comm - &user_summary.comm_active_bids;
        if !Bulletproofs::<G, H>::verify_range(
            &house_pp.range_proof_pp,
            &house_pp.ped_pp,
            &comm_balance,
            BID_BITS as u64,
            &bid.range_proof_balance,
        )? {
            return Err(Box::new(AuctionError::InvalidBid));
        }
        // Update state
        let bid_id = auction.accept_bid(&auction_pp.auction_pp, &bid.comm_bid)?;
        bid_map.insert(user_id, bid_id as u32);
        user_summary.balance -= auction_pp.reward_self_open + auction_pp.reward_force_open;
        user_summary.comm_active_bids += &bid.comm_bid.ped_comm;
        Ok(())
    }

    pub fn account_self_open(
        &mut self,
        _house_pp: &HouseParams<G>,
        auction_pp: &HouseAuctionParams<G, RsaP>,
        auction_id: u32,
        user_id: u32,
        bid: u32,
        opening: &TCOpening<G, RsaP, H2P>,
    ) -> Result<(), Error> {
        let user_summary = self.accounts.get_mut(&user_id)
            .ok_or(Box::new(AuctionError::InvalidID))?;
        let (auction, bid_map) = self.active_auctions.get_mut(&auction_id)
            .ok_or(Box::new(AuctionError::InvalidID))?;
        let bid_id = bid_map.get(&user_id)
            .ok_or(Box::new(AuctionError::InvalidID))?;
        // Update state
        auction.accept_self_opening(&auction_pp.auction_pp, bid, opening, *bid_id as usize)?;
        user_summary.balance += auction_pp.reward_self_open + auction_pp.reward_force_open;
        Ok(())
    }

    pub fn account_force_open(
        &mut self,
        _house_pp: &HouseParams<G>,
        auction_pp: &HouseAuctionParams<G, RsaP>,
        auction_id: u32,
        user_id: u32,
        bid_id: u32,
        bid: Option<u32>,
        opening: &TCOpening<G, RsaP, H2P>,
    ) -> Result<(), Error> {
        let user_summary = self.accounts.get_mut(&user_id)
            .ok_or(Box::new(AuctionError::InvalidID))?;
        let (auction, _) = self.active_auctions.get_mut(&auction_id)
            .ok_or(Box::new(AuctionError::InvalidID))?;
        // Update state
        auction.accept_force_opening(&auction_pp.auction_pp, bid, opening, bid_id as usize)?;
        user_summary.balance += auction_pp.reward_force_open;
        Ok(())
    }

    // Completes auction and returns (price, winners, refund_map<user_id, refund_amt>)
    pub fn complete_kplusone_price_auction(
        &mut self,
        _house_pp: &HouseParams<G>,
        auction_pp: &HouseAuctionParams<G, RsaP>,
        auction_id: u32,
        k: usize,
    ) -> Result<(u32, Vec<u32>, HashMap<u32, u32>), Error> {
        let (auction, bid_map) = self.active_auctions.get(&auction_id)
            .ok_or(Box::new(AuctionError::InvalidID))?;
        if auction.phase(&auction_pp.auction_pp) != AuctionPhase::Complete {
            return Err(Box::new(AuctionError::InvalidPhase));
        }
        let mut bids = bid_map.iter()
            .map(|(uid, bid_id)| (*uid, auction.bid_openings.get(&(*bid_id as usize)).unwrap()))
            .filter(|(_uid, bid)| bid.is_some())
            .map(|(uid, bid)| (uid, bid.unwrap()))
            .collect::<Vec<_>>();

        assert!(bids.len() > k as usize);

        // TODO: Does not handle tie bids. Currently tie is broken by unstable selection algo.
        let k1_index = bids.len() - (k + 1);
        bids.select_nth_unstable_by_key(k1_index, |(_, bid)| *bid);
        let price = bids[k1_index].1;
        let winners = bids[k1_index + 1..].iter()
            .map(|(uid, _)| *uid)
            .collect::<Vec<_>>();
        let refunds = bids[..k1_index + 1].to_vec().into_iter()
            .collect::<HashMap<u32, u32>>();

        self.active_auctions.remove(&auction_id);
        Ok((price, winners, refunds))
    }
}
