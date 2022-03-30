use ark_ec::ProjectiveCurve;

use num_traits::{Zero};
use digest::Digest;
use rand::{CryptoRng, Rng};
use std::{
    collections::{HashMap, HashSet},
    marker::PhantomData,
    time::{Duration, Instant},
};
use std::ops::Neg;
use ark_ff::PrimeField;

use rsa::{
    bigint::{BigInt, nat_to_f},
    hog::{RsaGroupParams},
    poe::{PoEParams},
    hash_to_prime::HashToPrime,
};
use timed_commitments::{
    PedersenParams,
    basic_tc::{TimeParams},
    lazy_tc::{LazyTC, Comm as TCComm, Opening as TCOpening},
};
use range_proofs::bulletproofs::{
    Bulletproofs, Params as RangeProofParams, Proof as RangeProof,
};
use crate::{
    Error, AuctionError,
    auction::{AuctionPhase, AuctionParams, Auction},
};

const BID_BITS: u32 = 32;

//TODO: PedersenParams should be here instead of in per-auction params
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct HouseParams<G: ProjectiveCurve> {
    range_proof_pp: RangeProofParams<G>,
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
    active_auctions: HashMap<u32, Auction<G, PoEP, RsaP, H, H2P>>,
    accounts: HashMap<u32, AccountSummary<G>>,
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
}
