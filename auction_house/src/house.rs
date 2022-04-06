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
    active_bids: HashMap<u32, (u32, TCOpening<G, RsaP, H2P>, TCComm<G, RsaP>)>,  // auction_id -> (bid, opening, comm)
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

    pub fn confirm_bid(
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
        self.active_bids.insert(auction_id, (bid, opening.clone(), proposal.comm_bid.clone()));
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

    pub fn confirm_auction_win(
        &mut self,
        _house_pp: &HouseParams<G>,
        _auction_pp: &HouseAuctionParams<G, RsaP>,
        auction_id: u32,
        price: u32,
    ) -> Result<(), Error> {
        {
            let (bid, opening, bid_comm) = self.active_bids.get(&auction_id).ok_or(Box::new(AuctionError::InvalidID))?;
            self.public_summary.balance -= price;
            self.sum_active_bids -= bid;
            self.opening_active_bids -= opening.get_ped_opening();
            self.public_summary.comm_active_bids -= bid_comm.ped_comm;
        }
        self.active_bids.remove(&auction_id);
        Ok(())
    }

    pub fn confirm_auction_loss(
        &mut self,
        _house_pp: &HouseParams<G>,
        _auction_pp: &HouseAuctionParams<G, RsaP>,
        auction_id: u32,
    ) -> Result<(), Error> {
        {
            let (bid, opening, bid_comm) = self.active_bids.get(&auction_id).ok_or(Box::new(AuctionError::InvalidID))?;
            self.sum_active_bids -= bid;
            self.opening_active_bids -= opening.get_ped_opening();
            self.public_summary.comm_active_bids -= bid_comm.ped_comm;
        }
        self.active_bids.remove(&auction_id);
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

    // Completes auction and returns (price, winners)
    pub fn complete_kplusone_price_auction(
        &mut self,
        _house_pp: &HouseParams<G>,
        auction_pp: &HouseAuctionParams<G, RsaP>,
        auction_id: u32,
        k: usize,
    ) -> Result<(u32, Vec<u32>), Error> {
        let (price, winners) = {
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

            for (uid, bid_id) in bid_map.iter() {
                let bid_comm = auction.bid_comms_i.get(&(*bid_id as usize)).unwrap();
                self.accounts.get_mut(uid).unwrap().comm_active_bids -= bid_comm.ped_comm;
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
    use ark_bls12_381::G1Projective as G;
    use once_cell::sync::Lazy;
    use rand::{rngs::StdRng, SeedableRng};
    use sha3::Keccak256;
    use std::{
        str::FromStr,
        thread,
        time::Duration,
    };

    use rsa::{
        bigint::BigInt,
        hash_to_prime::pocklington::{PocklingtonCertParams, PocklingtonHash},
    };

    use timed_commitments::lazy_tc::LazyTC;

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

    pub type TestRangeProof = Bulletproofs<G, Keccak256>;

    pub type TestAuctionHouse = AuctionHouse<
        G,
        TestPoEParams,
        TestRsaParams,
        Keccak256,
        PocklingtonHash<TestPocklingtonParams, Keccak256>,
    >;

    pub type TestUser = AccountPrivateState<
        G,
        TestPoEParams,
        TestRsaParams,
        Keccak256,
        PocklingtonHash<TestPocklingtonParams, Keccak256>,
    >;

    #[test]
    fn basic_auction_house_test() {
        let mut rng = StdRng::seed_from_u64(0u64);

        let (time_pp, _) = TC::gen_time_params(40).unwrap();
        let ped_pp = TC::gen_pedersen_params(&mut rng);
        let range_proof_pp = TestRangeProof::gen_params(&mut rng, BID_BITS as u64);
        let auction1_pp = HouseAuctionParams {
            auction_pp: AuctionParams {
                t_bid_collection: Duration::from_secs(20),
                t_bid_self_open: Duration::from_secs(60),
                time_pp: time_pp.clone(),
                ped_pp: ped_pp.clone(),
            },
            reward_self_open: 200,
            reward_force_open: 300
        };
        let auction2_pp = HouseAuctionParams {
            auction_pp: AuctionParams {
                t_bid_collection: Duration::from_secs(200),
                t_bid_self_open: Duration::from_secs(20),
                time_pp: time_pp.clone(),
                ped_pp: ped_pp.clone(),
            },
            reward_self_open: 200,
            reward_force_open: 300
        };

        let house_pp = HouseParams {
            range_proof_pp,
            ped_pp,
        };

        let mut auction_house = TestAuctionHouse::new(&house_pp);
        let mut users = (0..10).map(|i| {
            let mut user = TestUser::new();
            let (uid, _) = auction_house.new_account(&house_pp);
            assert_eq!(uid, i);
            auction_house.account_deposit(&house_pp, uid, 10000).unwrap();
            user.confirm_deposit(&house_pp, 10000).unwrap();
            user
        }).collect::<Vec<TestUser>>();

        // Start auctions
        let auction1_id = auction_house.new_auction(&house_pp, &auction1_pp);
        let auction2_id = auction_house.new_auction(&house_pp, &auction2_pp);
        let auction3_id = auction_house.new_auction(&house_pp, &auction2_pp);

        // Bid on auction 1
        let auction1_openings = users.iter_mut().enumerate().map(|(uid, user)| {
            let bid = (uid as u32 + 1) * 100;
            let (proposal, opening) = user.propose_bid(
                &mut rng,
                &house_pp,
                &auction1_pp,
                bid,
            ).unwrap();
            println!("Auction 1 bid: uid: {}", uid);
            auction_house.account_bid(
                &house_pp,
                &auction1_pp,
                auction1_id,
                uid as u32,
                &proposal,
            ).unwrap();
            user.confirm_bid(
                &house_pp,
                &auction1_pp,
                auction1_id,
                bid,
                &proposal,
                &opening,
            ).unwrap();
            opening
        }).collect::<Vec<_>>();

        // Bid on auction 2
        let _auction2_openings = users.iter_mut().enumerate().map(|(uid, user)| {
            let bid = (uid as u32 + 1) * 200;
            let (proposal, opening) = user.propose_bid(
                &mut rng,
                &house_pp,
                &auction2_pp,
                bid,
            ).unwrap();
            println!("Auction 2 bid: uid: {}", uid);
            auction_house.account_bid(
                &house_pp,
                &auction2_pp,
                auction2_id,
                uid as u32,
                &proposal,
            ).unwrap();
            user.confirm_bid(
                &house_pp,
                &auction2_pp,
                auction2_id,
                bid,
                &proposal,
                &opening,
            ).unwrap();
            opening
        }).collect::<Vec<_>>();

        // Withdrawal tests (uid9 balance 6000)
        assert_eq!(auction_house.accounts.get(&9).unwrap().balance, 9000);
        assert_eq!(users.get(9).unwrap().sum_active_bids, 3000);

        // Invalid withdrawal
        assert!(users.get(9).unwrap().propose_withdrawal(
            &mut rng,
            &house_pp,
            6250,
        ).is_err());

        users.get_mut(9).unwrap().confirm_deposit(&house_pp, 1000).unwrap();
        let invalid_withdraw_proof = users.get(9).unwrap().propose_withdrawal(
            &mut rng,
            &house_pp,
            6250,
        ).unwrap();
        assert!(auction_house.account_withdrawal(
            &house_pp,
            9,
            6250,
            &invalid_withdraw_proof,
        ).is_err());
        users.get_mut(9).unwrap().confirm_withdrawal(&house_pp, 1000).unwrap();

        // Valid withdrawal
        let withdraw_proof = users.get(9).unwrap().propose_withdrawal(
            &mut rng,
            &house_pp,
            4000,
        ).unwrap();
        auction_house.account_withdrawal(
            &house_pp,
            9,
            4000,
            &withdraw_proof,
        ).unwrap();
        users.get_mut(9).unwrap().confirm_withdrawal(&house_pp, 4000).unwrap();
        assert_eq!(auction_house.accounts.get(&9).unwrap().balance, 5000);

        // Invalid bid on auction 3
        assert!(users.get(9).unwrap().propose_bid(
            &mut rng,
            &house_pp,
            &auction2_pp,
            1600,
        ).is_err());

        users.get_mut(9).unwrap().confirm_deposit(&house_pp, 500).unwrap();
        let invalid_bid_proposal = users.get(9).unwrap().propose_bid(
            &mut rng,
            &house_pp,
            &auction2_pp,
            1600,
        ).unwrap();
        assert!(auction_house.account_bid(
            &house_pp,
            &auction2_pp,
            auction3_id,
            9,
            &invalid_bid_proposal.0,
        ).is_err());
        users.get_mut(9).unwrap().confirm_withdrawal(&house_pp, 500).unwrap();

        // Return self-opening rewards of auction 1
        println!("Sleeping for Auction 1 bid collection: {} seconds", auction1_pp.auction_pp.t_bid_collection.as_secs());
        thread::sleep(auction1_pp.auction_pp.t_bid_collection);

        users.iter_mut()
            .zip(auction1_openings.iter())
            .enumerate()
            .skip(1)
            .for_each(|(uid, (user, opening))| {
                println!("Auction 1 self-open: uid: {}", uid);
                let bid = (uid as u32 + 1) * 100;
                auction_house.account_self_open(
                    &house_pp,
                    &auction1_pp,
                    auction1_id,
                    uid as u32,
                    bid,
                    opening,
                ).unwrap();
                user.confirm_bid_self_open(&house_pp, &auction2_pp).unwrap();
            });
        assert_eq!(auction_house.accounts.get(&9).unwrap().balance, 5500);

        // Valid bid on auction 3
        let bid_proposal = users.get(9).unwrap().propose_bid(
            &mut rng,
            &house_pp,
            &auction2_pp,
            1600,
        ).unwrap();
        auction_house.account_bid(
            &house_pp,
            &auction2_pp,
            auction3_id,
            9,
            &bid_proposal.0,
        ).unwrap();
        users.get_mut(9).unwrap().confirm_bid(
            &house_pp,
            &auction2_pp,
            auction3_id,
            1600,
            &bid_proposal.0,
            &bid_proposal.1,
        ).unwrap();
        assert_eq!(auction_house.accounts.get(&9).unwrap().balance, 5000);
        assert_eq!(users.get(9).unwrap().sum_active_bids, 4600);

        // Complete auction 1
        println!("Sleeping for Auction 1 bid self-open: {} seconds", auction1_pp.auction_pp.t_bid_self_open.as_secs());
        thread::sleep(auction1_pp.auction_pp.t_bid_self_open);

        assert_eq!(auction_house.accounts.get(&0).unwrap().balance, 9000);
        assert_eq!(users.get(0).unwrap().sum_active_bids, 300);
        let (bid, force_opening) = auction_house.active_auctions.get(&auction1_id).unwrap().0.force_open_bid(&auction1_pp.auction_pp, 0).unwrap();
        auction_house.account_force_open(
            &house_pp,
            &auction1_pp,
            auction1_id,
            9,
            0,
            bid,
            &force_opening,
        ).unwrap();
        users.get_mut(9).unwrap().confirm_bid_force_open(
            &house_pp,
            &auction1_pp,
        ).unwrap();
        assert_eq!(auction_house.accounts.get(&9).unwrap().balance, 5300);

        let (price, winners) = auction_house.complete_kplusone_price_auction(
            &house_pp,
            &auction1_pp,
            auction1_id,
            3,
        ).unwrap();

        for uid in 0..10u32 {
            if winners.contains(&uid) {
                users.get_mut(uid as usize).unwrap().confirm_auction_win(
                    &house_pp,
                    &auction1_pp,
                    auction1_id,
                    price,
                ).unwrap();
            } else {
                users.get_mut(uid as usize).unwrap().confirm_auction_loss(
                    &house_pp,
                    &auction1_pp,
                    auction1_id,
                ).unwrap();
            }
        }
        assert_eq!(winners.len(), 3);
        assert!(winners.contains(&7));
        assert!(winners.contains(&8));
        assert!(winners.contains(&9));
        assert_eq!(price, 700);

        assert_eq!(auction_house.accounts.get(&9).unwrap().balance, 4600);
        assert_eq!(users.get(9).unwrap().sum_active_bids, 3600);
        assert_eq!(auction_house.accounts.get(&8).unwrap().balance, 8800);
        assert_eq!(users.get(8).unwrap().sum_active_bids, 1800);
        assert_eq!(auction_house.accounts.get(&1).unwrap().balance, 9500);
        assert_eq!(users.get(1).unwrap().sum_active_bids, 400);

        // Continue bidding on auction 3

        let bid_proposal = users.get(8).unwrap().propose_bid(
            &mut rng,
            &house_pp,
            &auction2_pp,
            6000,
        ).unwrap();
        auction_house.account_bid(
            &house_pp,
            &auction2_pp,
            auction3_id,
            8,
            &bid_proposal.0,
        ).unwrap();
        users.get_mut(8).unwrap().confirm_bid(
            &house_pp,
            &auction2_pp,
            auction3_id,
            6000,
            &bid_proposal.0,
            &bid_proposal.1,
        ).unwrap();
        assert_eq!(auction_house.accounts.get(&8).unwrap().balance, 8300);
        assert_eq!(users.get(8).unwrap().sum_active_bids, 7800);

        let bid_proposal = users.get(1).unwrap().propose_bid(
            &mut rng,
            &house_pp,
            &auction2_pp,
            8500,
        ).unwrap();
        auction_house.account_bid(
            &house_pp,
            &auction2_pp,
            auction3_id,
            1,
            &bid_proposal.0,
        ).unwrap();
        users.get_mut(1).unwrap().confirm_bid(
            &house_pp,
            &auction2_pp,
            auction3_id,
            8500,
            &bid_proposal.0,
            &bid_proposal.1,
        ).unwrap();
        assert_eq!(auction_house.accounts.get(&1).unwrap().balance, 9000);
        assert_eq!(users.get(1).unwrap().sum_active_bids, 8900);
    }
}
