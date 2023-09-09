use ark_ec::ProjectiveCurve;
use ark_ff::{PrimeField, ToConstraintField};
use ark_r1cs_std::{fields::fp::FpVar, prelude::*};
use ark_snark::SNARK;

use digest::Digest;
use num_traits::Zero;
use rand::{CryptoRng, Rng};
use std::ops::Neg;
use std::{collections::HashMap, marker::PhantomData};

use crate::{
    snark_auction::{AuctionParams, AuctionPhase, SnarkAuction as Auction},
    AuctionError, Error,
};
use range_proofs::bulletproofs::{Bulletproofs, Params as RangeProofParams, Proof as RangeProof};
use rsa::{
    bigint::{constraints::BigIntCircuitParams, nat_to_f, BigInt},
    hash_to_prime::HashToPrime,
    hog::RsaGroupParams,
    poe::PoEParams,
};
use timed_commitments::{
    snark_tc::{Comm as TCComm, Opening as TCOpening, SnarkTC, SnarkTCParams},
    PedersenParams,
};

const BID_BITS: u32 = 32;

//TODO: PedersenParams should be here instead of in per-auction params (currently duplicated)
#[derive(Clone)]
pub struct HouseParams<G: ProjectiveCurve> {
    pub range_proof_pp: RangeProofParams<G>,
    pub ped_pp: PedersenParams<G>,
}

#[derive(Clone)]
pub struct HouseAuctionParams<G: ProjectiveCurve, RsaP: RsaGroupParams, F: PrimeField, PS: SNARK<F>>
{
    pub auction_pp: AuctionParams<G, RsaP, F, PS>,
    pub reward_self_open: u32,
    pub reward_force_open: u32,
}

#[derive(Clone)]
pub struct AccountSummary<G: ProjectiveCurve> {
    pub balance: u32,
    pub comm_active_bids: G,
}

pub struct AuctionHouse<
    F: PrimeField,
    PS: SNARK<F>,
    P: SnarkTCParams<F>,
    PoEP: PoEParams,
    RsaP: RsaGroupParams,
    IntP: BigIntCircuitParams,
    H2P: HashToPrime,
    G: ProjectiveCurve,
    GV: CurveVar<G, F>,
    H: Digest,
> {
    active_auctions: HashMap<
        u32,
        (
            Auction<F, PS, P, PoEP, RsaP, IntP, H2P, G, GV>,
            HashMap<u32, u32>,
        ),
    >, // auction_id -> (auction, (user_id -> bid_id))
    accounts: HashMap<u32, AccountSummary<G>>, // user_id -> account_info
    //TODO: Will eventually overflow, use hash or replace finished auction ids
    ctr_auction: u32,
    ctr_account: u32,
    _hash: PhantomData<H>,
}

#[derive(Clone)]
pub struct AccountPrivateState<
    F: PrimeField,
    PS: SNARK<F>,
    P: SnarkTCParams<F>,
    PoEP: PoEParams,
    RsaP: RsaGroupParams,
    IntP: BigIntCircuitParams,
    H2P: HashToPrime,
    G: ProjectiveCurve,
    GV: CurveVar<G, F>,
    H: Digest,
> {
    pub public_summary: AccountSummary<G>,
    pub active_bids: HashMap<u32, (u32, TCOpening<G, RsaP, H2P>, TCComm<G, RsaP>)>, // auction_id -> (bid, opening, comm)
    pub sum_active_bids: u32,
    pub opening_active_bids: G::ScalarField,
    _auction: PhantomData<Auction<F, PS, P, PoEP, RsaP, IntP, H2P, G, GV>>,
    _hash: PhantomData<H>,
}

pub struct BidProposal<G: ProjectiveCurve, RsaP: RsaGroupParams, F: PrimeField, PS: SNARK<F>> {
    pub comm_bid: TCComm<G, RsaP>,
    pub comm_proof: PS::Proof,
    pub range_proof_bid: RangeProof<G>,
    pub range_proof_balance: RangeProof<G>,
}

impl<F, PS, P, PoEP, RsaP, IntP, H2P, G, GV, H>
    AccountPrivateState<F, PS, P, PoEP, RsaP, IntP, H2P, G, GV, H>
where
    F: PrimeField,
    PS: SNARK<F>,
    P: SnarkTCParams<F>,
    PoEP: PoEParams,
    RsaP: RsaGroupParams,
    IntP: BigIntCircuitParams,
    H2P: HashToPrime,
    G: ProjectiveCurve + ToConstraintField<F>,
    GV: CurveVar<G, F>,
    H: Digest,
{
    pub fn new() -> Self {
        Self {
            public_summary: AccountSummary {
                balance: 0,
                comm_active_bids: G::zero(),
            },
            active_bids: HashMap::new(),
            sum_active_bids: 0,
            opening_active_bids: G::ScalarField::zero(),
            _auction: PhantomData,
            _hash: PhantomData,
        }
    }

    pub fn propose_bid<R: CryptoRng + Rng>(
        &self,
        rng: &mut R,
        house_pp: &HouseParams<G>,
        auction_pp: &HouseAuctionParams<G, RsaP, F, PS>,
        bid: u32,
    ) -> Result<(BidProposal<G, RsaP, F, PS>, TCOpening<G, RsaP, H2P>), Error> {
        if self.sum_active_bids + bid + auction_pp.reward_self_open + auction_pp.reward_force_open
            > self.public_summary.balance
        {
            return Err(Box::new(AuctionError::InvalidBid));
        }
        let (comm_bid, opening_bid, comm_proof) =
            Auction::<F, PS, P, PoEP, RsaP, IntP, H2P, G, GV>::client_create_bid(
                rng,
                &auction_pp.auction_pp,
                bid,
            )?;
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
        let balance_less_reward = self.public_summary.balance
            - auction_pp.reward_self_open
            - auction_pp.reward_force_open;
        let f_balance_less_reward = nat_to_f::<G::ScalarField>(&BigInt::from(balance_less_reward))?;
        let comm_balance = auction_pp
            .auction_pp
            .ped_pp
            .g
            .mul(&f_balance_less_reward.into_repr())
            - &comm_bid.ped_comm
            - &self.public_summary.comm_active_bids;
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
                comm_proof,
                range_proof_bid,
                range_proof_balance,
            },
            opening_bid,
        ))
    }

    pub fn confirm_bid(
        &mut self,
        _house_pp: &HouseParams<G>,
        auction_pp: &HouseAuctionParams<G, RsaP, F, PS>,
        auction_id: u32,
        bid: u32,
        proposal: &BidProposal<G, RsaP, F, PS>,
        opening: &TCOpening<G, RsaP, H2P>,
    ) -> Result<(), Error> {
        // Update balance to remove reward
        self.public_summary.balance -= auction_pp.reward_self_open + auction_pp.reward_force_open;
        // Update active bids
        self.sum_active_bids += bid;
        self.opening_active_bids += opening.get_ped_opening();
        self.public_summary.comm_active_bids += proposal.comm_bid.ped_comm;
        self.active_bids.insert(
            auction_id,
            (bid, opening.clone(), proposal.comm_bid.clone()),
        );
        Ok(())
    }

    pub fn confirm_bid_self_open(
        &mut self,
        _house_pp: &HouseParams<G>,
        auction_pp: &HouseAuctionParams<G, RsaP, F, PS>,
    ) -> Result<(), Error> {
        self.public_summary.balance += auction_pp.reward_self_open + auction_pp.reward_force_open;
        Ok(())
    }

    pub fn confirm_bid_force_open(
        &mut self,
        _house_pp: &HouseParams<G>,
        auction_pp: &HouseAuctionParams<G, RsaP, F, PS>,
    ) -> Result<(), Error> {
        self.public_summary.balance += auction_pp.reward_force_open;
        Ok(())
    }

    pub fn confirm_auction_win(
        &mut self,
        _house_pp: &HouseParams<G>,
        _auction_pp: &HouseAuctionParams<G, RsaP, F, PS>,
        auction_id: u32,
        price: u32,
    ) -> Result<(), Error> {
        {
            let (bid, opening, bid_comm) = self
                .active_bids
                .get(&auction_id)
                .ok_or(Box::new(AuctionError::InvalidID))?;
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
        _auction_pp: &HouseAuctionParams<G, RsaP, F, PS>,
        auction_id: u32,
    ) -> Result<(), Error> {
        {
            let (bid, opening, bid_comm) = self
                .active_bids
                .get(&auction_id)
                .ok_or(Box::new(AuctionError::InvalidID))?;
            self.sum_active_bids -= bid;
            self.opening_active_bids -= opening.get_ped_opening();
            self.public_summary.comm_active_bids -= bid_comm.ped_comm;
        }
        self.active_bids.remove(&auction_id);
        Ok(())
    }

    pub fn confirm_deposit(&mut self, _house_pp: &HouseParams<G>, amt: u32) -> Result<(), Error> {
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
            return Err(Box::new(AuctionError::InvalidBid));
        }
        // Prove balance - amt - active_bids > 0
        let balance_less_amt = self.public_summary.balance - amt;
        let f_balance_less_amt = nat_to_f::<G::ScalarField>(&BigInt::from(balance_less_amt))?;
        let comm_balance = house_pp.ped_pp.g.mul(&f_balance_less_amt.into_repr())
            - &self.public_summary.comm_active_bids;
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

impl<F, PS, P, PoEP, RsaP, IntP, H2P, G, GV, H>
    AuctionHouse<F, PS, P, PoEP, RsaP, IntP, H2P, G, GV, H>
where
    F: PrimeField,
    PS: SNARK<F>,
    P: SnarkTCParams<F>,
    PoEP: PoEParams,
    RsaP: RsaGroupParams,
    IntP: BigIntCircuitParams,
    H2P: HashToPrime,
    G: ProjectiveCurve + ToConstraintField<F>,
    GV: CurveVar<G, F>,
    H: Digest,
{
    pub fn new(_house_pp: &HouseParams<G>) -> Self {
        Self {
            active_auctions: HashMap::new(),
            accounts: HashMap::new(),
            ctr_auction: 0,
            ctr_account: 0,
            _hash: PhantomData,
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

    pub fn account_deposit(
        &mut self,
        _house_pp: &HouseParams<G>,
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
        house_pp: &HouseParams<G>,
        user_id: u32,
        amt: u32,
        proof: &RangeProof<G>,
    ) -> Result<(), Error> {
        let user_summary = self
            .accounts
            .get_mut(&user_id)
            .ok_or(Box::new(AuctionError::InvalidID))?;
        let balance_less_amt = user_summary.balance - amt;
        let f_balance_less_amt = nat_to_f::<G::ScalarField>(&BigInt::from(balance_less_amt))?;
        let comm_balance =
            house_pp.ped_pp.g.mul(&f_balance_less_amt.into_repr()) - &user_summary.comm_active_bids;
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
        auction_pp: &HouseAuctionParams<G, RsaP, F, PS>,
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
        auction_pp: &HouseAuctionParams<G, RsaP, F, PS>,
        auction_id: u32,
        user_id: u32,
        bid: &BidProposal<G, RsaP, F, PS>,
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
        let balance_less_reward =
            user_summary.balance - auction_pp.reward_self_open - auction_pp.reward_force_open;
        let f_balance_less_reward = nat_to_f::<G::ScalarField>(&BigInt::from(balance_less_reward))?;
        let comm_balance = house_pp.ped_pp.g.mul(&f_balance_less_reward.into_repr())
            - &bid.comm_bid.ped_comm
            - &user_summary.comm_active_bids;
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
        let bid_id = auction.accept_bid(&auction_pp.auction_pp, &bid.comm_bid, &bid.comm_proof)?;
        bid_map.insert(user_id, bid_id as u32);
        user_summary.balance -= auction_pp.reward_self_open + auction_pp.reward_force_open;
        user_summary.comm_active_bids += &bid.comm_bid.ped_comm;
        Ok(())
    }

    pub fn account_self_open(
        &mut self,
        _house_pp: &HouseParams<G>,
        auction_pp: &HouseAuctionParams<G, RsaP, F, PS>,
        auction_id: u32,
        user_id: u32,
        bid: u32,
        opening: &TCOpening<G, RsaP, H2P>,
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
        user_summary.balance += auction_pp.reward_self_open + auction_pp.reward_force_open;
        Ok(())
    }

    pub fn account_force_open(
        &mut self,
        _house_pp: &HouseParams<G>,
        auction_pp: &HouseAuctionParams<G, RsaP, F, PS>,
        auction_id: u32,
        user_id: u32,
        bid_id: u32,
        bid: u32,
        opening: &TCOpening<G, RsaP, H2P>,
    ) -> Result<(), Error> {
        let user_summary = self
            .accounts
            .get_mut(&user_id)
            .ok_or(Box::new(AuctionError::InvalidID))?;
        let (auction, _) = self
            .active_auctions
            .get_mut(&auction_id)
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
        auction_pp: &HouseAuctionParams<G, RsaP, F, PS>,
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
                .map(|(uid, bid_id)| {
                    (
                        *uid,
                        *auction.bid_openings.get(&(*bid_id as usize)).unwrap(),
                    )
                })
                .collect::<Vec<_>>();

            assert!(bids.len() > k as usize);

            // TODO: Does not handle tie bids. Currently tie is broken by unstable selection algo.
            let k1_index = bids.len() - (k + 1);
            bids.select_nth_unstable_by_key(k1_index, |(_, bid)| *bid);
            let price = bids[k1_index].1;
            let winners = bids[k1_index + 1..]
                .iter()
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
        //self.active_auctions.remove(&auction_id);
        Ok((price, winners))
    }

    // Dummy function
    pub fn complete_fixed_price(
        &mut self,
        _house_pp: &HouseParams<G>,
        auction_pp: &HouseAuctionParams<G, RsaP, F, PS>,
        auction_id: u32,
        k: usize,
    ) -> Result<(u32, Vec<u32>), Error> {
        let (price, winners) = {
            let (auction, bid_map) = self
                .active_auctions
                .get(&auction_id)
                .ok_or(Box::new(AuctionError::InvalidID))?;
            if auction.phase(&auction_pp.auction_pp) != AuctionPhase::Complete {
                // return Err(Box::new(AuctionError::InvalidPhase));
            }
            let mut bids = bid_map
                .iter()
                .map(|(uid, bid_id)| {
                    (
                        *uid,
                        *auction.bid_openings.get(&(*bid_id as usize)).unwrap(),
                    )
                })
                .collect::<Vec<_>>();

            assert!(bids.len() > k as usize);

            // // TODO: Does not handle tie bids. Currently tie is broken by unstable selection algo.
            // let k1_index = bids.len() - (k + 1);
            // bids.select_nth_unstable_by_key(k1_index, |(_, bid)| *bid);
            // let price = bids[k1_index].1;
            // let winners = bids[k1_index + 1..]
            //     .iter()
            //     .map(|(uid, _)| *uid)
            //     .collect::<Vec<_>>();

            // let price = 0;
            // let winners = vec![1];

            // for (uid, bid_id) in bid_map.iter() {
            //     let bid_comm = auction.bid_comms_i.get(&(*bid_id as usize)).unwrap();
            //     self.accounts.get_mut(uid).unwrap().comm_active_bids -= bid_comm.ped_comm;
            // }
            // for uid in winners.iter() {
            //     self.accounts.get_mut(uid).unwrap().balance -= price;
            // }
            // (price, winners)

            self.accounts.get_mut(&1).unwrap().balance -= 0;
            (0, vec![1])
        };
        // self.active_auctions.remove(&auction_id);
        Ok((price, winners))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::{Bn254, Fr as F};
    use ark_ed_on_bn254::{constraints::EdwardsVar as GV, EdwardsProjective as G};
    use ark_ff::UniformRand;
    use ark_groth16::Groth16;
    use ark_sponge::poseidon::PoseidonParameters;
    use once_cell::sync::Lazy;
    use rand::{rngs::StdRng, SeedableRng};
    use sha3::Keccak256;
    use std::{str::FromStr, thread, time::Duration};

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
    pub struct BigNatTestParams;

    impl BigIntCircuitParams for BigNatTestParams {
        const LIMB_WIDTH: usize = 64;
        const N_LIMBS: usize = 32;
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

    #[derive(Clone, PartialEq, Eq, Debug)]
    pub struct TestSnarkTCParams;

    impl SnarkTCParams<F> for TestSnarkTCParams {
        const M_LEN: usize = 16;
        const POSEIDON_PARAMS: Lazy<PoseidonParameters<F>> =
            Lazy::new(|| poseidon_parameters_for_test());
        const TC_RANDOMIZER_BIT_LEN: usize = 128;
    }

    pub type TC = SnarkTC<
        F,
        Groth16<Bn254>,
        TestSnarkTCParams,
        TestPoEParams,
        TestRsaParams,
        BigNatTestParams,
        PocklingtonHash<TestPocklingtonParams, Keccak256>,
        G,
        GV,
    >;

    pub type TestRangeProof = Bulletproofs<G, Keccak256>;

    pub type TestAuctionHouse = AuctionHouse<
        F,
        Groth16<Bn254>,
        TestSnarkTCParams,
        TestPoEParams,
        TestRsaParams,
        BigNatTestParams,
        PocklingtonHash<TestPocklingtonParams, Keccak256>,
        G,
        GV,
        Keccak256,
    >;

    pub type TestUser = AccountPrivateState<
        F,
        Groth16<Bn254>,
        TestSnarkTCParams,
        TestPoEParams,
        TestRsaParams,
        BigNatTestParams,
        PocklingtonHash<TestPocklingtonParams, Keccak256>,
        G,
        GV,
        Keccak256,
    >;

    #[test]
    #[ignore] // Expensive test, run with ``cargo test basic_snark_auction_house_test -- --ignored --nocapture``
    fn basic_snark_auction_house_test() {
        let mut rng = StdRng::seed_from_u64(0u64);

        let (time_pp, _) = TC::gen_time_params(40).unwrap();
        let ped_pp = TC::gen_pedersen_params(&mut rng);
        let (snark_pk, snark_vk) = TC::gen_snark_params(&mut rng, &time_pp, &ped_pp);
        let range_proof_pp = TestRangeProof::gen_params(&mut rng, BID_BITS as u64);
        let auction1_pp = HouseAuctionParams {
            auction_pp: AuctionParams {
                t_bid_collection: Duration::from_secs(20),
                t_bid_self_open: Duration::from_secs(60),
                time_pp: time_pp.clone(),
                ped_pp: ped_pp.clone(),
                snark_pk,
                snark_vk,
            },
            reward_self_open: 200,
            reward_force_open: 300,
        };

        let house_pp = HouseParams {
            range_proof_pp,
            ped_pp,
        };

        let mut auction_house = TestAuctionHouse::new(&house_pp);
        let mut users = (0..1)
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

        // Bid on auction 1
        let bid = 100;
        let (proposal, opening) = users
            .get_mut(0)
            .unwrap()
            .propose_bid(&mut rng, &house_pp, &auction1_pp, bid)
            .unwrap();

        // Start auction
        let auction1_id = auction_house.new_auction(&house_pp, &auction1_pp);

        auction_house
            .account_bid(&house_pp, &auction1_pp, auction1_id, 0, &proposal)
            .unwrap();
        users
            .get_mut(0)
            .unwrap()
            .confirm_bid(
                &house_pp,
                &auction1_pp,
                auction1_id,
                bid,
                &proposal,
                &opening,
            )
            .unwrap();

        // Return self-opening rewards of auction 1
        println!(
            "Sleeping for Auction 1 bid collection: {} seconds",
            auction1_pp.auction_pp.t_bid_collection.as_secs()
        );
        thread::sleep(auction1_pp.auction_pp.t_bid_collection);

        auction_house
            .account_self_open(&house_pp, &auction1_pp, auction1_id, 0, bid, &opening)
            .unwrap();
        users
            .get_mut(0)
            .unwrap()
            .confirm_bid_self_open(&house_pp, &auction1_pp)
            .unwrap();

        // Complete auction 1
        println!(
            "Sleeping for Auction 1 bid self-open: {} seconds",
            auction1_pp.auction_pp.t_bid_self_open.as_secs()
        );
        thread::sleep(auction1_pp.auction_pp.t_bid_self_open);

        let (price, winners) = auction_house
            .complete_kplusone_price_auction(&house_pp, &auction1_pp, auction1_id, 0)
            .unwrap();
    }

    fn poseidon_parameters_for_test<F: PrimeField>() -> PoseidonParameters<F> {
        let alpha = 17;
        let mds = vec![
            vec![
                F::from_str(
                    "43228725308391137369947362226390319299014033584574058394339561338097152657858",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "20729134655727743386784826341366384914431326428651109729494295849276339718592",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "14275792724825301816674509766636153429127896752891673527373812580216824074377",
                )
                .map_err(|_| ())
                .unwrap(),
            ],
            vec![
                F::from_str(
                    "3039440043015681380498693766234886011876841428799441709991632635031851609481",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "6678863357926068615342013496680930722082156498064457711885464611323928471101",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "37355038393562575053091209735467454314247378274125943833499651442997254948957",
                )
                .map_err(|_| ())
                .unwrap(),
            ],
            vec![
                F::from_str(
                    "26481612700543967643159862864328231943993263806649000633819754663276818191580",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "30103264397473155564098369644643015994024192377175707604277831692111219371047",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "5712721806190262694719203887224391960978962995663881615739647362444059585747",
                )
                .map_err(|_| ())
                .unwrap(),
            ],
        ];
        let ark = vec![
            vec![
                F::from_str(
                    "44595993092652566245296379427906271087754779418564084732265552598173323099784",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "23298463296221002559050231199021122673158929708101049474262017406235785365706",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "34212491019164671611180318500074499609633402631511849759183986060951187784466",
                )
                .map_err(|_| ())
                .unwrap(),
            ],
            vec![
                F::from_str(
                    "19098051134080182375553680073525644187968170656591203562523489333616681350367",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "7027675418691353855077049716619550622043312043660992344940177187528247727783",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "47642753235356257928619065424282314733361764347085604019867862722762702755609",
                )
                .map_err(|_| ())
                .unwrap(),
            ],
            vec![
                F::from_str(
                    "24281836129477728386327945482863886685457469794572168729834072693507088619997",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "12624893078331920791384400430193929292743809612452779381349824703573823883410",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "22654862987689323504199204643771547606936339944127455903448909090318619188561",
                )
                .map_err(|_| ())
                .unwrap(),
            ],
            vec![
                F::from_str(
                    "27229172992560143399715985732065737093562061782414043625359531774550940662372",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "13224952063922250960936823741448973692264041750100990569445192064567307041002",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "40380869235216625717296601204704413215735530626882135230693823362552484855508",
                )
                .map_err(|_| ())
                .unwrap(),
            ],
            vec![
                F::from_str(
                    "4245751157938905689397184705633683893932492370323323780371834663438472308145",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "8252156875535418429533049587170755750275631534314711502253775796882240991261",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "32910829712934971129644416249914075073083903821282503505466324428991624789936",
                )
                .map_err(|_| ())
                .unwrap(),
            ],
            vec![
                F::from_str(
                    "49412601297460128335642438246716127241669915737656789613664349252868389975962",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "841661305510340459373323516098909074520942972558284146843779636353111592117",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "37926489020263024391336570420006226544461516787280929232555625742588667303947",
                )
                .map_err(|_| ())
                .unwrap(),
            ],
            vec![
                F::from_str(
                    "18433043696013996573551852847056868761017170818820490351056924728720017242180",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "45376910275288438312773930242803223482318753992595269901397542214841496212310",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "47854349410014339708332226068958253098964727682486278458389508597930796651514",
                )
                .map_err(|_| ())
                .unwrap(),
            ],
            vec![
                F::from_str(
                    "32638426693771251366613055506166587312642876874690861030672730491779486904360",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "19105439281696418043426755774110765432959446684037017837894045255490581318047",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "13484299981373196201166722380389594773562113262309564134825386266765751213853",
                )
                .map_err(|_| ())
                .unwrap(),
            ],
            vec![
                F::from_str(
                    "63360321133852659797114062808297090090814531427710842859827725871241144161",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "42427543035537409467993338717379268954936885184662765745740070438835506287271",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "149101987103211771991327927827692640556911620408176100290586418839323044234",
                )
                .map_err(|_| ())
                .unwrap(),
            ],
            vec![
                F::from_str(
                    "8341764062226826803887898710015561861526081583071950015446833446251359696930",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "45635980415044299013530304465786867101223925975971912073759959440335364441441",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "49833261156201520743834327917353893365097424877680239796845398698940689734850",
                )
                .map_err(|_| ())
                .unwrap(),
            ],
            vec![
                F::from_str(
                    "26764715016591436228000634284249890185894507497739511725029482580508707525029",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "25054530812095491217523557726611612265064441619646263299990388543372685322499",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "47654590955096246997622155031169641628093104787883934397920286718814889326452",
                )
                .map_err(|_| ())
                .unwrap(),
            ],
            vec![
                F::from_str(
                    "16463825890556752307085325855351334996898686633642574805918056141310194135796",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "17473961341633494489168064889016732306117097771640351649096482400214968053040",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "49914603434867854893558366922996753035832008639512305549839666311012232077468",
                )
                .map_err(|_| ())
                .unwrap(),
            ],
            vec![
                F::from_str(
                    "17122578514152308432111470949473865420090463026624297565504381163777697818362",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "34870689836420861427379101859113225049736283485335674111421609473028315711541",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "4622082908476410083286670201138165773322781640914243047922441301693321472984",
                )
                .map_err(|_| ())
                .unwrap(),
            ],
            vec![
                F::from_str(
                    "6079244375752010013798561155333454682564824861645642293573415833483620500976",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "2635090520059500019661864086615522409798872905401305311748231832709078452746",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "19070766579582338321241892986615538320421651429118757507174186491084617237586",
                )
                .map_err(|_| ())
                .unwrap(),
            ],
            vec![
                F::from_str(
                    "12622420533971517050761060317049369208980632120901481436392835424625664738526",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "8965101225657199137904506150282256568170501907667138404080397024857524386266",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "27085091008069524593196374148553176565775450537072498305327481366756159319838",
                )
                .map_err(|_| ())
                .unwrap(),
            ],
            vec![
                F::from_str(
                    "45929056591150668409624595495643698205830429971690813312608217341940499221218",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "50361689160518167880500080025023064746137161030119436080957023803101861300846",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "6722586346537620732668048024627882970582133613352245923413730968378696371065",
                )
                .map_err(|_| ())
                .unwrap(),
            ],
            vec![
                F::from_str(
                    "7340485916200743279276570085958556798507770452421357119145466906520506506342",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "25946733168219652706630789514519162148860502996914241011500280690204368174083",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "9962367658743163006517635070396368828381757404628822422306438427554934645464",
                )
                .map_err(|_| ())
                .unwrap(),
            ],
            vec![
                F::from_str(
                    "7221669722700687417346373353960536661883467014204005276831020252277657076044",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "21487980358388383563030903293359140836304488103090321183948009095669344637431",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "44389482047246878765773958430749333249729101516826571588063797358040130313157",
                )
                .map_err(|_| ())
                .unwrap(),
            ],
            vec![
                F::from_str(
                    "32887270862917330820874162842519225370447850172085449103568878409533683733185",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "15453393396765207016379045014101989306173462885430532298601655955681532648226",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "5478929644476681096437469958231489102974161353940993351588559414552523375472",
                )
                .map_err(|_| ())
                .unwrap(),
            ],
            vec![
                F::from_str(
                    "41981370411247590312677561209178363054744730805951096631186178388981705304138",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "3474136981645476955784428843999869229067282976757744542648188369810577298585",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "26251477770740399889956219915654371915771248171098220204692699710414817081869",
                )
                .map_err(|_| ())
                .unwrap(),
            ],
            vec![
                F::from_str(
                    "51916561889718854106125837319509539220778634838409949714061033196765117231752",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "25355145802812435959748831835587713214179184608408449220418373832038339021974",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "31950684570730625275416731570246297947385359051792335826965013637877068017530",
                )
                .map_err(|_| ())
                .unwrap(),
            ],
            vec![
                F::from_str(
                    "40966378914980473680181850710703295982197782082391794594149984057481543436879",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "1141315130963422417761731263662398620858625339733452795772225916965481730059",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "9812100862165422922235757591915383485338044715409891361026651619010947646011",
                )
                .map_err(|_| ())
                .unwrap(),
            ],
            vec![
                F::from_str(
                    "25276091996614379065765602410190790163396484122487585763380676888280427744737",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "18512694312063606403196469408971540495273694846641903978723927656359350642619",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "5791584766415439694303685437881192048262049244830616851865505314899699012588",
                )
                .map_err(|_| ())
                .unwrap(),
            ],
            vec![
                F::from_str(
                    "34501536331706470927069149344450300773777486993504673779438188495686129846168",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "10797737565565774079718466476236831116206064650762676383469703413649447678207",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "42599392747310354323136214835734307933597896695637215127297036595538235868368",
                )
                .map_err(|_| ())
                .unwrap(),
            ],
            vec![
                F::from_str(
                    "1336670998775417133322626564820911986969949054454812685145275612519924150700",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "2630141283339761901081411552890260088516693208402906795133548756078952896770",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "5206688943117414740600380377278238268309952400341418217132724749372435975215",
                )
                .map_err(|_| ())
                .unwrap(),
            ],
            vec![
                F::from_str(
                    "10739264253827005683370721104077252560524362323422172665530191908848354339715",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "48010640624945719826344492755710886355389194986527731603685956726907395779674",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "47880724693177306044229143357252697148359033158394459365791331000715957339701",
                )
                .map_err(|_| ())
                .unwrap(),
            ],
            vec![
                F::from_str(
                    "51658938856669444737833983076793759752280196674149218924101718974926964118996",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "27558055650076329657496888512074319504342606463881203707330358472954748913263",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "38886981777859313701520424626728402175860609948757992393598285291689196608037",
                )
                .map_err(|_| ())
                .unwrap(),
            ],
            vec![
                F::from_str(
                    "17152756165118461969542990684402410297675979513690903033350206658079448802479",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "43766946932033687220387514221943418338304186408056458476301583041390483707207",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "24324495647041812436929170644873622904287038078113808264580396461953421400343",
                )
                .map_err(|_| ())
                .unwrap(),
            ],
            vec![
                F::from_str(
                    "6935839211798937659784055008131602708847374430164859822530563797964932598700",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "42126767398190942911395299419182514513368023621144776598842282267908712110039",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "5702364486091252903915715761606014714345316580946072019346660327857498603375",
                )
                .map_err(|_| ())
                .unwrap(),
            ],
            vec![
                F::from_str(
                    "28184981699552917714085740963279595942132561155181044254318202220270242523053",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "27078204494010940048327822707224393686245007379331357330801926151074766130790",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "5004172841233947987988267535285080365124079140142987718231874743202918551203",
                )
                .map_err(|_| ())
                .unwrap(),
            ],
            vec![
                F::from_str(
                    "7974360962120296064882769128577382489451060235999590492215336103105134345602",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "48062035869818179910046292951628308709251170031813126950740044942870578526376",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "26361151154829600651603985995297072258262605598910254660032612019129606811983",
                )
                .map_err(|_| ())
                .unwrap(),
            ],
            vec![
                F::from_str(
                    "46973867849986280770641828877435510444176572688208439836496241838832695841519",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "1219439673853113792340300173186247996249367102884530407862469123523013083971",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "8063356002935671186275773257019749639571745240775941450161086349727882957042",
                )
                .map_err(|_| ())
                .unwrap(),
            ],
            vec![
                F::from_str(
                    "8815571992701260640209942886673939234666734294275300852283020522390608544536",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "36384568984671043678320545346945893232044626942887414733675890845013312931948",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "7493936589040764830842760521372106574503511314427857201860148571929278344956",
                )
                .map_err(|_| ())
                .unwrap(),
            ],
            vec![
                F::from_str(
                    "26516538878265871822073279450474977673130300973488209984756372331392531193948",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "3872858659373466814413243601289105962248870842202907364656526273784217311104",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "8291822807524000248589997648893671538524566700364221355689839490238724479848",
                )
                .map_err(|_| ())
                .unwrap(),
            ],
            vec![
                F::from_str(
                    "32842548776827046388198955038089826231531188946525483251252938248379132381248",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "10749428410907700061565796335489079278748501945557710351216806276547834974736",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "43342287917341177925402357903832370099402579088513884654598017447701677948416",
                )
                .map_err(|_| ())
                .unwrap(),
            ],
            vec![
                F::from_str(
                    "29658571352070370791360499299098360881857072189358092237807807261478461425147",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "7805182565862454238315452208989152534554369855020544477885853141626690738363",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "30699555847500141715826240743138908521140760599479365867708690318477369178275",
                )
                .map_err(|_| ())
                .unwrap(),
            ],
            vec![
                F::from_str(
                    "1231951350103545216624376889222508148537733140742167414518514908719103925687",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "24784260089125933876714702247471508077514206350883487938806451152907502751770",
                )
                .map_err(|_| ())
                .unwrap(),
                F::from_str(
                    "36563542611079418454711392295126742705798573252480028863133394504154697924536",
                )
                .map_err(|_| ())
                .unwrap(),
            ],
        ];
        let full_rounds = 8;
        let total_rounds = 37;
        let partial_rounds = total_rounds - full_rounds;
        PoseidonParameters::new(full_rounds, partial_rounds, alpha, mds, ark)
    }
}
