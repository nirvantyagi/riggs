use ark_bn254::{Bn254, G1Projective as G};

use ark_ec::short_weierstrass_jacobian::GroupProjective;
use ark_ec::ProjectiveCurve;
use ethabi::Token;
mod preamble;
use preamble::{Account, TestPoEParams, TestPocklingtonParams, TestRsaParams};
use primitive_types::U256;

use auction_house::house::{AccountPrivateState, AuctionHouse, HouseAuctionParams, HouseParams};
use rand::rngs::StdRng;
use rand::SeedableRng;
use rsa::{
    bigint::BigInt,
    hash_to_prime::pocklington::{PocklingtonCertParams, PocklingtonHash},
};
use sha3::Keccak256;
use solidity::{encode_bulletproof, encode_new_auction, encode_tc_comm, encode_tc_opening};
use solidity_test_utils::{
    address::Address, contract::Contract, encode_field_element, evm::Evm, to_be_bytes,
};
use timed_commitments::{lazy_tc::LazyTC, PedersenComm};

use csv::WriterBuilder;
use std::{io::stdout, time::Instant};

use solidity::{mean, std_deviation};

// pub fn setup_bidders<PoEP: PoEParams, RsaP: RsaGroupParams, H: Digest, H2P: HashToPrime>(
//     evm: &mut Evm,
//     n_bidders: usize,
//     auction_house: &AuctionHouse<G, PoEP, RsaP, H, H2P>,
//     house_pp: &HouseParams<G>,
//     ah_coin_contract: &Contract,
//     ah_coin_contract_addr: &Address,
//     bidders: &Vec<(AccountPrivateState<G, PoEP, RsaP, H, H2P>, Address)>,
// ) {

pub fn setup_bidders(
    evm: &mut Evm,
    n_bidders: usize,
    auction_house: &mut AuctionHouse<
        G,
        TestPoEParams,
        TestRsaParams,
        Keccak256,
        PocklingtonHash<TestPocklingtonParams, Keccak256>,
    >,
    house_pp: &HouseParams<G>,
    ah_coin_contract: &mut Contract,
    ah_coin_contract_addr: &Address,
) -> Vec<(
    AccountPrivateState<
        G,
        TestPoEParams,
        TestRsaParams,
        Keccak256,
        PocklingtonHash<TestPocklingtonParams, Keccak256>,
    >,
    Address,
)> {
    let mut rng = StdRng::seed_from_u64(1u64);
    let mut bidders = Vec::new();

    let big_balance = (n_bidders as u32) * 100;
    for i in 0..n_bidders {
        let bidder_addr = Address::random(&mut rng);
        evm.create_account(&bidder_addr, big_balance);

        let (uid, _) = auction_house.new_account(&house_pp);
        assert_eq!(uid, i as u32);
        auction_house
            .account_deposit(&house_pp, uid, big_balance)
            .unwrap();

        let _ = evm
            .call_payable(
                ah_coin_contract
                    .encode_call_contract_bytes("exchangeAHCFromEther", &[])
                    .unwrap(),
                &ah_coin_contract_addr,
                &bidder_addr,
                U256::from(big_balance),
            )
            .unwrap();
        // println!("Bidder {} exchanged ether for AHC: gas: {}", i, result.gas);

        let _ = evm
            .call(
                ah_coin_contract
                    .encode_call_contract_bytes(
                        "approve",
                        &[
                            ah_coin_contract_addr.as_token(),
                            Token::Uint(U256::from(big_balance)),
                        ],
                    )
                    .unwrap(),
                &ah_coin_contract_addr,
                &bidder_addr,
            )
            .unwrap();
        // println!(
        //   "Bidder {} approved auction house to transfer AHC: gas: {}",
        //   i, result.gas
        // );

        let _ = evm
            .call(
                ah_coin_contract
                    .encode_call_contract_bytes("deposit", &[Token::Uint(U256::from(big_balance))])
                    .unwrap(),
                &ah_coin_contract_addr,
                &bidder_addr,
            )
            .unwrap();
        // println!(
        //   "Bidder {} deposited AHC into auction house balance: gas: {}",
        //   i, result.gas
        // );

        let mut bidder = Account::new();
        bidder.confirm_deposit(house_pp, big_balance).unwrap();

        bidders.push((bidder, bidder_addr));
    }
    bidders
}
