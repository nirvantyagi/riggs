use ark_bn254::{Bn254, G1Projective as G};

use ethabi::Token;
use once_cell::sync::Lazy;
use primitive_types::U256;
use rand::{rngs::StdRng, SeedableRng};
use sha3::{Digest, Keccak256};

use std::{ops::Deref, str::FromStr, thread, time::Duration};

use auction_house::{
    baseline_auction::AuctionParams,
    baseline_house::{AccountPrivateState, AuctionHouse, HouseAuctionParams, HouseParams},
};

use solidity::{
    encode_bulletproof, encode_new_auction, encode_tc_comm, encode_tc_opening, encode_tc_partial,
    get_bigint_library_src, get_bn254_deploy_src, get_bn254_library_src,
    get_bulletproofs_verifier_contract_src, get_filename_src, get_fkps_src,
    get_pedersen_deploy_src, get_pedersen_library_src, get_rsa_library_src,
};
use solidity_test_utils::{
    address::Address, contract::Contract, encode_bytes32, evm::Evm, to_be_bytes,
};

const MOD_BITS: usize = 2048;
const TIME_PARAM: u32 = 40;
const NUM_BID_BITS: u64 = 32;
const LOG_NUM_BID_BITS: u64 = 5;

pub type Account = AccountPrivateState<Keccak256>;

pub type TestAuctionHouse = AuctionHouse<Keccak256>;

use ark_ff::UniformRand;

use csv::Writer;
use std::{io::stdout, string::String, time::Instant};

mod utilities;
use utilities::{collect_bids, deploy_ah_coin, deploy_ahc_factory, deploy_erc721};

fn main() {
    let mut start = Instant::now();
    let mut end = start.elapsed().as_nanos();

    // csv writer
    let mut csv_writer = Writer::from_writer(stdout());
    csv_writer
        .write_record(&["function", "client_time", "server_time", "gas_cost"])
        .unwrap();
    csv_writer.flush().unwrap();

    let mut baseline_bids: Vec<u32> = Vec::new();
    let mut baseline_openings: Vec<u32> = Vec::new();

    // Begin benchmark
    let mut rng = StdRng::seed_from_u64(1u64);

    // Generate parameters
    let auction_pp = HouseAuctionParams {
        auction_pp: AuctionParams {
            t_bid_collection: Duration::from_secs(2),
            t_bid_self_open: Duration::from_secs(2),
        },
    };
    let house_pp = HouseParams {};

    // Setup EVM
    let mut evm = Evm::new();
    let deployer = Address::random(&mut rng);
    evm.create_account(&deployer, 0);

    let (erc721_contract, erc721_contract_addr) = deploy_erc721(&mut evm, &deployer);

    // println!("Compiling (but not deploying) Auction House Coin contract...");
    let ah_coin_contract = deploy_ah_coin(&mut evm, &deployer);

    // println!("Compiling Auction House Coin Factory contract...");
    let (ahc_factory_contract, ahc_factory_contract_addr) = deploy_ahc_factory(&mut evm, &deployer);

    // Compile auction house contract from template
    let auction_house_src = get_filename_src("BaselineAuctionHouse.sol", true);
    let erc20_src = get_filename_src("IERC20.sol", false);
    let erc721_src = get_filename_src("IERC721.sol", false);
    let ahc_factory_src = get_filename_src("AuctionHouseCoinFactory.sol", false);
    let ah_coin_src = get_filename_src("AuctionHouseCoin.sol", false);

    let solc_config = r#"
            {
                "language": "Solidity",
                "sources": {
                    "input.sol": { "content": "<%src%>" },
                    "IERC20.sol": { "content": "<%erc20_src%>" },
                    "IERC721.sol": { "content": "<%erc721_src%>" },
                    "AuctionHouseCoinFactory.sol": { "content": "<%ahc_factory_src%>" },
                    "AuctionHouseCoin.sol": { "content": "<%ah_coin_src%>" }
                },
                "settings": {
                    "optimizer": { "enabled": <%opt%> },
                    "outputSelection": {
                        "*": {
                            "*": [
                                "evm.bytecode.object", "abi"
                            ],
                        "": [ "*" ] } },
                    "libraries": {
                    }
                }
            }"#
    .replace("<%opt%>", &false.to_string())
    .replace("<%erc20_src%>", &erc20_src)
    .replace("<%erc721_src%>", &erc721_src)
    .replace("<%ahc_factory_src%>", &ahc_factory_src)
    .replace("<%ah_coin_src%>", &ah_coin_src)
    .replace("<%src%>", &auction_house_src);

    let ah_contract = Contract::compile_from_config(&solc_config, "AuctionHouse").unwrap();

    let contract_constructor_input = vec![ahc_factory_contract_addr.as_token()];
    let deploy_ah_result = evm
        .deploy(
            ah_contract
                .encode_create_contract_bytes(&contract_constructor_input)
                .unwrap(),
            &deployer,
        )
        .unwrap();
    let ah_contract_addr = deploy_ah_result.addr.clone();
    // Benchmark: Create House
    csv_writer
        .write_record(&["create_house", "0", "0", &deploy_ah_result.gas.to_string()])
        .unwrap();
    csv_writer.flush().unwrap();

    // Mint token to auction (auctioned by "owner")
    let owner = Address::random(&mut rng);

    let result_coin_address = evm
        .call(
            ah_contract
                .encode_call_contract_bytes("get_AHCoin_address", &[])
                .unwrap(),
            &ah_contract_addr,
            &owner,
        )
        .unwrap();

    let ahc_address_vec = &result_coin_address.out;

    let ah_coin_contract_addr = solidity_test_utils::address::Address(
        primitive_types::H160::from_slice(&ahc_address_vec[12..]),
    );
    // println!("Coin contract is at address: {:?}", ah_coin_contract_addr);

    evm.create_account(&owner, 0);
    let result = evm
        .call(
            erc721_contract
                .encode_call_contract_bytes("mint", &[owner.as_token(), Token::Uint(U256::from(1))])
                .unwrap(),
            &erc721_contract_addr,
            &deployer,
        )
        .unwrap();
    // println!("Minted token to auction: result: {:?}", result);

    // Owner approves auction house to take control of token
    let result = evm
        .call(
            erc721_contract
                .encode_call_contract_bytes(
                    "approve",
                    &[ah_contract_addr.as_token(), Token::Uint(U256::from(1))],
                )
                .unwrap(),
            &erc721_contract_addr,
            &owner,
        )
        .unwrap();
    // println!(
    //   "Approved auction house to transfer token: gas: {}",
    //   result.gas
    // );

    let mut auction_house = TestAuctionHouse::new(&house_pp);

    let n_bidders = 100;

    let big_balance = (n_bidders as u32) * 100;

    // Create bidders and their accounts in the AH contract
    let mut bidders = {
        let mut bidders = Vec::new();
        for i in 0..n_bidders {
            let bidder_addr = Address::random(&mut rng);
            evm.create_account(&bidder_addr, big_balance);

            let (uid, _) = auction_house.new_account(&house_pp);
            assert_eq!(uid, i as u32);
            auction_house
                .account_deposit(&house_pp, uid, big_balance)
                .unwrap();

            let result = evm
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

            let result = evm
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

            let result = evm
                .call(
                    ah_coin_contract
                        .encode_call_contract_bytes(
                            "deposit",
                            &[Token::Uint(U256::from(big_balance))],
                        )
                        .unwrap(),
                    &ah_coin_contract_addr,
                    &bidder_addr,
                )
                .unwrap();
            let mut bidder = Account::new();
            bidder.confirm_deposit(&house_pp, big_balance).unwrap();

            bidders.push((bidder, bidder_addr));
        }
        bidders
    };

    // create new auction
    evm.set_block_number(1);
    let result = evm
        .call(
            ah_contract
                .encode_call_contract_bytes(
                    "newAuction",
                    &[
                        erc721_contract_addr.as_token(),
                        Token::Uint(U256::from(1)),
                        Token::Uint(U256::from(20)),
                        Token::Uint(U256::from(10)),
                    ],
                )
                .unwrap(),
            &ah_contract_addr,
            &owner,
        )
        .unwrap();

    // Benchmark: Create New Auction
    csv_writer
        .write_record(&["create_auction", "0", "0", &result.gas.to_string()])
        .unwrap();
    csv_writer.flush().unwrap();
    assert_eq!(&result.out, &to_be_bytes(&U256::from(0)));

    let auction_id = auction_house.new_auction(&house_pp, &auction_pp);

    let mut place_bid_client: u64 = 0;
    let mut place_bid_server: u64 = 0;
    let mut place_bid_gas: u64 = 0;
    let mut place_bid_count: u64 = 0;

    // Bid collection
    evm.set_block_number(8);
    {
        for i in 0..n_bidders {
            let bid = (i as u32 + 1) * 20;
            let collateral = bid;
            let (bidder, bidder_addr) = bidders.get_mut(i).unwrap();

            // ClientTime: Submit Bid
            start = Instant::now();
            let (bid_proposal, opening) = bidder
                .propose_bid(&mut rng, &house_pp, &auction_pp, bid, collateral)
                .unwrap();
            end = start.elapsed().as_nanos();
            place_bid_client = place_bid_client + (end as u64);

            baseline_bids.push(bid);
            baseline_openings.push(opening);

            let result = evm
                .call(
                    ah_contract
                        .encode_call_contract_bytes(
                            "bidAuction",
                            &[
                                Token::Uint(U256::from(0 as u32)),
                                Token::FixedBytes(bid_proposal.comm_bid.to_vec()),
                                Token::Uint(U256::from(collateral)),
                            ],
                        )
                        .unwrap(),
                    &ah_contract_addr,
                    &bidder_addr,
                )
                .unwrap();
            place_bid_gas = place_bid_gas + result.gas;
            place_bid_count = place_bid_count + 1;

            bidder
                .confirm_bid(
                    &house_pp,
                    &auction_pp,
                    0,
                    (i as u32 + 1) * 20,
                    &bid_proposal,
                    opening,
                )
                .unwrap();

            start = Instant::now();
            let bidret = auction_house
                .account_bid(&house_pp, &auction_pp, 0, i as u32, &bid_proposal, bid)
                .unwrap();
            end = start.elapsed().as_nanos();
            place_bid_server = place_bid_server + (end as u64);
        }

        // Benchmark: Submit Bid
        csv_writer
            .write_record(&[
                "submit_bid",
                &(place_bid_client / place_bid_count).to_string(),
                &(place_bid_server / place_bid_count).to_string(),
                &(place_bid_gas / place_bid_count).to_string(),
            ])
            .unwrap();
        csv_writer.flush().unwrap();

        let result = evm
            .call(
                ah_contract
                    .encode_call_contract_bytes("getAuctionPhase", &[Token::Uint(U256::from(0))])
                    .unwrap(),
                &ah_contract_addr,
                &deployer,
            )
            .unwrap();
        assert_eq!(&result.out, &to_be_bytes(&U256::from(0))); // Bid collection enum = 0
    }

    // Self opening
    let mut self_open_client = 0;
    let mut self_open_server = 0;
    let mut self_open_gas = 0;
    let mut self_open_count = 0;

    evm.set_block_number(25);
    // thread::sleep(auction_pp.auction_pp.t_bid_collection);
    {
        for i in 0..(n_bidders - 1) {
            let (bidder, bidder_addr) = bidders.get_mut(i).unwrap();
            // let (bid, opening, _) = bidder.active_bids.get(&0).unwrap();
            let bid = baseline_bids.get(i).unwrap();
            let opening = baseline_openings.get(i).unwrap();
            let result = evm
                .call(
                    ah_contract
                        .encode_call_contract_bytes(
                            "selfOpenAuction",
                            &[
                                Token::Uint(U256::from(0)),
                                Token::Uint(U256::from(*bid)),
                                Token::Uint(U256::from(*opening)),
                            ],
                        )
                        .unwrap(),
                    &ah_contract_addr,
                    &bidder_addr,
                )
                .unwrap();
            self_open_gas = self_open_gas + result.gas;
            self_open_count = self_open_count + 1;

            bidder
                .confirm_bid_self_open(&house_pp, &auction_pp, 0)
                .unwrap();

            // ServerTime
            start = Instant::now();
            auction_house
                .account_self_open(&house_pp, &auction_pp, 0, i as u32, *bid, *opening)
                .unwrap();
            end = start.elapsed().as_nanos();
            self_open_server = self_open_server + (end as u64);
        }
        let result = evm
            .call(
                ah_contract
                    .encode_call_contract_bytes("getAuctionPhase", &[Token::Uint(U256::from(0))])
                    .unwrap(),
                &ah_contract_addr,
                &deployer,
            )
            .unwrap();
        assert_eq!(&result.out, &to_be_bytes(&U256::from(1))); // Bid self open enum = 1
    }

    // Benchmark: Self Opening Bid
    csv_writer
        .write_record(&[
            "self_open",
            "0",
            &(self_open_server / self_open_count).to_string(),
            &(self_open_gas / self_open_count).to_string(),
        ])
        .unwrap();
    csv_writer.flush().unwrap();

    // // Force opening
    evm.set_block_number(35);
    // thread::sleep(auction_pp.auction_pp.t_bid_self_open);

    // Benchmark: Force Opening Bid
    csv_writer
        .write_record(&["force_open", "0", "0", "0"])
        .unwrap();
    csv_writer.flush().unwrap();

    let mut complete_server = 0;
    let mut complete_gas = 0;
    let mut complete_count = 0;
    // Complete auction
    {
        let result = evm
            .call(
                ah_contract
                    .encode_call_contract_bytes("getAuctionPhase", &[Token::Uint(U256::from(0))])
                    .unwrap(),
                &ah_contract_addr,
                &deployer,
            )
            .unwrap();
        assert_eq!(&result.out, &to_be_bytes(&U256::from(2))); // Auction complete enum = 2

        let complete_result = evm
            .call(
                ah_contract
                    .encode_call_contract_bytes("completeAuction", &[Token::Uint(U256::from(0))])
                    .unwrap(),
                &ah_contract_addr,
                &deployer,
            )
            .unwrap();
        // println!("Complete auction: gas: {}", result.gas);
        // println!("{:?}", result);

        start = Instant::now();
        let (price, winners) = auction_house
            .complete_kplusone_price_auction(&house_pp, &auction_pp, 0, 0)
            .unwrap();
        end = start.elapsed().as_nanos();
        complete_server = end as u64;

        // Benchmark: Complete Auction
        csv_writer
            .write_record(&[
                "complete_auction",
                "0",
                &complete_server.to_string(),
                &complete_result.gas.to_string(),
            ])
            .unwrap();
        csv_writer.flush().unwrap();

        let mut reclaim_server = 0;
        let mut reclaim_gas = 0;
        let mut reclaim_count = 0;

        let winner = n_bidders - 1;
        for i in 0..n_bidders {
            if i == winner {
                continue;
            }
            let (bidder, bidder_addr) = bidders.get_mut(i).unwrap();
            start = Instant::now();
            let reclaim_result = evm
                .call(
                    ah_contract
                        .encode_call_contract_bytes("reclaim", &[Token::Uint(U256::from(0))])
                        .unwrap(),
                    &ah_contract_addr,
                    &bidder_addr,
                )
                .unwrap();

            reclaim_gas = reclaim_gas + reclaim_result.gas;
            reclaim_count = reclaim_count + 1;

            if i == 1 {
                csv_writer
                    .write_record(&["reclaim", "0", "0", &(reclaim_result.gas).to_string()])
                    .unwrap();
                csv_writer.flush().unwrap();
            }
        }

        // Check token was transferred to winning bidder
        let result = evm
            .call(
                erc721_contract
                    .encode_call_contract_bytes(
                        "balanceOf",
                        &[bidders.get(n_bidders - 2).unwrap().1.as_token()],
                    )
                    .unwrap(),
                &erc721_contract_addr,
                &deployer,
            )
            .unwrap();
        assert_eq!(&result.out, &to_be_bytes(&U256::from(1)));

        // // Check owner was transferred winning funds
        // // TODO: Optimization: Shouldn't need to provide range proof if no active bids
        // let withdrawal_proof = {
        //   let mut owner = Account::new();
        //   owner.confirm_deposit(&house_pp, 60).unwrap();
        //   owner.propose_withdrawal(&mut rng, &house_pp, 60).unwrap()
        // };
        // let result = evm
        //   .call(
        //     contract
        //       .encode_call_contract_bytes(
        //         "withdraw",
        //         &[
        //           Token::Uint(U256::from(60)),
        //           encode_bulletproof::<Bn254>(&withdrawal_proof),
        //         ],
        //       )
        //       .unwrap(),
        //     &contract_addr,
        //     &owner,
        //   )
        //   .unwrap();
        // println!(
        //   "Owner withdrew AHC from auction house balance: gas: {}",
        //   result.gas
        // );

        // bidders
        //   .get_mut(0)
        //   .unwrap()
        //   .0
        //   .confirm_auction_loss(&house_pp, &auction_pp, 0)
        //   .unwrap();
        // bidders
        //   .get_mut(1)
        //   .unwrap()
        //   .0
        //   .confirm_auction_loss(&house_pp, &auction_pp, 0)
        //   .unwrap();
        // bidders
        //   .get_mut(2)
        //   .unwrap()
        //   .0
        //   .confirm_auction_win(&house_pp, &auction_pp, 0, 60)
        //   .unwrap();
    }

    // // Withdrawal after active bids updated
    // {
    //   let (bidder, bidder_addr) = bidders.get_mut(1).unwrap();
    //   let withdrawal_proof = bidder.propose_withdrawal(&mut rng, &house_pp, 80).unwrap();
    //   let result = evm
    //     .call(
    //       contract
    //         .encode_call_contract_bytes(
    //           "withdraw",
    //           &[
    //             Token::Uint(U256::from(80)),
    //             encode_bulletproof::<Bn254>(&withdrawal_proof),
    //           ],
    //         )
    //         .unwrap(),
    //       &contract_addr,
    //       &bidder_addr,
    //     )
    //     .unwrap();
    //   println!(
    //     "Bidder 2 withdrew AHC from auction house balance: gas: {}",
    //     result.gas
    //   );
    //   //println!("{:?}", result);
    //   bidder.confirm_withdrawal(&house_pp, 80).unwrap();
    // }
}
