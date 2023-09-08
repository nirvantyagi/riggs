use ark_bn254::{Bn254, G1Projective as G};

use ethabi::Token;
use once_cell::sync::Lazy;
use primitive_types::U256;
use rand::{rngs::StdRng, SeedableRng};
use sha3::{Digest, Keccak256};

use std::{ops::Deref, str::FromStr};

use auction_house::{
    baseline_auction::AuctionParams,
    baseline_house::{AccountPrivateState, HouseAuctionParams, HouseParams},
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
use ark_ff::UniformRand;

fn main() {
    let mut baseline_bids: Vec<u32> = Vec::new();
    let mut baseline_openings: Vec<u32> = Vec::new();

    // Begin benchmark
    let mut rng = StdRng::seed_from_u64(1u64);

    // Generate parameters
    let auction_pp = HouseAuctionParams {
        auction_pp: AuctionParams {
            t_bid_collection: Default::default(),
            t_bid_self_open: Default::default(),
        },
    };
    let house_pp = HouseParams {};

    // Setup EVM
    let mut evm = Evm::new();
    let deployer = Address::random(&mut rng);
    evm.create_account(&deployer, 0);

    // Compile ERC721 contract from template
    println!("Compiling ERC721 contract...");

    let solc_config = r#"
            {
                "language": "Solidity",
                "sources": {
                    "input.sol": { "content": "<%src%>" },
                    "IERC721.sol": { "content": "<%erc721_src%>" }
                },
                "settings": {
                    "optimizer": { "enabled": <%opt%> },
                    "outputSelection": {
                        "*": {
                            "*": [
                                "evm.bytecode.object", "abi"
                            ],
                        "": [ "*" ] } }
                }
            }"#
    .replace("<%opt%>", &true.to_string())
    .replace("<%erc721_src%>", &get_filename_src("IERC721.sol", false))
    .replace("<%src%>", &get_filename_src("TestERC721.sol", true));

    let erc721_contract = Contract::compile_from_config(&solc_config, "TestERC721").unwrap();

    println!("Compiling (but not deploying) Auction House Coin contract...");
    let ah_coin_contract = {
        let auction_house_coin_src = get_filename_src("AuctionHouseCoin.sol", true);
        let erc20_src = get_filename_src("IERC20.sol", false);
        let erc721_src = get_filename_src("IERC721.sol", false);

        let solc_config = r#"
            {
                "language": "Solidity",
                "sources": {
                    "input.sol": { "content": "<%src%>" },
                    "IERC20.sol": { "content": "<%erc20_src%>" },
                    "IERC721.sol": { "content": "<%erc721_src%>" }
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
        .replace("<%src%>", &auction_house_coin_src);

        let contract = Contract::compile_from_config(&solc_config, "AuctionHouseCoin").unwrap();
        contract
    };

    println!("Compiling Auction House Coin Factory contract...");
    let (ahc_factory_contract, ahc_factory_contract_addr) = {
        let ahc_factory_src = get_filename_src("AuctionHouseCoinFactory.sol", true);
        let erc20_src = get_filename_src("IERC20.sol", false);
        let erc721_src = get_filename_src("IERC721.sol", false);
        let ah_coin_src = get_filename_src("AuctionHouseCoin.sol", false);

        let solc_config = r#"
            {
                "language": "Solidity",
                "sources": {
                    "input.sol": { "content": "<%src%>" },
                    "AuctionHouseCoin.sol": { "content": "<%ah_coin_src%>" },
                    "IERC20.sol": { "content": "<%erc20_src%>" },
                    "IERC721.sol": { "content": "<%erc721_src%>" }

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
        .replace("<%opt%>", &false.to_string()) // Needed to disable opt for a BigNumber assembly instruction
        .replace("<%erc20_src%>", &erc20_src)
        .replace("<%erc721_src%>", &erc721_src)
        .replace("<%ah_coin_src%>", &ah_coin_src)
        .replace("<%src%>", &ahc_factory_src);

        let contract =
            Contract::compile_from_config(&solc_config, "AuctionHouseCoinFactory").unwrap();
        let create_result = evm
            .deploy(
                contract.encode_create_contract_bytes(&[]).unwrap(),
                &deployer,
            )
            .unwrap();
        let contract_addr = create_result.addr.clone();
        println!(
            "AHC Factory contract deployed at address: {:?}",
            contract_addr
        );
        (contract, contract_addr)
    };

    // Compile auction house contract from template
    println!("Compiling auction house contract...");
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

    let contract = Contract::compile_from_config(&solc_config, "AuctionHouse").unwrap();

    // Deploy ERC-721 contract
    let create_result = evm
        .deploy(
            erc721_contract
                .encode_create_contract_bytes(&[
                    Token::String("TestERC721".to_string()),
                    Token::String("NFT".to_string()),
                ])
                .unwrap(),
            &deployer,
        )
        .unwrap();
    let erc721_contract_addr = create_result.addr.clone();
    println!(
        "ERC-721 contract deployed at address: {:?}",
        erc721_contract_addr
    );
    println!("ERC-721 contract deploy gas cost: {}", create_result.gas);

    // Deploy auction house contract
    let contract_constructor_input = vec![ahc_factory_contract_addr.as_token()];
    let create_result = evm
        .deploy(
            contract
                .encode_create_contract_bytes(&contract_constructor_input)
                .unwrap(),
            &deployer,
        )
        .unwrap();
    let contract_addr = create_result.addr.clone();
    println!("Contract deploy gas cost: {}", create_result.gas);

    // Mint token to auction (auctioned by "owner")
    let owner = Address::random(&mut rng);

    let result_coin_address = evm
        .call(
            contract
                .encode_call_contract_bytes("get_AHCoin_address", &[])
                .unwrap(),
            &contract_addr,
            &owner,
        )
        .unwrap();
    println!("Owner created auction: gas: {}", result_coin_address.gas);

    let ahc_address_vec = &result_coin_address.out;

    let ah_coin_contract_addr = solidity_test_utils::address::Address(
        primitive_types::H160::from_slice(&ahc_address_vec[12..]),
    );
    println!("Coin contract is at address: {:?}", ah_coin_contract_addr);

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
    //println!("Minted token to auction: result: {:?}", result);
    println!("Minted token to auction: gas: {}", result.gas);

    // Owner approves auction house to take control of token
    let result = evm
        .call(
            erc721_contract
                .encode_call_contract_bytes(
                    "approve",
                    &[contract_addr.as_token(), Token::Uint(U256::from(1))],
                )
                .unwrap(),
            &erc721_contract_addr,
            &owner,
        )
        .unwrap();
    //println!("Approved auction house to transfer token: result: {:?}", result);
    println!(
        "Approved auction house to transfer token: gas: {}",
        result.gas
    );

    let mut bidders = {
        let mut bidders = Vec::new();
        for i in 0..3_usize {
            let bidder_addr = Address::random(&mut rng);
            evm.create_account(&bidder_addr, 100);

            let result = evm
                .call_payable(
                    ah_coin_contract
                        .encode_call_contract_bytes("exchangeAHCFromEther", &[])
                        .unwrap(),
                    &ah_coin_contract_addr,
                    &bidder_addr,
                    U256::from(80),
                )
                .unwrap();
            println!("Bidder {} exchanged ether for AHC: gas: {}", i, result.gas);
            //println!("{:?}", result);

            let result = evm
                .call(
                    ah_coin_contract
                        .encode_call_contract_bytes(
                            "approve",
                            &[
                                ah_coin_contract_addr.as_token(),
                                Token::Uint(U256::from(80)),
                            ],
                        )
                        .unwrap(),
                    &ah_coin_contract_addr,
                    &bidder_addr,
                )
                .unwrap();
            println!(
                "Bidder {} approved auction house to transfer AHC: gas: {}",
                i, result.gas
            );
            //println!("{:?}", result);

            let result = evm
                .call(
                    ah_coin_contract
                        .encode_call_contract_bytes("deposit", &[Token::Uint(U256::from(80))])
                        .unwrap(),
                    &ah_coin_contract_addr,
                    &bidder_addr,
                )
                .unwrap();
            println!(
                "Bidder {} deposited AHC into auction house balance: gas: {}",
                i, result.gas
            );
            //println!("{:?}", result);

            let mut bidder = Account::new();
            bidder.confirm_deposit(&house_pp, 80).unwrap();

            bidders.push((bidder, bidder_addr));
        }
        bidders
    };

    // create new auction
    evm.set_block_number(1);
    let result = evm
        .call(
            contract
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
            &contract_addr,
            &owner,
        )
        .unwrap();
    println!("Owner created auction: gas: {}", result.gas);
    assert_eq!(&result.out, &to_be_bytes(&U256::from(0)));

    // Bid collection
    evm.set_block_number(8);
    {
        for i in 0..3_usize {
            let bid = (i as u32 + 1) * 20;
            let collateral = bid;
            let (bidder, bidder_addr) = bidders.get_mut(i).unwrap();
            let (bid_proposal, opening) = bidder
                .propose_bid(&mut rng, &house_pp, &auction_pp, bid, collateral)
                .unwrap();

            baseline_bids.push(bid);
            baseline_openings.push(opening);

            let result = evm
                .call(
                    contract
                        .encode_call_contract_bytes(
                            "bidAuction",
                            &[
                                Token::Uint(U256::from(0 as u32)),
                                Token::FixedBytes(bid_proposal.comm_bid.to_vec()),
                                Token::Uint(U256::from(collateral)),
                            ],
                        )
                        .unwrap(),
                    &contract_addr,
                    &bidder_addr,
                )
                .unwrap();
            println!("Bidder {} placed bid: gas: {}", i, result.gas);
            // println!("{:?}", result);

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
        }

        let result = evm
            .call(
                contract
                    .encode_call_contract_bytes("getAuctionPhase", &[Token::Uint(U256::from(0))])
                    .unwrap(),
                &contract_addr,
                &deployer,
            )
            .unwrap();
        assert_eq!(&result.out, &to_be_bytes(&U256::from(0))); // Bid collection enum = 0
    }

    // Self opening
    evm.set_block_number(25);
    {
        for i in 0..2_usize {
            let (bidder, bidder_addr) = bidders.get_mut(i).unwrap();
            // let (bid, opening, _) = bidder.active_bids.get(&0).unwrap();
            let bid = baseline_bids.get(i).unwrap();
            let opening = baseline_openings.get(i).unwrap();
            let result = evm
                .call(
                    contract
                        .encode_call_contract_bytes(
                            "selfOpenAuction",
                            &[
                                Token::Uint(U256::from(0)),
                                Token::Uint(U256::from(*bid)),
                                Token::Uint(U256::from(*opening)),
                            ],
                        )
                        .unwrap(),
                    &contract_addr,
                    &bidder_addr,
                )
                .unwrap();
            println!("Bidder {} self-opened bid: gas: {}", i, result.gas);
            // println!("{:?}", result);
            bidder
                .confirm_bid_self_open(&house_pp, &auction_pp, 0)
                .unwrap();
        }
        let result = evm
            .call(
                contract
                    .encode_call_contract_bytes("getAuctionPhase", &[Token::Uint(U256::from(0))])
                    .unwrap(),
                &contract_addr,
                &deployer,
            )
            .unwrap();
        assert_eq!(&result.out, &to_be_bytes(&U256::from(1))); // Bid self open enum = 1
    }

    // // Force opening
    evm.set_block_number(35);
    {
        // let result = evm
        //   .call(
        //     contract
        //       .encode_call_contract_bytes("getAuctionPhase", &[Token::Uint(U256::from(0))])
        //       .unwrap(),
        //     &contract_addr,
        //     &deployer,
        //   )
        //   .unwrap();
        // assert_eq!(&result.out, &to_be_bytes(&U256::from(2))); // Auction complete enum = 2

        //   let (bidder, bidder_addr) = bidders.get(2).unwrap();
        //   let (bid, _, comm) = bidder.active_bids.get(&0).unwrap();
        //   let (_, opening) = TC::force_open(&time_pp, &ped_pp, comm).unwrap();
        //   let (_opener, opener_addr) = bidders.get(0).unwrap();
        //   let result = evm
        //     .call(
        //       contract
        //         .encode_call_contract_bytes(
        //           "forceOpenAuction",
        //           &[
        //             Token::Uint(U256::from(0)),
        //             bidder_addr.as_token(),
        //             Token::Uint(U256::from(*bid)),
        //             encode_tc_opening(&opening),
        //           ],
        //         )
        //         .unwrap(),
        //       &contract_addr,
        //       &opener_addr,
        //     )
        //     .unwrap();
        //   println!("Bidder 0 force-opened bid 2: gas: {}", result.gas);
        //   //println!("{:?}", result);
        //   let (opener, _opener_addr) = bidders.get_mut(0).unwrap();
        //   opener
        //     .confirm_bid_force_open(&house_pp, &auction_pp)
        //     .unwrap();
        // }

        // // Withdrawal
        // {
        //   let (bidder, bidder_addr) = bidders.get_mut(0).unwrap();
        //   let withdrawal_proof = bidder.propose_withdrawal(&mut rng, &house_pp, 65).unwrap();
        //   let result = evm
        //     .call(
        //       contract
        //         .encode_call_contract_bytes(
        //           "withdraw",
        //           &[
        //             Token::Uint(U256::from(65)),
        //             encode_bulletproof::<Bn254>(&withdrawal_proof),
        //           ],
        //         )
        //         .unwrap(),
        //       &contract_addr,
        //       &bidder_addr,
        //     )
        //     .unwrap();
        //   println!(
        //     "Bidder 0 withdrew AHC from auction house balance: gas: {}",
        //     result.gas
        //   );
        //   //println!("{:?}", result);
        //   bidder.confirm_withdrawal(&house_pp, 65).unwrap();
    }

    // Complete auction
    {
        let result = evm
            .call(
                contract
                    .encode_call_contract_bytes("getAuctionPhase", &[Token::Uint(U256::from(0))])
                    .unwrap(),
                &contract_addr,
                &deployer,
            )
            .unwrap();
        assert_eq!(&result.out, &to_be_bytes(&U256::from(2))); // Auction complete enum = 2

        let result = evm
            .call(
                contract
                    .encode_call_contract_bytes("completeAuction", &[Token::Uint(U256::from(0))])
                    .unwrap(),
                &contract_addr,
                &deployer,
            )
            .unwrap();
        println!("Complete auction: gas: {}", result.gas);
        //println!("{:?}", result);

        // Check token was transferred to winning bidder
        let result = evm
            .call(
                erc721_contract
                    .encode_call_contract_bytes(
                        "balanceOf",
                        &[bidders.get(1).unwrap().1.as_token()],
                    )
                    .unwrap(),
                &erc721_contract_addr,
                &deployer,
            )
            .unwrap();
        assert_eq!(&result.out, &to_be_bytes(&U256::from(1)));
        println!("Bidder 1 won and received token: gas: {}", result.gas);

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
