use ark_bn254::{Bn254, G1Projective as G};

use ark_ec::ProjectiveCurve;
use ark_ff::{biginteger::BigInteger, PrimeField};
use ethabi::Token;
use num_integer::Integer;
use num_traits::FromPrimitive;
use once_cell::sync::Lazy;
use primitive_types::U256;
use rand::{rngs::StdRng, SeedableRng};
use sha3::Keccak256;

use num_bigint::Sign;
use std::{ops::Deref, str::FromStr, thread, time::Duration};

use auction_house::{
  auction::AuctionParams,
  house::{AccountPrivateState, AuctionHouse, HouseAuctionParams, HouseParams},
};
use range_proofs::bulletproofs::Bulletproofs;
use rsa::{
  bigint::{nat_to_f, BigInt},
  hash_to_prime::pocklington::{PocklingtonCertParams, PocklingtonHash},
  hog::{RsaGroupParams, RsaHiddenOrderGroup},
  poe::PoEParams,
};
use solidity::{
  encode_bulletproof, encode_new_auction, encode_tc_comm, encode_tc_opening
};
use solidity_test_utils::{
  address::Address, contract::Contract, encode_field_element, evm::Evm, to_be_bytes,
};
use timed_commitments::{lazy_tc::LazyTC, PedersenComm};

use csv::{Writer, WriterBuilder};
use std::{io::stdout, string::String, time::Instant};

use solidity::{mean, std_deviation};

mod preamble;
use preamble::{deploy_bulletproofs, deploy_tc, deploy_erc721, deploy_ah_coin, deploy_ahc_factory, deploy_ah};
use preamble::{TestRsaParams, Hog, TestPoEParams, TestPocklingtonParams, TC, Account, TestAuctionHouse};
use preamble::{MOD_BITS, TIME_PARAM, NUM_BID_BITS, LOG_NUM_BID_BITS, REWARD_SELF_OPEN, REWARD_FORCE_OPEN};

fn main() {
  let order = BigInt::from_str("220221485961027482895807132690296630677486844071857248828102639779900826037\
                522817575171387188561253238223028895754955597267595588137098207226627715313\
                686049237996261509248457831215460282155642105163463527516323185300916088248\
                789771290659167975569920900762065967420098972398211591577160443767729150998\
                814909357423098257777268264247365382899876367590978535154987039555696635449\
                479033630746473829352109992523017984438324929520913675495666843818457268371\
                447341902888262499596643623902905552015345991769002075550880559006205833829\
                780310095180709267067428790477468978775910299274821078714680960191595657081\
                71734442332552864").unwrap();

  let n_bidders: usize = 10_usize;

  let mut start = Instant::now();
  let mut end = start.elapsed().as_millis();

  // csv writer
  let mut csv_writer = WriterBuilder::new().delimiter(b' ').from_writer(stdout());
  csv_writer
    .write_record(&["function", "client_time", "c_std", "server_time", "s_std","gas_cost"])
    .unwrap();
  csv_writer.flush().unwrap();

  // Begin benchmark
  let mut rng = StdRng::seed_from_u64(1u64);

  // Generate parameters
  let time_pp = TC::gen_time_params_cheating(TIME_PARAM, &order).unwrap();

  let ped_pp = PedersenComm::<G>::gen_pedersen_params(&mut rng);
  let bulletproofs_pp = Bulletproofs::<G, sha3::Keccak256>::gen_params(&mut rng, NUM_BID_BITS);
  let auction_pp = HouseAuctionParams {
    auction_pp: AuctionParams {
      t_bid_collection: Duration::from_secs(5),
      t_bid_self_open: Duration::from_secs(10),
      time_pp: time_pp.clone(),
      ped_pp: ped_pp.clone(),
    },
    reward_self_open: REWARD_SELF_OPEN,
    reward_force_open: REWARD_FORCE_OPEN,
  };
  let house_pp = HouseParams {
    range_proof_pp: bulletproofs_pp.clone(),
    ped_pp: ped_pp.clone(),
  };

  // Setup EVM
  let mut evm = Evm::new();
  let deployer = Address::random(&mut rng);
  evm.create_account(&deployer, 0);

  // Compile and deploy libraries to reduce contract size under limit

  // println!("Compiling bulletproofs contract...");
  let (_bulletproofs_contract, bulletproofs_contract_addr) = deploy_bulletproofs(&mut evm, &deployer, &ped_pp, &bulletproofs_pp);
  
  // println!("Compiling timed commitments contract...");
  let (_tc_contract, tc_contract_addr) = deploy_tc(&mut evm, &deployer, &ped_pp, &time_pp); 

  let (erc721_contract, erc721_contract_addr) = deploy_erc721(&mut evm, &deployer);

  // println!("Compiling (but not deploying) Auction House Coin contract...");
  let ah_coin_contract = deploy_ah_coin(&mut evm, &deployer, &ped_pp, &bulletproofs_pp, &bulletproofs_contract_addr);

  // println!("Compiling Auction House Coin Factory contract...");
  let (ahc_factory_contract, ahc_factory_contract_addr) = deploy_ahc_factory(&mut evm, &deployer, &ped_pp, &bulletproofs_pp, &bulletproofs_contract_addr);


  let (ah_contract, contract_addr) = deploy_ah(&mut evm, &deployer, &ped_pp, &time_pp, &bulletproofs_pp, &bulletproofs_contract_addr, &tc_contract_addr, &ahc_factory_contract_addr);

  // Deploy auction house contract
  let contract_constructor_input = vec![
    ahc_factory_contract_addr.as_token(),
    // Token::Uint(U256::from(20)),
    // Token::Uint(U256::from(10)),
    // Token::Uint(U256::from(REWARD_SELF_OPEN)),
    // Token::Uint(U256::from(REWARD_FORCE_OPEN)),
  ];
  let create_result = evm
    .deploy(
      ah_contract
        .encode_create_contract_bytes(&contract_constructor_input)
        .unwrap(),
      &deployer,
    )
    .unwrap();
  let contract_addr = create_result.addr.clone();
  // println!("Contract deploy gas cost: {}", create_result.gas);

  // Benchmark: Create House
  csv_writer
    .write_record(&["create_house", "0", "0",  "0", "0",&create_result.gas.to_string()])
    .unwrap();
  csv_writer.flush().unwrap();

  // Mint token to auction (auctioned by "owner")
  let owner = Address::random(&mut rng);

  let result_coin_address = evm
    .call(
      ah_contract
        .encode_call_contract_bytes("get_AHCoin_address", &[])
        .unwrap(),
      &contract_addr,
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
  //println!("Minted token to auction: result: {:?}", result);
  // println!("Minted token to auction: gas: {}", result.gas);

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
  // println!(
  //   "Approved auction house to transfer token: gas: {}",
  //   result.gas
  // );

  let mut auction_house = TestAuctionHouse::new(&house_pp);

  let big_balance = (n_bidders as u32) * 100;
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
      //println!("{:?}", result);

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
      // println!(
      //   "Bidder {} approved auction house to transfer AHC: gas: {}",
      //   i, result.gas
      // );
      //println!("{:?}", result);

      let result = evm
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
      //println!("{:?}", result);

      let mut bidder = Account::new();
      bidder.confirm_deposit(&house_pp, big_balance).unwrap();

      bidders.push((bidder, bidder_addr));
    }
    bidders
  };

  let new_auction_inputs = encode_new_auction::<Bn254, _>(
    &erc721_contract_addr,
    1,
    20,
    10,
    REWARD_SELF_OPEN,
    REWARD_FORCE_OPEN,
    &time_pp,
  );

  evm.set_block_number(1);
  let result = evm
    .call(
      ah_contract
        .encode_call_contract_bytes(
          "newAuction",
          // &[
          //   erc721_contract_addr.as_token(),
          //   Token::Uint(U256::from(1)),
          //   Token::Uint(U256::from(20)),
          //   Token::Uint(U256::from(10)),
          //   Token::Uint(U256::from(REWARD_SELF_OPEN)),
          //   Token::Uint(U256::from(REWARD_FORCE_OPEN)),
          // ],
          &new_auction_inputs,
        )
        .unwrap(),
      &contract_addr,
      &owner,
    )
    .unwrap();
  // println!("Owner created auction: gas: {}", result.gas);
  assert_eq!(&result.out, &to_be_bytes(&U256::from(0)));

  let auction_id = auction_house.new_auction(&house_pp, &auction_pp);

  // Benchmark: Create Auction
  csv_writer
    .write_record(&["create_auction", "0", "0",  "0", "0", &result.gas.to_string()])
    .unwrap();
  csv_writer.flush().unwrap();
  assert_eq!(&result.out, &to_be_bytes(&U256::from(0)));

  // Bid collection

  let mut place_bid_gas: u64 = 0;
  let mut place_bid_client_vec:Vec<u64> = Vec::new();
  let mut place_bid_server_vec:Vec<u64> = Vec::new();

  evm.set_block_number(8);
  {
    for i in 0..n_bidders {
      let (bidder, bidder_addr) = bidders.get_mut(i).unwrap();
      start = Instant::now();
      let (bid_proposal, opening) = bidder
        .propose_bid(&mut rng, &house_pp, &auction_pp, (i as u32 + 1) * 20)
        .unwrap();
      end = start.elapsed().as_nanos();
      place_bid_client_vec.push(end as u64);


      let result = evm
        .call(
          ah_contract
            .encode_call_contract_bytes(
              "bidAuction",
              &[
                Token::Uint(U256::from(0)),
                encode_tc_comm::<Bn254, _>(&bid_proposal.comm_bid),
                encode_bulletproof::<Bn254>(&bid_proposal.range_proof_bid),
                encode_bulletproof::<Bn254>(&bid_proposal.range_proof_balance),
              ],
            )
            .unwrap(),
          &contract_addr,
          &bidder_addr,
        )
        .unwrap();

      // println!("Bidder {} placed bid: gas: {}", i, result.gas);
      
      if i==0 {place_bid_gas=result.gas;}

      bidder
        .confirm_bid(
          &house_pp,
          &auction_pp,
          0,
          (i as u32 + 1) * 20,
          &bid_proposal,
          &opening,
        )
        .unwrap();

      start = Instant::now();
      let bidret = auction_house
        .account_bid(&house_pp, &auction_pp, 0, i as u32, &bid_proposal)
        .unwrap();
      end = start.elapsed().as_nanos();
      place_bid_server_vec.push(end as u64);
    }

    // Benchmark: Submit Bid
    csv_writer
      .write_record(&[
        "submit_bid",
        &mean(&place_bid_client_vec).unwrap().to_string(),
        &std_deviation(&place_bid_client_vec).unwrap().to_string(),
        &mean(&place_bid_server_vec).unwrap().to_string(),
        &std_deviation(&place_bid_server_vec).unwrap().to_string(),
        &(place_bid_gas).to_string(),
      ])
      .unwrap();
    csv_writer.flush().unwrap();

    let result = evm
      .call(
        ah_contract
          .encode_call_contract_bytes("getAuctionPhase", &[Token::Uint(U256::from(0))])
          .unwrap(),
        &contract_addr,
        &deployer,
      )
      .unwrap();
    assert_eq!(&result.out, &to_be_bytes(&U256::from(0))); // Bid collection enum = 0
  }

  // Self opening
  let mut self_open_gas = 0;
  let mut self_open_client_vec:Vec<u64> = Vec::new();
  let mut self_open_server_vec:Vec<u64> = Vec::new();
  
  evm.set_block_number(25);
  thread::sleep(auction_pp.auction_pp.t_bid_collection);
  {
    for i in 0..(n_bidders - 1) {
      let (bidder, bidder_addr) = bidders.get_mut(i).unwrap();
      // ClientTime
      start = Instant::now();
      let bidder_clone = bidder.clone();
      let (bid, opening, _) = bidder_clone.active_bids.get(&0).unwrap();
      end = start.elapsed().as_nanos();
      self_open_client_vec.push(end as u64);

      let tc_m_copy = &(opening.tc_m).clone().unwrap();

      let mut m_computed = tc_m_copy.to_vec();
      // let f_bytes = <G::ScalarField as PrimeField>::BigInt::NUM_LIMBS * 8;
      let f_bytes = 32;
      let ped_opening = nat_to_f(&BigInt::from_bytes_be(
        Sign::Plus,
        &m_computed.split_off(m_computed.len() - f_bytes),
      ))
      .unwrap();

      let result = evm
        .call(
          ah_contract
            .encode_call_contract_bytes(
              "selfOpenAuctionOptimized",
              &[
                Token::Uint(U256::from(0)),
                Token::Uint(U256::from(*bid)),
                encode_field_element::<Bn254>(&ped_opening),
              ],
            )
            .unwrap(),
          &contract_addr,
          &bidder_addr,
        )
        .unwrap();

      if (i==1) {self_open_gas = result.gas as u64;}
    
      // println!("Bidder {} self-opened bid: gas: {}", i, result.gas);

      bidder
        .confirm_bid_self_open(&house_pp, &auction_pp)
        .unwrap();
      // ServerTime
      start = Instant::now();
      auction_house
        .account_self_open_optimized(&house_pp, &auction_pp, 0, i as u32, *bid, &ped_opening)
        .unwrap();
      end = start.elapsed().as_nanos();
      self_open_server_vec.push(end as u64);
    }
    let result = evm
      .call(
        ah_contract
          .encode_call_contract_bytes("getAuctionPhase", &[Token::Uint(U256::from(0))])
          .unwrap(),
        &contract_addr,
        &deployer,
      )
      .unwrap();
    assert_eq!(&result.out, &to_be_bytes(&U256::from(1))); // Bid self open enum = 1
  }

  // Benchmark: Self Opening Bid
  csv_writer
    .write_record(&[
      "self_open",
        &mean(&self_open_client_vec).unwrap().to_string(),
        &std_deviation(&self_open_client_vec).unwrap().to_string(),
        &mean(&self_open_server_vec).unwrap().to_string(),
        &std_deviation(&self_open_server_vec).unwrap().to_string(),
        &self_open_gas.to_string(),
    ])
    .unwrap();
  csv_writer.flush().unwrap();

  let mut update_winnner_gas = 0;
  // Benchmark: Update winner, prices
  {
    for i in 0..(n_bidders - 1) {
      let (bidder, bidder_addr) = bidders.get_mut(i).unwrap();

      let bidder_clone = bidder.clone();
      let (bid, opening, _) = bidder_clone.active_bids.get(&0).unwrap();

      let result = evm
        .call(
          ah_contract
            .encode_call_contract_bytes(
              "updateWinnerPrices",
              &[
                Token::Uint(U256::from(0)),
                bidder_addr.as_token(),
                Token::Uint(U256::from(*bid)),
              ],
            )
            .unwrap(),
          &contract_addr,
          &bidder_addr,
        )
        .unwrap();

      update_winnner_gas = result.gas as u64;
    }
  }

  // // Benchmark: Update Prices
  // csv_writer
  //   .write_record(&["update_prices", "0", "0", &update_winnner_gas.to_string()])
  //   .unwrap();
  // csv_writer.flush().unwrap();

  // Force opening
  let mut force_open_gas = 0;

  let mut force_open_client_vec:Vec<u64> = Vec::new();
  let mut force_open_server_vec:Vec<u64> = Vec::new();

  evm.set_block_number(35);
  thread::sleep(auction_pp.auction_pp.t_bid_self_open);
  {
    let result = evm
      .call(
        ah_contract
          .encode_call_contract_bytes("getAuctionPhase", &[Token::Uint(U256::from(0))])
          .unwrap(),
        &contract_addr,
        &deployer,
      )
      .unwrap();
    assert_eq!(&result.out, &to_be_bytes(&U256::from(2))); // Bid force open enum = 2

    let (bidder, bidder_addr) = bidders.get(n_bidders - 1).unwrap();
    let (bid, _, comm) = bidder.active_bids.get(&0).unwrap();

    // ClientTime
    start = Instant::now();
    let (_, opening) = TC::force_open_cheating(&time_pp, &ped_pp, comm, &order).unwrap();
    end = start.elapsed().as_nanos();
    force_open_client_vec.push(end as u64);

    let mut bidders_clone = bidders.clone();

    let (opener, opener_addr) = bidders_clone.get_mut(0).unwrap();
    let result = evm
      .call(
        ah_contract
          .encode_call_contract_bytes(
            "forceOpenAuction",
            &[
              Token::Uint(U256::from(0)),
              bidder_addr.as_token(),
              Token::Uint(U256::from(*bid)),
              encode_tc_opening(&opening),
            ],
          )
          .unwrap(),
        &contract_addr,
        &opener_addr,
      )
      .unwrap();
    // println!("Bidder 0 force-opened bid 2: gas: {}", result.gas);

    // CALL UPDATE FUNCTION
    let update_result = evm
      .call(
        ah_contract
          .encode_call_contract_bytes(
            "updateWinnerPrices",
            &[
              Token::Uint(U256::from(0)),
              bidder_addr.as_token(),
              Token::Uint(U256::from(*bid)),
            ],
          )
          .unwrap(),
        &contract_addr,
        &bidder_addr,
      )
      .unwrap();

    force_open_gas = result.gas as u64;

    // ServerTime
    start = Instant::now();
    // opener
    //   .confirm_bid_force_open(&house_pp, &auction_pp)
    //   .unwrap();
    auction_house
      .account_force_open(
        &house_pp,
        &auction_pp,
        0,
        (n_bidders - 1) as u32,
        (n_bidders - 1) as u32,
        Some(*bid),
        &opening,
      )
      .unwrap();
    end = start.elapsed().as_nanos();
    force_open_server_vec.push(end as u64);
  }

  // Benchmark: Force Opening Bid
  csv_writer
    .write_record(&[
      "FORCE_OPEN",
        &mean(&force_open_client_vec).unwrap().to_string(),
        &std_deviation(&force_open_client_vec).unwrap().to_string(),
         &mean(&force_open_server_vec).unwrap().to_string(),
        &std_deviation(&force_open_server_vec).unwrap().to_string(),
        &force_open_gas.to_string(),
    ])
    .unwrap();
  csv_writer.flush().unwrap();

  // Withdrawal

  {
    let (bidder, bidder_addr) = bidders.get_mut(0).unwrap();
    let withdrawal_proof = bidder.propose_withdrawal(&mut rng, &house_pp, 65).unwrap();
    let result = evm
      .call(
        ah_contract
          .encode_call_contract_bytes(
            "withdraw",
            &[
              Token::Uint(U256::from(65)),
              encode_bulletproof::<Bn254>(&withdrawal_proof),
            ],
          )
          .unwrap(),
        &contract_addr,
        &bidder_addr,
      )
      .unwrap();
    // println!(
    //   "Bidder 0 withdrew AHC from auction house balance: gas: {}",
    //   result.gas
    // );
    //println!("{:?}", result);
    bidder.confirm_withdrawal(&house_pp, 65).unwrap();
  }

  // Complete auction

  let mut complete_server = 0;
  let mut complete_server_fixed = 0;
  let mut complete_gas = 0;
  let mut complete_count = 0;

  let winner = n_bidders - 1;

  {
    let result = evm
      .call(
        ah_contract
          .encode_call_contract_bytes("getAuctionPhase", &[Token::Uint(U256::from(0))])
          .unwrap(),
        &contract_addr,
        &deployer,
      )
      .unwrap();
    assert_eq!(&result.out, &to_be_bytes(&U256::from(3))); // Auction complete enum = 3

    let result = evm
      .call(
        ah_contract
          .encode_call_contract_bytes("completeAuction", &[Token::Uint(U256::from(0))])
          .unwrap(),
        &contract_addr,
        &deployer,
      )
      .unwrap();
    // println!("Complete auction: gas: {}", result.gas);
    //println!("{:?}", result);
    complete_gas = result.gas as u64;

    // Check token was transferred to winning bidder
    let result = evm
      .call(
        erc721_contract
          .encode_call_contract_bytes(
            "balanceOf",
            &[bidders.get(n_bidders - 1).unwrap().1.as_token()],
          )
          .unwrap(),
        &erc721_contract_addr,
        &deployer,
      )
      .unwrap();
    assert_eq!(&result.out, &to_be_bytes(&U256::from(1)));
    // println!("Bidder nbidders-1 won and received token: gas: {}", result.gas);

    start = Instant::now();
    let (price, winners) = auction_house
      .complete_kplusone_price_auction(&house_pp, &auction_pp, 0, 0)
      .unwrap();
    end = start.elapsed().as_nanos();
    complete_server = end as u64;

    // csv_writer
    //   .write_record(&[
    //     "complete_auction_full_calc",
    //     "0",
    //     "0",
    //     &(complete_server).to_string(),
    //     "0",
    //     "0",
    //   ])
    //   .unwrap();
    // csv_writer.flush().unwrap();

    start = Instant::now();
    let (price, winners) = auction_house
      .complete_fixed_price(&house_pp, &auction_pp, 0, 0)
      .unwrap();
    end = start.elapsed().as_nanos();
    complete_server_fixed = end as u64;

    // Check owner was transferred winning funds
    // TODO: Optimization: Shouldn't need to provide range proof if no active bids
    let withdrawal_proof = {
      let mut owner = Account::new();
      owner.confirm_deposit(&house_pp, 60).unwrap();
      owner.propose_withdrawal(&mut rng, &house_pp, 60).unwrap()
    };
    let withdraw_result = evm
      .call(
        ah_contract
          .encode_call_contract_bytes(
            "withdraw",
            &[
              Token::Uint(U256::from(60)),
              encode_bulletproof::<Bn254>(&withdrawal_proof),
            ],
          )
          .unwrap(),
        &contract_addr,
        &owner,
      )
      .unwrap();
    // println!(
    //   "Owner withdrew AHC from auction house balance: gas: {}",
    //   result.gas
    // );

    bidders
      .get_mut(0)
      .unwrap()
      .0
      .confirm_auction_loss(&house_pp, &auction_pp, 0)
      .unwrap();
    bidders
      .get_mut(1)
      .unwrap()
      .0
      .confirm_auction_loss(&house_pp, &auction_pp, 0)
      .unwrap();
    bidders
      .get_mut(n_bidders - 1)
      .unwrap()
      .0
      .confirm_auction_win(&house_pp, &auction_pp, 0, 60)
      .unwrap();
  }

  csv_writer
    .write_record(&[
      "complete_auction_fixed",
      "0",
      "0",
      &(complete_server_fixed / 1).to_string(),
      "0",
      &(complete_gas / 1).to_string(),
    ])
    .unwrap();
  csv_writer.flush().unwrap();

  let mut reclaim_server = 0;
  let mut reclaim_gas = 0;
  let mut reclaim_count = 0;

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
        &contract_addr,
        &bidder_addr,
      )
      .unwrap();

    if i == 1 {
      // csv_writer
      //   .write_record(&["reclaim", "0", "0", &(reclaim_result.gas).to_string()])
      //   .unwrap();
      // csv_writer.flush().unwrap();
      reclaim_gas = reclaim_result.gas;
    }
  }
  csv_writer
    .write_record(&[
      "complete_auction_per_bidder",
      "0",
      "0",
      &((complete_server - complete_server_fixed) / (n_bidders as u64)).to_string(),
      "0",
      &(reclaim_gas + update_winnner_gas).to_string(),
    ])
    .unwrap();
  csv_writer.flush().unwrap();

  // Withdrawal after active bids updated

  let mut withdraw_client_vec:Vec<u64> = Vec::new();
  let mut withdraw_server_vec:Vec<u64> = Vec::new();
  let mut withdraw_gas = 0;
  {
    for i in 0..n_bidders {
      let (bidder, bidder_addr) = bidders.get_mut(i).unwrap();
      start = Instant::now();
      let withdrawal_proof = bidder.propose_withdrawal(&mut rng, &house_pp, 80).unwrap();
      end = start.elapsed().as_nanos();
      withdraw_client_vec.push(end as u64);

      let withdraw_result = evm
        .call(
          ah_contract
            .encode_call_contract_bytes(
              "withdraw",
              &[
                Token::Uint(U256::from(80)),
                encode_bulletproof::<Bn254>(&withdrawal_proof),
              ],
            )
            .unwrap(),
          &contract_addr,
          &bidder_addr,
        )
        .unwrap();

      withdraw_gas = withdraw_result.gas as u64;
      bidder.confirm_withdrawal(&house_pp, 80).unwrap();

      start = Instant::now();
      auction_house.account_withdrawal(&house_pp, 1, 80, &withdrawal_proof);
      end = start.elapsed().as_nanos();
      withdraw_server_vec.push(end as u64);
    }

          // Benchmark: Withdraw
      csv_writer
        .write_record(&[
          "withdraw",
          &mean(&withdraw_client_vec).unwrap().to_string(),
          &std_deviation(&withdraw_client_vec).unwrap().to_string(),
          &mean(&withdraw_server_vec).unwrap().to_string(),
          &std_deviation(&withdraw_server_vec).unwrap().to_string(),
          &(withdraw_gas).to_string(),
        ])
        .unwrap();
      csv_writer.flush().unwrap();
  }
}
