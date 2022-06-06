use ark_bn254::{Bn254, G1Projective as G};

use ethabi::Token;
use once_cell::sync::Lazy;
use primitive_types::U256;
use rand::{rngs::StdRng, SeedableRng};
use sha3::Keccak256;

use std::{ops::Deref, str::FromStr, thread, time::Duration};

use auction_house::{
  rp_auction::AuctionParams,
  rp_house::{AccountPrivateState, AuctionHouse, HouseAuctionParams, HouseParams},
};
use range_proofs::bulletproofs::Bulletproofs;
use rsa::{
  bigint::BigInt,
  hash_to_prime::pocklington::{PocklingtonCertParams, PocklingtonHash},
  hog::{RsaGroupParams, RsaHiddenOrderGroup},
  poe::PoEParams,
};
use solidity::{
  encode_bulletproof, encode_new_auction, encode_ped_comm_struct, get_bigint_library_src,
  get_bn254_deploy_src, get_bn254_library_src, get_bulletproofs_verifier_contract_src,
  get_filename_src, get_fkps_src, get_pedersen_deploy_src, get_pedersen_library_src,
  get_rsa_library_src, mean, std_deviation
};
use solidity_test_utils::{
  address::Address, contract::Contract, encode_field_element, encode_group_element, evm::Evm,
  to_be_bytes,
};
use timed_commitments::{lazy_tc::LazyTC, PedersenComm};

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

pub type Hog = RsaHiddenOrderGroup<TestRsaParams>;

const MOD_BITS: usize = 2048;
const TIME_PARAM: u32 = 40;
const NUM_BID_BITS: u64 = 32;
const LOG_NUM_BID_BITS: u64 = 5;

const REWARD_SELF_OPEN: u32 = 5;
const REWARD_FORCE_OPEN: u32 = 5;

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TestPoEParams;

impl PoEParams for TestPoEParams {
  const HASH_TO_PRIME_ENTROPY: usize = 256;
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TestPocklingtonParams;
impl PocklingtonCertParams for TestPocklingtonParams {
  const NONCE_SIZE: usize = 16;
  const MAX_STEPS: usize = 5;
  const INCLUDE_SOLIDITY_WITNESSES: bool = true;
}

pub type TC = LazyTC<
  G,
  TestPoEParams,
  TestRsaParams,
  Keccak256,
  PocklingtonHash<TestPocklingtonParams, Keccak256>,
>;

pub type Account = AccountPrivateState<G, Keccak256>;

pub type TestAuctionHouse = AuctionHouse<G, Keccak256>;

use csv::{Writer, WriterBuilder};
use std::{io::stdout, string::String, time::Instant};

fn main() {
  let mut start = Instant::now();
  let mut end = start.elapsed().as_nanos();

  // csv writer
  let mut csv_writer = WriterBuilder::new().delimiter(b' ').from_writer(stdout());
  csv_writer
    .write_record(&["function", "client_time", "c_std", "server_time", "s_std","gas_cost"])
    .unwrap();
  csv_writer.flush().unwrap();

  // Begin benchmark
  let mut rng = StdRng::seed_from_u64(1u64);

  // Generate parameters
  let (time_pp, _time_pp_proof) = TC::gen_time_params(TIME_PARAM).unwrap();
  let ped_pp = PedersenComm::<G>::gen_pedersen_params(&mut rng);
  let bulletproofs_pp = Bulletproofs::<G, sha3::Keccak256>::gen_params(&mut rng, NUM_BID_BITS);
  let auction_pp = HouseAuctionParams {
    auction_pp: AuctionParams {
      t_bid_collection: Duration::from_secs(5),
      t_bid_self_open: Duration::from_secs(10),
      ped_pp: ped_pp.clone(),
    },
    reward_self_open: REWARD_SELF_OPEN,
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
  // TODO: Create better tooling for compiling and deploying with libraries
  // println!("Compiling bulletproofs contract...");
  let (_bulletproofs_contract, bulletproofs_contract_addr) = {
    let bn254_src = get_bn254_library_src();
    let pedersen_lib_src = get_pedersen_library_src(&ped_pp, false);
    let bulletproofs_src = get_bulletproofs_verifier_contract_src(
      &bulletproofs_pp,
      &ped_pp,
      NUM_BID_BITS,
      LOG_NUM_BID_BITS,
      false,
    );

    let solc_config = r#"
            {
                "language": "Solidity",
                "sources": {
                    "input.sol": { "content": "<%src%>" },
                    "BN254.sol": { "content": "<%bn254_src%>" },
                    "Pedersen.sol": { "content": "<%pedersen_lib_src%>" }
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
      .replace("<%bn254_src%>", &bn254_src)
      .replace("<%pedersen_lib_src%>", &pedersen_lib_src)
      .replace("<%src%>", &bulletproofs_src);

    let bulletproofs_contract =
      Contract::compile_from_config(&solc_config, "BulletproofsVerifier").unwrap();
    let create_result = evm
      .deploy(
        bulletproofs_contract
          .encode_create_contract_bytes(&[])
          .unwrap(),
        &deployer,
      )
      .unwrap();
    let contract_addr = create_result.addr.clone();
    // println!(
    //   "Bulletproofs contract deployed at address: {:?}",
    //   contract_addr
    // );
    (bulletproofs_contract, contract_addr)
  };

  // println!("Compiling timed commitments contract...");
  // let (_tc_contract, tc_contract_addr) = {
  //   let bn254_src = get_bn254_library_src();
  //   let bigint_src = get_bigint_library_src();
  //   let pedersen_lib_src = get_pedersen_library_src(&ped_pp, false);
  //   let rsa_src = get_rsa_library_src(TestRsaParams::M.deref(), MOD_BITS, false);
  //   let poe_src = get_filename_src("PoEVerifier.sol", false);
  //   let fkps_src = get_fkps_src(&time_pp.x.n, &time_pp.y.n, MOD_BITS, TIME_PARAM, false);
  //   let tc_src = get_filename_src("TC.sol", false);
  //
  //   let solc_config = r#"
  //           {
  //               "language": "Solidity",
  //               "sources": {
  //                   "input.sol": { "content": "<%src%>" },
  //                   "BN254.sol": { "content": "<%bn254_src%>" },
  //                   "Pedersen.sol": { "content": "<%pedersen_lib_src%>" },
  //                   "BigInt.sol": { "content": "<%bigint_src%>" },
  //                   "RSA2048.sol": { "content": "<%rsa_lib_src%>" },
  //                   "PoEVerifier.sol": { "content": "<%poe_lib_src%>" },
  //                   "FKPS.sol": { "content": "<%fkps_lib_src%>" }
  //               },
  //               "settings": {
  //                   "optimizer": { "enabled": <%opt%> },
  //                   "outputSelection": {
  //                       "*": {
  //                           "*": [
  //                               "evm.bytecode.object", "abi"
  //                           ],
  //                       "": [ "*" ] } }
  //               }
  //           }"#
  //     .replace("<%opt%>", &false.to_string()) // Needed to disable opt for a BigNumber assembly instruction
  //     .replace("<%bn254_src%>", &bn254_src)
  //     .replace("<%pedersen_lib_src%>", &pedersen_lib_src)
  //     .replace("<%bigint_src%>", &bigint_src)
  //     .replace("<%rsa_lib_src%>", &rsa_src)
  //     .replace("<%poe_lib_src%>", &poe_src)
  //     .replace("<%fkps_lib_src%>", &fkps_src)
  //     .replace("<%src%>", &tc_src);
  //
  //   let contract = Contract::compile_from_config(&solc_config, "TC").unwrap();
  //   let create_result = evm
  //     .deploy(
  //       contract.encode_create_contract_bytes(&[]).unwrap(),
  //       &deployer,
  //     )
  //     .unwrap();
  //   let contract_addr = create_result.addr.clone();
  //   println!(
  //     "Timed commitment contract deployed at address: {:?}",
  //     contract_addr
  //   );
  //   (contract, contract_addr)
  // };

  // Compile ERC721 contract from template

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

  // println!("Compiling (but not deploying) Auction House Coin contract...");
  let ah_coin_contract = {
    let auction_house_coin_src = get_filename_src("AuctionHouseCoin.sol", true);
    let bn254_src = get_bn254_library_src();
    let pedersen_lib_src = get_pedersen_library_src(&ped_pp, false);
    let bulletproofs_src = get_bulletproofs_verifier_contract_src(
      &bulletproofs_pp,
      &ped_pp,
      NUM_BID_BITS,
      LOG_NUM_BID_BITS,
      false,
    );
    let erc20_src = get_filename_src("IERC20.sol", false);
    let erc721_src = get_filename_src("IERC721.sol", false);

    let solc_config = r#"
            {
                "language": "Solidity",
                "sources": {
                    "input.sol": { "content": "<%src%>" },
                    "BN254.sol": { "content": "<%bn254_src%>" },
                    "Pedersen.sol": { "content": "<%pedersen_lib_src%>" },
                    "BulletproofsVerifier.sol": { "content": "<%bulletproofs_lib_src%>" },
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
                        "BulletproofsVerifier.sol": {
                            "BulletproofsVerifier": "<%bulletproofs_lib_addr%>"
                        }
                    }
                }
            }"#
      .replace("<%opt%>", &false.to_string()) // Needed to disable opt for a BigNumber assembly instruction
      .replace("<%bn254_src%>", &bn254_src)
      .replace("<%pedersen_lib_src%>", &pedersen_lib_src)
      .replace("<%bulletproofs_lib_src%>", &bulletproofs_src)
      .replace(
        "<%bulletproofs_lib_addr%>",
        &bulletproofs_contract_addr.to_string(),
      )
      .replace("<%erc20_src%>", &erc20_src)
      .replace("<%erc721_src%>", &erc721_src)
      .replace("<%src%>", &auction_house_coin_src);

    let contract = Contract::compile_from_config(&solc_config, "AuctionHouseCoin").unwrap();
    // let create_result = evm
    //   .deploy(
    //     contract.encode_create_contract_bytes(&[]).unwrap(),
    //     &deployer,
    //   )
    //   .unwrap();
    // let contract_addr = create_result.addr.clone();
    // println!("AH Coin contract deployed at address: {:?}", contract_addr);
    contract
  };

  // println!("Compiling Auction House Coin Factory contract...");
  let (ahc_factory_contract, ahc_factory_contract_addr) = {
    let ahc_factory_src = get_filename_src("AuctionHouseCoinFactory.sol", true);
    let bn254_src = get_bn254_library_src();
    let pedersen_lib_src = get_pedersen_library_src(&ped_pp, false);
    let bulletproofs_src = get_bulletproofs_verifier_contract_src(
      &bulletproofs_pp,
      &ped_pp,
      NUM_BID_BITS,
      LOG_NUM_BID_BITS,
      false,
    );
    let erc20_src = get_filename_src("IERC20.sol", false);
    let erc721_src = get_filename_src("IERC721.sol", false);
    let ah_coin_src = get_filename_src("AuctionHouseCoin.sol", false);

    let solc_config = r#"
            {
                "language": "Solidity",
                "sources": {
                    "input.sol": { "content": "<%src%>" },
                    "BN254.sol": { "content": "<%bn254_src%>" },
                    "Pedersen.sol": { "content": "<%pedersen_lib_src%>" },
                    "BulletproofsVerifier.sol": { "content": "<%bulletproofs_lib_src%>" },
                    "IERC20.sol": { "content": "<%erc20_src%>" },
                    "IERC721.sol": { "content": "<%erc721_src%>" },
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
                        "BulletproofsVerifier.sol": {
                            "BulletproofsVerifier": "<%bulletproofs_lib_addr%>"
                        }
                    }
                }
            }"#
      .replace("<%opt%>", &false.to_string()) // Needed to disable opt for a BigNumber assembly instruction
      .replace("<%bn254_src%>", &bn254_src)
      .replace("<%pedersen_lib_src%>", &pedersen_lib_src)
      .replace("<%bulletproofs_lib_src%>", &bulletproofs_src)
      .replace(
        "<%bulletproofs_lib_addr%>",
        &bulletproofs_contract_addr.to_string(),
      )
      .replace("<%erc20_src%>", &erc20_src)
      .replace("<%erc721_src%>", &erc721_src)
      .replace("<%ah_coin_src%>", &ah_coin_src)
      .replace("<%src%>", &ahc_factory_src);

    let contract = Contract::compile_from_config(&solc_config, "AuctionHouseCoinFactory").unwrap();
    let create_result = evm
      .deploy(
        contract.encode_create_contract_bytes(&[]).unwrap(),
        &deployer,
      )
      .unwrap();
    let contract_addr = create_result.addr.clone();
    // println!(
    //   "AHC Factory contract deployed at address: {:?}",
    //   contract_addr
    // );
    (contract, contract_addr)
  };

  // Compile auction house contract from template
  // !("Compiling RP auction house contract...");
  let rp_auction_house_src = get_filename_src("AuctionHouseRP.sol", true);
  let bn254_src = get_bn254_library_src();
  let pedersen_lib_src = get_pedersen_library_src(&ped_pp, false);
  let bulletproofs_src = get_bulletproofs_verifier_contract_src(
    &bulletproofs_pp,
    &ped_pp,
    NUM_BID_BITS,
    LOG_NUM_BID_BITS,
    false,
  );
  let erc20_src = get_filename_src("IERC20.sol", false);
  let erc721_src = get_filename_src("IERC721.sol", false);
  let ahc_factory_src = get_filename_src("AuctionHouseCoinFactory.sol", false);
  let ah_coin_src = get_filename_src("AuctionHouseCoin.sol", false);

  let solc_config = r#"
            {
                "language": "Solidity",
                "sources": {
                    "input.sol": { "content": "<%src%>" },
                    "BN254.sol": { "content": "<%bn254_src%>" },
                    "Pedersen.sol": { "content": "<%pedersen_lib_src%>" },
                    "BulletproofsVerifier.sol": { "content": "<%bulletproofs_lib_src%>" },
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
                        "BulletproofsVerifier.sol": {
                            "BulletproofsVerifier": "<%bulletproofs_lib_addr%>"
                        }
                    }
                }
            }"#
    .replace("<%opt%>", &false.to_string()) // Needed to disable opt for a BigNumber assembly instruction
    .replace("<%bn254_src%>", &bn254_src)
    .replace("<%pedersen_lib_src%>", &pedersen_lib_src)
    .replace("<%bulletproofs_lib_src%>", &bulletproofs_src)
    .replace(
      "<%bulletproofs_lib_addr%>",
      &bulletproofs_contract_addr.to_string(),
    )
    .replace("<%erc20_src%>", &erc20_src)
    .replace("<%erc721_src%>", &erc721_src)
    .replace("<%ahc_factory_src%>", &ahc_factory_src)
    .replace("<%ah_coin_src%>", &ah_coin_src)
    .replace("<%src%>", &rp_auction_house_src);

  let contract = Contract::compile_from_config(&solc_config, "AuctionHouseRP").unwrap();

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
  // println!(
  //   "ERC-721 contract deployed at address: {:?}",
  //   erc721_contract_addr
  // );
  // println!("ERC-721 contract deploy gas cost: {}", create_result.gas);

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
      contract
        .encode_create_contract_bytes(&contract_constructor_input)
        .unwrap(),
      &deployer,
    )
    .unwrap();
  let contract_addr = create_result.addr.clone();

  // Benchmark: Create House
  csv_writer
    .write_record(&["create_house", "0", "0",  "0", "0",&create_result.gas.to_string()])
    .unwrap();
  csv_writer.flush().unwrap();

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

  // Arasu: changed contract_addr to ah_coin_contract_addr
  // in many of these function calls

  let mut auction_house = TestAuctionHouse::new(&house_pp);

  let n_bidders = 10_usize;
  let max_balance = 10000;

  let mut bidders = {
    let mut bidders = Vec::new();
    for i in 0..n_bidders {
      let bidder_addr = Address::random(&mut rng);
      evm.create_account(&bidder_addr, max_balance);

      let (uid, _) = auction_house.new_account(&house_pp);
      assert_eq!(uid, i as u32);
      auction_house
        .account_deposit(&house_pp, uid, max_balance)
        .unwrap();

      let result = evm
        .call_payable(
          ah_coin_contract
            .encode_call_contract_bytes("exchangeAHCFromEther", &[])
            .unwrap(),
          &ah_coin_contract_addr,
          &bidder_addr,
          U256::from(max_balance),
        )
        .unwrap();
      // println!("Bidder {} exchanged ether for AHC: gas: {}", i, result.gas);

      // // Just testing ownership
      // let result = evm
      //   .call(
      //     ah_coin_contract
      //       .encode_call_contract_bytes("queryDeposit", &[bidder_addr.as_token()])
      //       .unwrap(),
      //     &ah_coin_contract_addr,
      //     &bidder_addr,
      //   )
      //   .unwrap();
      // // result will be "Revert"
      // println!("TRYING ONLY OWNERSHIP FUNCTIONS: {:?}", result);

      let result = evm
        .call(
          ah_coin_contract
            .encode_call_contract_bytes(
              "approve",
              &[
                ah_coin_contract_addr.as_token(),
                Token::Uint(U256::from(max_balance)),
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
            .encode_call_contract_bytes("deposit", &[Token::Uint(U256::from(max_balance))])
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
      bidder.confirm_deposit(&house_pp, max_balance).unwrap();

      bidders.push((bidder, bidder_addr));
    }
    bidders
  };

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
            Token::Uint(U256::from(REWARD_SELF_OPEN)),
          ],
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

  let mut place_bid_gas: u64 = 0;
  let mut place_bid_client_vec:Vec<u64> = Vec::new();
  let mut place_bid_server_vec:Vec<u64> = Vec::new();

  // Bid collection
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
          contract
            .encode_call_contract_bytes(
              "bidAuction",
              &[
                Token::Uint(U256::from(0)),
                encode_ped_comm_struct::<Bn254>(&bid_proposal.comm_bid.g),
                encode_bulletproof::<Bn254>(&bid_proposal.range_proof_bid),
                encode_bulletproof::<Bn254>(&bid_proposal.range_proof_balance),
              ],
            )
            .unwrap(),
          &contract_addr,
          &bidder_addr,
        )
        .unwrap();

      if i==1 {place_bid_gas = result.gas;}
      
      // println!("Bidder {} placed bid: gas: {}", i, result.gas);
      //println!("{:?}", result);

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
  let mut self_open_gas = 0;
  let mut self_open_client_vec:Vec<u64> = Vec::new();
  let mut self_open_server_vec:Vec<u64> = Vec::new();

  evm.set_block_number(25);
  thread::sleep(auction_pp.auction_pp.t_bid_collection);
  {
    for i in 0..n_bidders {
      let (bidder, bidder_addr) = bidders.get_mut(i).unwrap();

      // ClientTime
      start = Instant::now();
      let bidder_clone = bidder.clone();
      let (bid, opening, _) = bidder_clone.active_bids.get(&0).unwrap();
      end = start.elapsed().as_nanos();
      self_open_client_vec.push(end as u64);

      let result = evm
        .call(
          contract
            .encode_call_contract_bytes(
              "selfOpenAuction",
              &[
                Token::Uint(U256::from(0)),
                Token::Uint(U256::from(*bid)),
                encode_field_element::<Bn254>(&opening),
              ],
            )
            .unwrap(),
          &contract_addr,
          &bidder_addr,
        )
        .unwrap();
      // println!("Bidder {} self-opened bid: gas: {}", i, result.gas);

      if (i==1) {self_open_gas = result.gas as u64;}

      bidder
        .confirm_bid_self_open(&house_pp, &auction_pp)
        .unwrap();

      // ServerTime
      start = Instant::now();
      auction_house
        .account_self_open(&house_pp, &auction_pp, 0, i as u32, *bid, opening)
        .unwrap();
      end = start.elapsed().as_nanos();
      self_open_server_vec.push(end as u64);
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

  // Benchmark: Self Opening Bid
  csv_writer
    .write_record(&[
      "self_open",
        //&mean(&self_open_client_vec).unwrap().to_string(),
        &format!("{:01}", (&mean(&self_open_client_vec).unwrap())),
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
          contract
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

  // // Force opening
  evm.set_block_number(35);
  thread::sleep(auction_pp.auction_pp.t_bid_self_open);

  // Benchmark: Force Opening Bid
  csv_writer
    .write_record(&["force_open", "0", "0", "0", "0", "0"])
    .unwrap();
  csv_writer.flush().unwrap();

  // {
  //   let result = evm
  //     .call(
  //       contract
  //         .encode_call_contract_bytes("getAuctionPhase", &[Token::Uint(U256::from(0))])
  //         .unwrap(),
  //       &contract_addr,
  //       &deployer,
  //     )
  //     .unwrap();
  //   assert_eq!(&result.out, &to_be_bytes(&U256::from(2))); // Bid force open enum = 2
  //
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
  // }

  // Complete auction
  let winner = n_bidders - 2;

  let mut complete_server = 0;
  let mut complete_server_fixed = 0;
  let mut complete_gas = 0;
  let mut complete_count = 0;

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

    let complete_result = evm
      .call(
        contract
          .encode_call_contract_bytes("completeAuction", &[Token::Uint(U256::from(0))])
          .unwrap(),
        &contract_addr,
        &deployer,
      )
      .unwrap();
    // println!("Complete auction: gas: {}", result.gas);

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
    //     "0",
    //     &(complete_server).to_string(),
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

    // Benchmark: Complete Auction
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

    // // Check token was transferred to winning bidder
    // let result = evm
    //   .call(
    //     erc721_contract
    //       .encode_call_contract_bytes(
    //         "balanceOf",
    //         &[bidders.get(n_bidders - 1).unwrap().1.as_token()],
    //       )
    //       .unwrap(),
    //     &erc721_contract_addr,
    //     &deployer,
    //   )
    //   .unwrap();
    // assert_eq!(&result.out, &to_be_bytes(&U256::from(1)));
    // println!(
    //   "Bidder n_bidders-1 won and received token: gas: {}",
    //   result.gas
    // );

    // Check owner was transferred winning funds
    // TODO: Optimization: Shouldn't need to provide range proof if no active bids
    let withdrawal_proof = {
      let mut owner = Account::new();
      owner.confirm_deposit(&house_pp, 60).unwrap();
      owner.propose_withdrawal(&mut rng, &house_pp, 60).unwrap()
    };
    let result = evm
      .call(
        contract
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
      .get_mut(2)
      .unwrap()
      .0
      .confirm_auction_win(&house_pp, &auction_pp, 0, 60)
      .unwrap();
  }

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
        contract
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

  // // Withdrawal after active bids updated
  // {
  //   let (bidder, bidder_addr) = bidders.get_mut(1).unwrap();
  //   let withdrawal_proof = bidder
  //     .propose_withdrawal(&mut rng, &house_pp, 1000)
  //     .unwrap();
  //   let result = evm
  //     .call(
  //       contract
  //         .encode_call_contract_bytes(
  //           "withdraw",
  //           &[
  //             Token::Uint(U256::from(1000)),
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
  //   bidder.confirm_withdrawal(&house_pp, 1000).unwrap();
  // }
}
