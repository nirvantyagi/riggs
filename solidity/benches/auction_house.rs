use ark_bn254::{Bn254, G1Projective as G};

use ethabi::Token;
use once_cell::sync::Lazy;
use primitive_types::U256;
use rand::{rngs::StdRng, SeedableRng, Rng};
use sha3::{Keccak256};

use std::{
  ops::Deref,
  str::{FromStr},
  collections::BTreeSet,
};

use rsa::{
  bigint::{BigInt},
  hash_to_prime::{pocklington::{PocklingtonCertParams, PocklingtonHash}},
  hog::{RsaGroupParams, RsaHiddenOrderGroup},
  poe::{PoEParams},
};
use timed_commitments::{
  PedersenComm,
  lazy_tc::{LazyTC},
};
use range_proofs::bulletproofs::{Bulletproofs};
use solidity::{
  encode_tc_comm, encode_tc_opening, encode_tc_pp, get_bigint_library_src,
  get_bn254_library_src, get_filename_src, get_fkps_src, get_pedersen_library_src,
  get_rsa_library_src, get_bulletproofs_verifier_contract_src,
};
use solidity_test_utils::{
  address::Address, contract::Contract, evm::Evm,
  to_be_bytes,
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

pub type Hog = RsaHiddenOrderGroup<TestRsaParams>;

const MOD_BITS: usize = 2048;
const TIME_PARAM: u32 = 40;
const NUM_BID_BITS: u64 = 32;
const LOG_NUM_BID_BITS: u64 = 5;

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

fn main() {
  // cargo bench --bench tc --profile test

  // Begin benchmark
  let mut rng = StdRng::seed_from_u64(1u64);

  // Generate parameters
  let (time_pp, time_pp_proof) = TC::gen_time_params(TIME_PARAM).unwrap();
  let ped_pp = PedersenComm::<G>::gen_pedersen_params(&mut rng);
  let bulletproofs_pp = Bulletproofs::<G, sha3::Keccak256>::gen_params(&mut rng, NUM_BID_BITS);
  assert!(TC::ver_time_params(&time_pp, &time_pp_proof).unwrap());

  // Create commitment, opening
  println!("Compiling contract...");

  // Compile contract from template
  let auction_house_src = get_filename_src("AuctionHouse.sol", true);
  let bn254_src = get_bn254_library_src();
  let bigint_src = get_bigint_library_src();
  let pedersen_lib_src = get_pedersen_library_src(&ped_pp, false);
  let rsa_src = get_rsa_library_src(TestRsaParams::M.deref(), MOD_BITS, false);
  let poe_src = get_filename_src("PoEVerifier.sol", false);
  let fkps_src = get_fkps_src(&time_pp.x.n, &time_pp.y.n, MOD_BITS, TIME_PARAM, false);
  let tc_src = get_filename_src("TC.sol", false);
  let bulletproofs_src =
      get_bulletproofs_verifier_contract_src(&bulletproofs_pp, &ped_pp, NUM_BID_BITS, LOG_NUM_BID_BITS, true);

  let solc_config = r#"
            {
                "language": "Solidity",
                "sources": {
                    "input.sol": { "content": "<%src%>" },
                    "BN254.sol": { "content": "<%bn254_src%>" },
                    "Pedersen.sol": { "content": "<%pedersen_lib_src%>" },
                    "BigInt.sol": { "content": "<%bigint_src%>" },
                    "RSA2048.sol": { "content": "<%rsa_lib_src%>" },
                    "PoEVerifier.sol": { "content": "<%poe_lib_src%>" },
                    "FKPS.sol": { "content": "<%fkps_lib_src%>" },
                    "TC.sol": { "content": "<%tc_lib_src%>" },
                    "BulletproofsVerifier.sol": { "content": "<%bulletproofs_lib_src%>" }
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
    .replace("<%opt%>", &false.to_string()) // Needed to disable opt for a BigNumber assembly instruction
    .replace("<%bn254_src%>", &bn254_src)
    .replace("<%pedersen_lib_src%>", &pedersen_lib_src)
    .replace("<%bigint_src%>", &bigint_src)
    .replace("<%rsa_lib_src%>", &rsa_src)
    .replace("<%poe_lib_src%>", &poe_src)
    .replace("<%fkps_lib_src%>", &fkps_src)
    .replace("<%tc_lib_src%>", &tc_src)
    .replace("<%bulletproofs_lib_src%>", &bulletproofs_src)
    .replace("<%src%>", &auction_house_src);

  let contract = Contract::compile_from_config(&solc_config, "AuctionHouse").unwrap();

  // Setup EVM
  let mut evm = Evm::new();
  let deployer = Address::random(&mut rng);
  evm.create_account(&deployer, 0);

  // Deploy contract
  let contract_constructor_input = vec![
    Token::Uint(U256::from(20)),
    Token::Uint(U256::from(10)),
  ];
  let create_result = evm
    .deploy(
      contract.encode_create_contract_bytes(&contract_constructor_input).unwrap(),
      &deployer,
    )
    .unwrap();
  let contract_addr = create_result.addr.clone();
  println!("Contract deploy gas cost: {}", create_result.gas);

  evm.set_block_number(1);
  let result = evm
    .call(
      contract
        .encode_call_contract_bytes("newAuction", &[])
        .unwrap(),
      &contract_addr,
      &deployer,
    )
    .unwrap();
  assert_eq!(&result.out, &to_be_bytes(&U256::from(0)));
  println!("Create auction gas cost: {:?}", result.gas);

  evm.set_block_number(8);
  let result = evm
      .call(
        contract
            .encode_call_contract_bytes("bidAuction", &[Token::Uint(U256::from(0))])
            .unwrap(),
        &contract_addr,
        &deployer,
      )
      .unwrap();
  let result = evm
      .call(
        contract
            .encode_call_contract_bytes("getAuctionPhase", &[Token::Uint(U256::from(0))])
            .unwrap(),
        &contract_addr,
        &deployer,
      )
      .unwrap();
  println!("{:?}", result);

  evm.set_block_number(25);
  let result = evm
      .call(
        contract
            .encode_call_contract_bytes("getAuctionPhase", &[Token::Uint(U256::from(0))])
            .unwrap(),
        &contract_addr,
        &deployer,
      )
      .unwrap();
  println!("{:?}", result);

  evm.set_block_number(35);
  let result = evm
      .call(
        contract
            .encode_call_contract_bytes("getAuctionPhase", &[Token::Uint(U256::from(0))])
            .unwrap(),
        &contract_addr,
        &deployer,
      )
      .unwrap();
  println!("{:?}", result);
}
