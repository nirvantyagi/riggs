use once_cell::sync::Lazy;
use primitive_types::U256;
use rand::{rngs::StdRng, SeedableRng, Rng};
use sha3::{Keccak256};

use std::{ops::Deref, str::FromStr};

use solidity_test_utils::{
  address::Address, contract::Contract, evm::Evm, to_be_bytes,
};

use rsa::{
  bigint::BigInt,
  hash_to_prime::{
    pocklington::{PocklingtonCertParams, PocklingtonHash},
  },
  hog::{RsaGroupParams, RsaHiddenOrderGroup},
  poe::{PoE, PoEParams, Proof as PoEProof},
};
use timed_commitments::{
  basic_tc::{BasicTC},
};
use solidity::{
  encode_fkps_comm, encode_fkps_opening, encode_fkps_pp,
  get_bigint_library_src, get_filename_src, get_fkps_src,
  get_rsa_library_src,
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


#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TestPoEParams;

impl PoEParams for TestPoEParams {
  const HASH_TO_PRIME_ENTROPY: usize = 128; // TODO: This should be 256
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TestPocklingtonParams;
impl PocklingtonCertParams for TestPocklingtonParams {
  const NONCE_SIZE: usize = 16;
  const MAX_STEPS: usize = 5;
  const INCLUDE_SOLIDITY_WITNESSES: bool = true;
}

pub type TC = BasicTC<
  TestPoEParams,
  TestRsaParams,
  Keccak256,
  PocklingtonHash<TestPocklingtonParams, Keccak256>,
>;


fn main() {
  // cargo bench --bench fkps --profile test
  let mut rng = StdRng::seed_from_u64(1u64);

  // Generate time parameters
  let (fkps_pp, fkps_pp_proof) = TC::gen_time_params(TIME_PARAM).unwrap();
  assert!(TC::ver_time_params(&fkps_pp, &fkps_pp_proof).unwrap());

  // Create commitment, opening
  let mut m = [0u8; 32];
  rng.fill(&mut m);
  let (comm, opening) = TC::commit(&mut rng, &fkps_pp, &m).unwrap();

  println!("Compiling contract...");

  // Compile contract from template
  let bigint_src = get_bigint_library_src();
  let rsa_src = get_rsa_library_src(TestRsaParams::M.deref(), MOD_BITS, false);
  let poe_src = get_filename_src("PoEVerifier.sol", false);
  let fkps_src = get_fkps_src(&fkps_pp.x.n, &fkps_pp.y.n, MOD_BITS, TIME_PARAM, true);

  let solc_config = r#"
            {
                "language": "Solidity",
                "sources": {
                    "input.sol": { "content": "<%src%>" },
                    "BigInt.sol": { "content": "<%bigint_src%>" },
                    "RSA2048.sol": { "content": "<%rsa_lib_src%>" },
                    "PoEVerifier.sol": { "content": "<%poe_lib_src%>" }
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
    .replace("<%opt%>", &false.to_string())
    .replace("<%bigint_src%>", &bigint_src)
    .replace("<%rsa_lib_src%>", &rsa_src)
    .replace("<%poe_lib_src%>", &poe_src)
    .replace("<%src%>", &fkps_src);

  let contract = Contract::compile_from_config(&solc_config, "FKPS").unwrap();

  // Setup EVM
  let mut evm = Evm::new();
  let deployer = Address::random(&mut rng);
  evm.create_account(&deployer, 0);

  // Deploy contract
  let create_result = evm
    .deploy(
      contract.encode_create_contract_bytes(&[]).unwrap(),
      &deployer,
    )
    .unwrap();
  let contract_addr = create_result.addr.clone();
  println!("Contract deploy gas cost: {}", create_result.gas);

  let input = vec![
    encode_fkps_comm(&comm),
    encode_fkps_opening(&opening, &Some(m.to_vec())),
    encode_fkps_pp(TestRsaParams::M.deref(), &fkps_pp),
  ];

  let result = evm
    .call(
      contract
        .encode_call_contract_bytes("verOpen", &input)
        .unwrap(),
      &contract_addr,
      &deployer,
    )
    .unwrap();

  assert_eq!(&result.out, &to_be_bytes(&U256::from(1)));
  println!("FKPS verification costs {:?} gas", result.gas);

  // Part 2: TEST Force Open
  // The part below is moved to a separate fkps_force bench file.
  // To do it in this file, just uncomment what's below
  // AND change the entropy parameter to 256 above.

  // let fkps_force_opening = TC::force_open(&fkps_pp, &fkps_comm, &ad).unwrap();

  // match &fkps_force_opening.1 {
  //   basic_tc::Opening::SELF(r) => {}
  //   basic_tc::Opening::FORCE(y, poe_proof) => {
  //     let (force_z_hat, force_opening_proof) = (y, poe_proof);
  //     // Call force verify function on contract;
  //     let force_input = vec![
  //       encode_rsa_element(&fkps_comm.x),
  //       encode_bytes(&fkps_comm.ct),
  //       encode_rsa_element(&y),
  //       encode_poe_proof(&poe_proof),
  //       encode_bytes(&bid_bytes),
  //     ];

  //     let force_result = evm
  //       .call(
  //         contract
  //           .encode_call_contract_bytes("testVerForceOpen", &force_input)
  //           .unwrap(),
  //         &contract_addr,
  //         &deployer,
  //       )
  //       .unwrap();

  //     println!("force result from {:?}", &force_result.out);
  //   }
  // };
}