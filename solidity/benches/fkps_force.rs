use ethabi::Token;
use num_bigint::{RandomBits, Sign};
use once_cell::sync::Lazy;
use primitive_types::U256;
use rand::{distributions::Distribution, rngs::StdRng, SeedableRng};
use sha3::{Digest, Keccak256};

use std::{ops::Deref, str::FromStr};

use solidity_test_utils::{
  address::Address, contract::Contract, encode_bytes, encode_int_from_bytes, evm::Evm, to_be_bytes,
};

use rsa::{
  bigint::BigInt,
  hash_to_prime::HashToPrime,
  hog::{RsaGroupParams, RsaHiddenOrderGroup},
  poe::{PoE, PoEParams, Proof as PoEProof},
};

use solidity::{
  encode_fkps_comm, encode_fkps_opening, encode_fkps_pp, encode_poe_proof, encode_rsa_element,
  get_bigint_library_src, get_filename_src, get_fkps_src, get_rsa_library_src,
};

use rsa::hash_to_prime::pocklington::{PocklingtonCertParams, PocklingtonHash};
use timed_commitments::basic_tc;

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TestRsaParams;

impl RsaGroupParams for TestRsaParams {
  const G: Lazy<BigInt> = Lazy::new(|| BigInt::from(2));
  const M: Lazy<BigInt> = Lazy::new(|| {
    BigInt::from_str("25195908475657893494027183240048398571429282126204032027777137836043662020707595556264018525880784406918290641249515082189298559149176184502808489120072844992687392807287776735971418347270261896375014971824691165077613379859095700097330459748808428401797429100642458691817195118746121515172654632282216869987549182422433637259085141865462043576798423387184774447920739934236584823824281198163815010674810451660377306056201619676256133844143603833904414952634432190114657544454178424020924616515723350778707749817125772467962926386356373289912154831438167899885040445364023527381951378636564391212010397122822120720357").unwrap()
  });
}

pub type Hog = RsaHiddenOrderGroup<TestRsaParams>;

const MOD_BITS: usize = 2048;

use hex::ToHex;

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

pub type TC = basic_tc::BasicTC<
  TestPoEParams,
  TestRsaParams,
  Keccak256,
  PocklingtonHash<TestPocklingtonParams, Keccak256>,
>;

fn pad_32(input: &[u8]) -> [u8; 32] {
  let mut padded: [u8; 32] = [0; 32];
  let m = std::cmp::min(32, input.len());
  for i in 0..m {
    padded[31 - i] = input[input.len() - 1 - i];
  }
  return padded;
}

fn pad_256(input: &[u8]) -> [u8; 256] {
  let mut padded: [u8; 256] = [0; 256];
  let m = std::cmp::min(256, input.len());
  for i in 0..m {
    padded[255 - i] = input[input.len() - 1 - i];
  }
  return padded;
}
fn main() {
  // cargo bench --bench poe_verifier --profile test
  let mut rng = StdRng::seed_from_u64(1u64);

  // Create bid
  let bid = BigInt::from(10000);
  let bid_bytes = [bid.to_bytes_be().1].concat();

  // Generate parameters
  let (fkps_pp, fkps_pp_proof) = TC::gen_time_params(40).unwrap();
  assert!(TC::ver_time_params(&fkps_pp, &fkps_pp_proof).unwrap());

  // Create commitment, opening
  let mut ad = [0u8; 32];
  let (fkps_comm, _) = TC::commit(&mut rng, &fkps_pp, &bid_bytes, &ad).unwrap();

  let fkps_force_opening = TC::force_open(&fkps_pp, &fkps_comm, &ad).unwrap();

  println!("Compiling contract...");

  // Compile contract from template
  let bigint_src = get_bigint_library_src();
  let rsa_src = get_rsa_library_src(TestRsaParams::M.deref(), MOD_BITS, false);
  let poe_src = get_filename_src("PoElib.sol");
  let fkps_src = get_fkps_src(&fkps_pp.x.n, &fkps_pp.y.n, MOD_BITS, true);

  let solc_config = r#"
            {
                "language": "Solidity",
                "sources": {
                    "input.sol": { "content": "<%src%>" },
                    "BigInt.sol": { "content": "<%bigint_src%>" },
                    "RSA2048.sol": { "content": "<%rsa_lib_src%>" },
                    "PoElib.sol": { "content": "<%poe_lib_src%>" }
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

  match &fkps_force_opening.1 {
    basic_tc::Opening::SELF(r) => {}
    basic_tc::Opening::FORCE(y, poe_proof) => {
      let force_input = vec![
        encode_fkps_comm(&fkps_comm),
        encode_fkps_opening(&fkps_force_opening.1, &fkps_force_opening.0),
        encode_fkps_pp(TestRsaParams::M.deref(), &fkps_pp),
      ];

      let force_result = evm
        .call(
          contract
            .encode_call_contract_bytes("verForceOpen", &force_input)
            .unwrap(),
          &contract_addr,
          &deployer,
        )
        .unwrap();

      // println!("force result {:?}", &force_result.out);
      assert_eq!(&force_result.out, &to_be_bytes(&U256::from(1)));
      println!("FKPS Force verification succeeded");
      println!("Force verification costs {:?} gas", force_result.gas);
    }
  };
}
