use ark_bn254::{Bn254, G1Projective as G};
use ark_ec::ProjectiveCurve;
use ark_ff::{biginteger::BigInteger, PrimeField};

use ethabi::Token;
use num_bigint::{RandomBits, Sign};
use once_cell::sync::Lazy;
use primitive_types::U256;
use rand::{distributions::Distribution, rngs::StdRng, SeedableRng};
use sha3::{Digest, Keccak256};

use std::{ops::Deref, str::FromStr};

use solidity_test_utils::{
  address::Address, contract::Contract, encode_bytes, encode_field_element, encode_group_element,
  encode_int_from_bytes, evm::Evm, to_be_bytes,
};

use rsa::{
  bigint::{nat_to_f, BigInt},
  hash_to_prime::HashToPrime,
  hog::{RsaGroupParams, RsaHiddenOrderGroup},
  poe::{PoE, PoEParams, Proof as PoEProof},
};

use solidity::{
  encode_rsa_element, get_bigint_library_src, get_bn254_library_src, get_filename_src,
  get_fkps_library_src, get_pedersen_library_src, get_rsa_library_src,
};

use rsa::hash_to_prime::pocklington::{PocklingtonCertParams, PocklingtonHash};
use timed_commitments::{basic_tc, lazy_tc};

use range_proofs::bulletproofs::PedersenComm;

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
  const HASH_TO_PRIME_ENTROPY: usize = 128;
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TestPocklingtonParams;
impl PocklingtonCertParams for TestPocklingtonParams {
  const NONCE_SIZE: usize = 16;
  const MAX_STEPS: usize = 5;
  const INCLUDE_SOLIDITY_WITNESSES: bool = true;
}

pub type TC = lazy_tc::LazyTC<
  G,
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
  let ped_pp = PedersenComm::<G>::gen_pedersen_params(&mut rng);

  // create sample bid and FKPS commitment
  // 1. Get bid
  let bid = BigInt::from(10000);

  let bid_bytes = [bid.to_bytes_be().1].concat();

  let bid_f =
    nat_to_f::<<G as ProjectiveCurve>::ScalarField>(&BigInt::from_bytes_le(Sign::Plus, &bid_bytes))
      .unwrap();

  // CONNECT with LazyTC library
  let (tc_fkps_pp, tc_fkps_pp_proof) = TC::gen_time_params(40).unwrap();
  assert!(TC::ver_time_params(&tc_fkps_pp, &tc_fkps_pp_proof).unwrap());
  let mut ad = [0u8; 32];

  // !!! Arasu: Looks like pederden needs the values to be send as _le
  let (tc_comm, tc_opening) = TC::commit(&mut rng, &tc_fkps_pp, &ped_pp, &bid_bytes, &ad).unwrap();

  let open_alpha = match &tc_opening.tc_opening {
    basic_tc::Opening::SELF(r) => r.to_bytes_be().1,
    basic_tc::Opening::FORCE(y, _) => y.n.to_bytes_be().1,
  };

  let mut m_computed = tc_opening.tc_m.unwrap().to_vec();

  let tc_m = m_computed.clone();

  let f_bytes = <<G as ProjectiveCurve>::ScalarField as PrimeField>::BigInt::NUM_LIMBS * 8;
  //let f_bytes = 32;
  let ped_opening = nat_to_f(&BigInt::from_bytes_le(
    Sign::Plus,
    &m_computed.split_off(m_computed.len() - f_bytes),
  ))
  .unwrap();

  println!("Compiling contract...");

  // Compile contract from template
  let bn254_src = get_bn254_library_src();
  let bigint_src = get_bigint_library_src();
  let pedersen_lib_src = get_pedersen_library_src(&ped_pp);
  let rsa_src = get_rsa_library_src(TestRsaParams::M.deref(), MOD_BITS);
  // let fkps_src = get_fkps_library_src(&h_bigint, &z_bigint, MOD_BITS);
  let fkps_src = get_fkps_library_src(&tc_fkps_pp.x.n, &tc_fkps_pp.y.n, MOD_BITS);
  let tc_lib_src = get_filename_src("TC.sol");
  let tc_test_src = get_filename_src("TCTest.sol");

  let solc_config = r#"
            {
                "language": "Solidity",
                "sources": {
                    "input.sol": { "content": "<%src%>" },
                    "BN254.sol": { "content": "<%bn254_src%>" },
                    "Pedersen.sol": { "content": "<%pedersen_lib_src%>" },
                    "BigInt.sol": { "content": "<%bigint_src%>" },
                    "RSA2048.sol": { "content": "<%rsa_lib_src%>" },
                    "FKPS.sol": { "content": "<%fkps_lib_src%>" },
                    "TC.sol": { "content": "<%tc_lib_src%>" }
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
    .replace("<%fkps_lib_src%>", &fkps_src)
    .replace("<%tc_lib_src%>", &tc_lib_src)
    .replace("<%src%>", &tc_test_src);

  let contract = Contract::compile_from_config(&solc_config, "TCTest").unwrap();

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

  // Call verify function on contract
  let input = vec![
    encode_rsa_element(&tc_comm.tc_comm.x),
    encode_bytes(&tc_comm.tc_comm.ct),
    encode_group_element::<Bn254>(&tc_comm.ped_comm),
    encode_bytes(&tc_m),
    encode_int_from_bytes(&open_alpha),
    //encode_int_from_bytes(&bid_bytes),
    encode_field_element::<Bn254>(&bid_f),
    encode_field_element::<Bn254>(&ped_opening),
  ];

  let result = evm
    .call(
      contract
        .encode_call_contract_bytes("testVerOpen", &input)
        .unwrap(),
      &contract_addr,
      &deployer,
    )
    .unwrap();

  assert_eq!(&result.out, &to_be_bytes(&U256::from(1)));
  println!("TC verification succeeded");
  println!("TC verification cost {:?} gas", result.gas);

  // IGNORE MESS BELOW

  // println!(
  //   "ped comm x from solidity {:?}",
  //   &result.out.encode_hex::<String>()
  // );
  // println!("ped opening: {:?}", &ped_opening.to_string());
  // println!("ped opening from rust: {:?}", &ped_opening.to_string());
  // println!(
  //   "pad from rust {:?}",
  //   &tc_comm.tc_comm.ct.encode_hex::<String>()
  // );

  // println!("tc_m from rust {:?}", &tc_m.encode_hex::<String>());
}
