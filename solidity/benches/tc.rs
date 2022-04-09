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
  address::Address, contract::Contract, encode_bytes, encode_bytes_option, encode_field_element,
  encode_group_element, encode_int_from_bytes, evm::Evm, to_be_bytes,
};

use rsa::{
  bigint::{nat_to_f, BigInt},
  hash_to_prime::HashToPrime,
  hog::{RsaGroupParams, RsaHiddenOrderGroup},
  poe::{PoE, PoEParams, Proof as PoEProof},
};

use solidity::{
  encode_rsa_element, encode_tc_comm, encode_tc_opening, encode_tc_pp, get_bigint_library_src,
  get_bn254_library_src, get_filename_src, get_fkps_src, get_pedersen_library_src,
  get_rsa_library_src,
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
const TIME_PARAM: u32 = 40;

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

  // create sample bid and FKPS commitment
  // 1. Get bid
  let bid = BigInt::from(10000);
  let bid_bytes = [bid.to_bytes_be().1].concat();
  let bid_f =
    nat_to_f::<<G as ProjectiveCurve>::ScalarField>(&BigInt::from_bytes_le(Sign::Plus, &bid_bytes))
      .unwrap();

  // Generate Parameters
  let (time_pp, time_pp_proof) = TC::gen_time_params(TIME_PARAM).unwrap();
  let ped_pp = PedersenComm::<G>::gen_pedersen_params(&mut rng);
  assert!(TC::ver_time_params(&time_pp, &time_pp_proof).unwrap());

  // Create commitment, opening
  let (mut tc_comm, tc_opening) = TC::commit(&mut rng, &time_pp, &ped_pp, &bid_bytes).unwrap();

  println!("Compiling contract...");

  // Compile contract from template
  let bn254_src = get_bn254_library_src();
  let bigint_src = get_bigint_library_src();
  let pedersen_lib_src = get_pedersen_library_src(&ped_pp, false);
  let rsa_src = get_rsa_library_src(TestRsaParams::M.deref(), MOD_BITS, false);
  let poe_src = get_filename_src("PoEVerifier.sol", false);
  let fkps_src = get_fkps_src(&time_pp.x.n, &time_pp.y.n, MOD_BITS, TIME_PARAM, false);
  let tc_src = get_filename_src("TC.sol", true);
  // let tc_test_src = get_filename_src("TCTest.sol");

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
                    "FKPS.sol": { "content": "<%fkps_lib_src%>" }
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
    .replace("<%src%>", &tc_src);

  let contract = Contract::compile_from_config(&solc_config, "TC").unwrap();

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
    encode_tc_comm::<Bn254, _>(&tc_comm),
    encode_tc_opening(&tc_opening),
    encode_field_element::<Bn254>(&bid_f),
    encode_tc_pp::<Bn254, _>(TestRsaParams::M.deref(), &time_pp, &ped_pp),
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
  println!("TC verSelfOpen succeeded");
  println!("   verSelfOpen cost {:?} gas", result.gas);

  // Bench force verification

  let (mut m, mut tc_force_opening) = TC::force_open(&time_pp, &ped_pp, &tc_comm).unwrap();

  let tamper_method = 0; // 0 means no tamper
  for tamper_method in 0..4 {
    match tamper_method {
      // method
      1 => {
        let mut tc_input_group_element_bad = tc_comm.clone();
        tc_input_group_element_bad.tc_comm.x = RsaHiddenOrderGroup::from_nat(BigInt::from(2));
        let (force_m_bad, force_opening_bad) =
          TC::force_open(&time_pp, &ped_pp, &tc_input_group_element_bad).unwrap();
        assert!(force_m_bad.is_none());
        assert!(TC::ver_open(
          &time_pp,
          &ped_pp,
          &tc_input_group_element_bad,
          &force_m_bad,
          &force_opening_bad
        )
        .unwrap());
        tc_comm = tc_input_group_element_bad;
        tc_force_opening = force_opening_bad;
        m = force_m_bad;
      }
      // method
      2 => {
        let mut tc_ae_ct_bad = tc_comm.clone();
        tc_ae_ct_bad.tc_comm.ct[0] += 1u8;
        let (force_m_bad, force_opening_bad) =
          TC::force_open(&time_pp, &ped_pp, &tc_ae_ct_bad).unwrap();
        assert!(force_m_bad.is_none());
        assert!(TC::ver_open(
          &time_pp,
          &ped_pp,
          &tc_ae_ct_bad,
          &force_m_bad,
          &force_opening_bad
        )
        .unwrap());
        tc_comm = tc_ae_ct_bad;
        tc_force_opening = force_opening_bad;
        m = force_m_bad;
      }
      // method
      3 => {
        let mut ped_comm_bad = tc_comm.clone();
        ped_comm_bad.ped_comm = ped_pp.g.clone();
        let (force_m_bad, force_opening_bad) =
          TC::force_open(&time_pp, &ped_pp, &ped_comm_bad).unwrap();
        assert!(force_m_bad.is_none());
        assert!(TC::ver_open(
          &time_pp,
          &ped_pp,
          &ped_comm_bad,
          &force_m_bad,
          &force_opening_bad
        )
        .unwrap());
        tc_comm = ped_comm_bad;
        tc_force_opening = force_opening_bad;
        m = force_m_bad;
      }
      // no tamper
      _ => {}
    }
    let force_input = vec![
      encode_tc_comm::<Bn254, _>(&tc_comm),
      encode_tc_opening(&tc_force_opening),
      encode_bytes_option(&m),
      encode_field_element::<Bn254>(&bid_f),
      encode_tc_pp::<Bn254, _>(TestRsaParams::M.deref(), &time_pp, &ped_pp),
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
    if (tamper_method == 0) {
      println!("TC verForceOpen succeeded (without tampering)");
    } else {
      println!(
        "TC verForceOpen succeeded (with tamper method {})",
        tamper_method
      );
    }
    println!("   verForceOpen costs {:?} gas", force_result.gas);
  }
}
