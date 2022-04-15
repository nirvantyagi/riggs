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
  lazy_tc::{LazyTC},
};
use solidity::{
  encode_tc_comm, encode_tc_opening, encode_tc_pp, get_bigint_library_src,
  get_bn254_library_src, get_filename_src, get_fkps_src, get_pedersen_library_src,
  get_rsa_library_src,
};
use solidity_test_utils::{
  address::Address, contract::Contract, evm::Evm,
  to_be_bytes,
};


use range_proofs::bulletproofs::PedersenComm;

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
  let mut args: Vec<String> = std::env::args().collect();
  if args.last().unwrap() == "--bench" {
    args.pop();
  }
  let mut tamper_force_open: BTreeSet<String> = if args.len() > 1
      && (args[1] == "-h" || args[1] == "--help")
  {
    println!("Usage: ``cargo bench --bench tc --  [--tamper <none | bad_x | bad_ct | bad_ped_comm> ]``");
    return;
  } else {
    let mut args = args.into_iter().skip(1);
    let mut next_arg = args.next();
    let mut tamper_force_open = BTreeSet::new();
    while let Some(arg) = next_arg.clone() {
      match arg.as_str() {
        "--tamper" => {
          next_arg = args.next();
          'subargs: while let Some(subarg) = next_arg.clone() {
            if ["none", "bad_x", "bad_ct", "bad_ped_comm"].contains(&subarg.as_str()) {
              tamper_force_open.insert(subarg);
            } else {
              break 'subargs;
            }
            next_arg = args.next();
          }
        }
        _ => {
          println!("Invalid argument: {}; Run with -h for usage", arg);
          return;
        }
      }
    }
    tamper_force_open
  };
  if tamper_force_open.is_empty() {
    tamper_force_open = BTreeSet::from(["none".to_string(), "bad_x".to_string(), "bad_ct".to_string(), "bad_ped_comm".to_string()]);
  }
  println!("Benchmarking TC with tamper options: {:?}", tamper_force_open);

  // Begin benchmark
  let mut rng = StdRng::seed_from_u64(1u64);

  // Generate time parameters
  let (time_pp, time_pp_proof) = TC::gen_time_params(TIME_PARAM).unwrap();
  let ped_pp = PedersenComm::<G>::gen_pedersen_params(&mut rng);
  assert!(TC::ver_time_params(&time_pp, &time_pp_proof).unwrap());

  // Create commitment, opening
  let m = {
    let mut m = [0u8; 8];
    rng.fill(&mut m);
    m
  };
  let (tc_comm, tc_opening) = TC::commit(&mut rng, &time_pp, &ped_pp, &m).unwrap();

  println!("Compiling contract...");

  // Compile contract from template
  let bn254_src = get_bn254_library_src();
  let bigint_src = get_bigint_library_src();
  let pedersen_lib_src = get_pedersen_library_src(&ped_pp, false);
  let rsa_src = get_rsa_library_src(TestRsaParams::M.deref(), MOD_BITS, false);
  let poe_src = get_filename_src("PoEVerifier.sol", false);
  let fkps_src = get_fkps_src(&time_pp.x.n, &time_pp.y.n, MOD_BITS, TIME_PARAM, false);
  let tc_src = get_filename_src("TC.sol", true);

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

  // Benchmark self open
  println!("Benchmark self-open...");
  let input = vec![
    encode_tc_comm::<Bn254, _>(&tc_comm),
    encode_tc_opening(&tc_opening),
    Token::Uint(U256::from_little_endian(&m)),
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
  println!("TC self-open verification gas cost: {:?}", result.gas);

  // Benchmark force open
  for tamper_method in tamper_force_open.into_iter() {
    println!("Benchmark force-open with tamper: {} ...", tamper_method);
    let (tc_comm, m, tc_force_opening) = match tamper_method.as_str() {
      "bad_x" => {
        let mut tc_input_group_element_bad = tc_comm.clone();
        tc_input_group_element_bad.tc_comm.x = RsaHiddenOrderGroup::from_nat(BigInt::from(3));
        let (force_m_bad, force_opening_bad) =
          TC::force_open(&time_pp, &ped_pp, &tc_input_group_element_bad).unwrap();
        assert!(force_opening_bad.tc_m.is_none());
        assert!(force_m_bad.is_none());
        assert!(TC::ver_open(
          &time_pp,
          &ped_pp,
          &tc_input_group_element_bad,
          &force_m_bad,
          &force_opening_bad
        )
        .unwrap());
        (tc_input_group_element_bad, force_m_bad, force_opening_bad)
      }
      "bad_ct" => {
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
        (tc_ae_ct_bad, force_m_bad, force_opening_bad)
      }
      "bad_ped_comm" => {
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
        (ped_comm_bad, force_m_bad, force_opening_bad)
      }
      _ => {
        let (m, opening) = TC::force_open(&time_pp, &ped_pp, &tc_comm).unwrap();
        (tc_comm.clone(), m, opening)
      },
    };
    let force_input = vec![
      encode_tc_comm::<Bn254, _>(&tc_comm),
      encode_tc_opening(&tc_force_opening),
      Token::Uint(m.map(|m| U256::from_little_endian(&m)).unwrap_or(U256::from(0))),
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

    println!("{:?}", force_result);
    assert_eq!(&force_result.out, &to_be_bytes(&U256::from(1)));
    println!("TC force-open (with tamper {}) verification gas cost: {:?}", tamper_method, force_result.gas);
  }
}
