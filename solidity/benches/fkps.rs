use ark_bn254::{Bn254, G1Projective as G};
use ark_ec::ProjectiveCurve;
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

use range_proofs::bulletproofs::PedersenComm;
use solidity::{
  encode_fkps_comm, encode_fkps_opening, encode_fkps_pp, encode_poe_proof, encode_rsa_element,
  get_bigint_library_src, get_bn254_library_src, get_filename_src, get_fkps_src,
  get_pedersen_library_src, get_rsa_library_src,
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
  const HASH_TO_PRIME_ENTROPY: usize = 128; // TODO: This should be 256
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

  // create sample bid and FKPS commitment
  // 1. Sample bid
  let bid = BigInt::from(10000);
  let bid_bytes = [bid.to_bytes_be().1].concat();

  // Generate parameter
  let (fkps_pp, fkps_pp_proof) = TC::gen_time_params(40).unwrap();
  assert!(TC::ver_time_params(&fkps_pp, &fkps_pp_proof).unwrap());

  // Create commitment, opening
  let mut ad = [0u8; 32];
  let (fkps_comm, fkps_opening) = TC::commit(&mut rng, &fkps_pp, &bid_bytes, &ad).unwrap();

  println!("Compiling contract...");

  // Compile contract from template
  let bigint_src = get_bigint_library_src();
  let rsa_src = get_rsa_library_src(TestRsaParams::M.deref(), MOD_BITS, false);
  let poe_src = get_filename_src("PoElib.sol");
  let fkps_src = get_fkps_src(&fkps_pp.x.n, &fkps_pp.y.n, MOD_BITS, true);
  //let fkps_test_src = get_filename_src("FKPSTest.sol");

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
    //.replace("<%fkps_lib_src%>", &fkps_src)
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
    encode_fkps_comm(&fkps_comm),
    encode_fkps_opening(&fkps_opening, &Some(bid_bytes)),
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
  println!("FKPS verification succeeded");
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

// IGNORE MESS BELOW

// println!("pad from solidity {:?}", &result.out.encode_hex::<String>());
//   &pad_256(&z_hat.n.to_bytes_be().1).encode_hex::<String>()
// println!(
//   "h_hat: {:?}",
//   &fkps_comm.x.n.to_bytes_be().1.encode_hex::<String>()
// );

// println!(
//   "pad from rust is: {:?}",
//   &fkps_comm.ct.encode_hex::<String>()
// );

// let mut zhasher = Keccak256::new();
// let zero: &[u8] = &[0];
// let z_hat_string_solidity = "0681af53be16307765407990ae6548f667f2f51ef63b17e7a674f6811fab13bd5cd3dac0d0ab68696d5a02ad0fafaf9453e0fd50691117ae580b056fb55a43616a57e35f8edd72973e03e413f561430b8abaa6db834fc81bfc34a087e878c654309c9da5723adb36b9732eb32f4c5107567b62d3ab21427fc1959e8169ab3a793ab19302b283404c2f36979ff6a8508bc98875440ed3f38b085c0c4d1dfd7344244fd16ff475c7bc03bc7e2775432477c80be9624428243243ab7cc55a4888f16afd34bb938d4db1a906d8a6581d5ddb1b72b12b95fea9fe430a3a7afd90f20cd55b541476391e626087be04b7267af2ffcc029474ffd7d41d7aa27285a87c57";
// // zhasher.update(&fkps_comm.x.n.to_bytes_be().1.encode_hex::<String>());
// zhasher.update(decode_hex(z_hat_string_solidity).unwrap());
// let zhash = zhasher.finalize();
// println!("key should be: {:?}", &zhash.encode_hex::<String>());
// println!("key is: {:?}", &fkps_comm.ct.encode_hex::<String>());

// println!(
//   "try digest directly: {:?}",
//   &Keccak256::digest(&zero).encode_hex::<String>()
// );
// // use the following beloe for extra decoding functionality
// // use std::{fmt::Write, num::ParseIntError};
// // pub fn decode_hex(s: &str) -> Result<Vec<u8>, ParseIntError> {
// //   (0..s.len())
// //     .step_by(2)
// //     .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
// //     .collect()
// // }

// // 2. Compute h^alpha, z^alpha
// let h_hat = h.power(&alpha);
// let z_hat = z.power(&alpha);

// // 3. Compute k = Hash(z_hat, pp)
// // TODO: add pp to the hash
// let mut hasher = Keccak256::new();
// let z_hat_bytes = pad_256(&z_hat.n.to_bytes_be().1);
// hasher.update(&z_hat_bytes);
// let key = hasher.finalize();

// // 4. Compute ciphertext
// // The cipher used here is hash-to-cipher
// let mut pad_hasher = Keccak256::new();
// let zeros = &[
//   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
// ];
// let concat: Vec<u8> = [key.to_vec(), zeros.to_vec()].concat();
// pad_hasher.update(&concat);
// let pad = pad_hasher.finalize();

// let bid_256 = pad_32(&bid.to_bytes_be().1);

// let ct: Vec<u8> = bid_256
//   .iter()
//   .zip(pad.iter())
//   .map(|(&x1, &x2)| x1 ^ x2)
//   .collect();
