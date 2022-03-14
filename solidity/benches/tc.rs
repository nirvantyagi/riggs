use ark_bn254::{Bn254, G1Projective as G};

use ethabi::Token;
use num_bigint::{RandomBits, Sign};
use once_cell::sync::Lazy;
use primitive_types::U256;
use rand::{distributions::Distribution, rngs::StdRng, SeedableRng};
use sha3::{Digest, Keccak256};

use std::{ops::Deref, str::FromStr};

use range_proofs::bulletproofs::PedersenComm;

use solidity_test_utils::{
  address::Address, contract::Contract, encode_bytes, encode_field_element, encode_group_element,
  encode_int_from_bytes, evm::Evm, to_be_bytes,
};

use rsa::{
  bigint::BigInt,
  hog::{RsaGroupParams, RsaHiddenOrderGroup},
};

use solidity::{
  encode_rsa_element, get_bigint_library_src, get_bn254_library_src, get_filename_src,
  get_fkps_library_src, get_pedersen_library_src, get_rsa_library_src,
};

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

  let v = BigInt::from(10000);
  let (comm, v_f, opening) =
    PedersenComm::<G>::commit2(&mut rng, &ped_pp, &v.to_bytes_le().1).unwrap();

  assert!(PedersenComm::<G>::ver_open(&ped_pp, &comm, &v.to_bytes_le().1, &opening).unwrap());

  let h_bigint = BigInt::from_str(
    "11195908475657893494027183240048398571429282126204032027777137836043662020707595556264018525880784406918290641249515082189298559149176184502808489120072844992687392807287776735971418347270261896375014971824691165077613379859095700097330459748808428401797429100642458691817195118746121515172654632282216869987549182422433637259085141865462043576798423387184774447920739934236584823824281198163815010674810451660377306056201619676256133844143603833904414952634432190114657544454178424020924616515723350778707749817125772467962926386356373289912154831438167899885040445364023527381951378636564391212010397122822120720357",
  )
  .unwrap();
  let h = Hog::from_nat(h_bigint.clone());

  let z_bigint = BigInt::from_str(
    "1119590847565789349402718324004839857142928212620403202777713783604366202070759555626401852588078440691829064124951508218929855914917618450280848912007284499268739280728777673597141834727026189637501497182469116507761337985909570009733045974880842840179742910064245869181719511874612151517265463228221686998754918242243363725908514186546204357679842338718477444792073993423658482382428119816381501067481045166037730605620161967625613384414360383390441495263443219011465754445417842402092461651572335077870774981712577246796292638635637328991215483143816789988504044536402352738195137863656439121201039712282212072037",
  )
  .unwrap();
  let z = Hog::from_nat(z_bigint.clone());

  println!("Compiling contract...");

  // Compile contract from template
  let bn254_src = get_bn254_library_src();
  let bigint_src = get_bigint_library_src();
  let rsa_src = get_rsa_library_src(TestRsaParams::M.deref(), MOD_BITS);
  let fkps_src = get_fkps_library_src(&h_bigint, &z_bigint, MOD_BITS);
  let pedersen_lib_src = get_pedersen_library_src(&ped_pp);
  let tc_lib_src = get_filename_src("TC.sol");
  let tc_test_src = get_filename_src("TCTest.sol");

  let solc_config = r#"
            {
                "language": "Solidity",
                "sources": {
                    "input.sol": { "content": "<%src%>" },
                    "BigInt.sol": { "content": "<%bigint_src%>" },
                    "BN254.sol": { "content": "<%bn254_src%>" },
                    "RSA2048.sol": { "content": "<%rsa_lib_src%>" },
                    "FKPS.sol": { "content": "<%fkps_lib_src%>" },
                    "Pedersen.sol": { "content": "<%pedersen_lib_src%>" },
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
    .replace("<%bigint_src%>", &bigint_src)
    .replace("<%bn254_src%>", &bn254_src)
    .replace("<%rsa_lib_src%>", &rsa_src)
    .replace("<%fkps_lib_src%>", &fkps_src)
    .replace("<%pedersen_lib_src%>", &pedersen_lib_src)
    .replace("<%tc_lib_src%>", &tc_lib_src)
    .replace("<%src%>", &tc_test_src);

  let contract = Contract::compile_from_config(&solc_config, "TCTest").unwrap();

  // create sample bid and FKPS commitment
  // 1. Sample alpha
  let bid = BigInt::from(10000);
  let alpha = BigInt::from(10000);

  // 2. Compute h^alpha, z^alpha
  let h_hat = h.power(&alpha);
  let z_hat = z.power(&alpha);

  // 3. Compute k = Hash(z_hat, pp)
  // TODO: add pp to the hash
  let mut hasher = Keccak256::new();
  let z_hat_bytes = pad_256(&z_hat.n.to_bytes_be().1);
  hasher.update(&z_hat_bytes);
  let key = hasher.finalize();

  // 4. Compute ciphertext
  // The cipher used here is hash-to-cipher
  let mut pad_hasher = Keccak256::new();
  let zeros = &[
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  ];
  let concat: Vec<u8> = [key.to_vec(), zeros.to_vec()].concat();
  pad_hasher.update(&concat);
  let pad = pad_hasher.finalize();

  let bid_256 = pad_32(&bid.to_bytes_be().1);

  let ct: Vec<u8> = bid_256
    .iter()
    .zip(pad.iter())
    .map(|(&x1, &x2)| x1 ^ x2)
    .collect();

  // Thus, the FKPS commitment is: (h_hat, ct)

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
    encode_rsa_element(&h_hat),
    encode_bytes(&ct),
    encode_group_element::<Bn254>(&comm),
    encode_int_from_bytes(&alpha.to_bytes_be().1),
    encode_int_from_bytes(&bid.to_bytes_be().1),
    encode_field_element::<Bn254>(&opening),
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
  // println!("{:?}", &result.out.encode_hex::<String>());
  assert_eq!(&result.out, &to_be_bytes(&U256::from(1)));
  println!("TC verification costs {:?} gas", result.gas);

  //   &pad_256(&z_hat.n.to_bytes_be().1).encode_hex::<String>()
  // println!("Key: {:?}", &key.encode_hex::<String>());
}
