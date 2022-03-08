use ark_bn254::{Bn254, G1Projective as G};

use std::{ops::Deref, str::FromStr};

use primitive_types::U256;
use rand::{rngs::StdRng, SeedableRng};

use solidity_test_utils::{
    address::Address, contract::Contract, encode_bytes, encode_field_element, encode_group_element,
    encode_int_from_bytes, evm::Evm, to_be_bytes,
};

use sha3;
use sha3::{Digest, Keccak256};

use rsa::bigint::BigInt;

use rsa::hog::{RsaGroupParams, RsaHiddenOrderGroup};

use range_proofs::bulletproofs::{Bulletproofs, PedersenComm};
use solidity::{encode_bulletproof, get_bn254_library_src, get_filename_src};

use once_cell::sync::Lazy;

const NUM_BITS: u64 = 64;
const LOG_NUM_BITS: u64 = 6;

#[derive(Clone, PartialEq, Eq, Debug)]

pub struct TestRsaParams;

impl RsaGroupParams for TestRsaParams {
    const G: Lazy<BigInt> = Lazy::new(|| BigInt::from(2));
    const M: Lazy<BigInt> = Lazy::new(|| {
        BigInt::from_str("25195908475657893494027183240048398571429282126204032027777137836043662020707595556264018525880784406918290641249515082189298559149176184502808489120072844992687392807287776735971418347270261896375014971824691165077613379859095700097330459748808428401797429100642458691817195118746121515172654632282216869987549182422433637259085141865462043576798423387184774447920739934236584823824281198163815010674810451660377306056201619676256133844143603833904414952634432190114657544454178424020924616515723350778707749817125772467962926386356373289912154831438167899885040445364023527381951378636564391212010397122822120720357").unwrap()
    });
}

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
    let mut rng = StdRng::seed_from_u64(0u64);
    let ped_pp = PedersenComm::<G>::gen_pedersen_params(&mut rng);
    // let pp = Bulletproofs::<G, sha3::Keccak256>::gen_params(&mut rng, NUM_BITS);

    let v = BigInt::from(10000);
    let (comm, v_f, opening) =
        PedersenComm::<G>::commit2(&mut rng, &ped_pp, &v.to_bytes_le().1).unwrap();

    assert!(PedersenComm::<G>::ver_open(&ped_pp, &comm, &v.to_bytes_le().1, &opening).unwrap());

    // Compile contract from template
    let bignum_lib_src = get_filename_src("BigNumber.sol");

    let rsa_lib_src = get_filename_src("RSA.sol");
    let fkps_lib_src = get_filename_src("FKPS.sol");

    let fkps_test_lib_src = get_filename_src("FKPSTest.sol");

    let solc_config = r#"
            {
                "language": "Solidity",
                "sources": {
                    "input.sol": { "content": "<%src%>" },
                    "BigNumber.sol": { "content": "<%bignum_lib_src%>" },
                    "RSA.sol": { "content": "<%rsa_lib_src%>" },
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
    .replace("<%bignum_lib_src%>", &bignum_lib_src)
    .replace("<%rsa_lib_src%>", &rsa_lib_src)
    .replace("<%fkps_lib_src%>", &fkps_lib_src)
    .replace("<%src%>", &fkps_test_lib_src);

    let contract = Contract::compile_from_config(&solc_config, "FKPSTest").unwrap();

    pub type Hog = RsaHiddenOrderGroup<TestRsaParams>;
    let g = Hog::from_nat(
        BigInt::from_str(
            "45746267326477510121777008810664706780700497316550259121257880520529714488628",
        )
        .unwrap(),
    );
    let h = Hog::from_nat(
        BigInt::from_str(
            "45746267326477510121777008810664706780700497316550259121257880520529714488627",
        )
        .unwrap(),
    );
    let z = Hog::from_nat(
        BigInt::from_str(
            "45746267326477510121777008810664706780700497316550259121257880520529714488626",
        )
        .unwrap(),
    );
    let modulus = TestRsaParams::M.deref().clone();

    let bid = BigInt::from(10000);

    let alpha = BigInt::from(10000);

    let h_hat = h.power(&alpha);
    let z_hat = z.power(&alpha);

    let z_hat_bytes = z_hat.n.to_bytes_be().1;

    let mut hasher = Keccak256::new();
    hasher.update(&z_hat_bytes);
    let key = hasher.finalize();

    let mut pad_hasher = Keccak256::new();
    let zeros = &[
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
    ];
    let mut concat: Vec<u8> = [key.to_vec(), zeros.to_vec()].concat();

    pad_hasher.update(&concat);

    let pad = pad_hasher.finalize();

    let bid_256 = pad_32(&bid.to_bytes_be().1);

    let ct: Vec<u8> = bid_256
        .iter()
        .zip(pad.iter())
        .map(|(&x1, &x2)| x1 ^ x2)
        .collect();

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

    // println!("{:x?}", &modulus.n.to_bytes_be().1);
    // println!("{:x?}", &g.n.to_bytes_be().1);
    // println!("{:x?}", &h.n.to_bytes_be().1);
    // println!("{:x?}", &z.n.to_bytes_be().1);
    // println!("{:x?}", &h_hat.n.to_bytes_be().1);

    // println!("{:x?}", &ct);

    // println!("{:x?}", &alpha.to_bytes_be().1);

    // println!("{:x?}", &bid.to_bytes_be().1);

    // Call verify function on contract
    let input = vec![
        encode_bytes(&modulus.to_bytes_be().1),
        encode_bytes(&g.n.to_bytes_be().1),
        encode_bytes(&h.n.to_bytes_be().1),
        encode_bytes(&z.n.to_bytes_be().1),
        encode_bytes(&h_hat.n.to_bytes_be().1),
        encode_bytes(&ct),
        encode_int_from_bytes(&alpha.to_bytes_be().1),
        encode_int_from_bytes(&bid.to_bytes_be().1),
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
    // println!("{:?}", &result);
    println!("FKPS verification costs {:?} gas", result.gas);

    // //assert_eq!(&result.out, &to_be_bytes(&U256::from(1)));
    // let res_len = result.out.len();
    // let padded_res = pad_256(&result.out);

    // // assert_eq!(&padded_res, &padded_y);
    // assert_eq!(&padded_res, &pad_256(&[1]));

    // // println!("{:?}", &padded_res);
}
