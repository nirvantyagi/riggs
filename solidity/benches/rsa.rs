use ark_bn254::{Bn254, G1Projective as G};

use std::{ops::Deref, str::FromStr};

use primitive_types::U256;
use rand::{rngs::StdRng, SeedableRng};

use solidity_test_utils::{
    address::Address,
    // <<<<<<< Updated upstream
    contract::Contract,
    encode_bytes,
    // =======
    //     address::Address, contract::Contract, encode_bytes, encode_group_element,
    //     encode_int_from_bytes, evm::Evm, to_be_bytes,
    // >>>>>>> Stashed changes
    encode_field_element,
    encode_group_element,
    encode_int_from_bytes,
    evm::Evm,
    to_be_bytes,
};

use rsa::bigint::BigInt;

use rsa::hog::{RsaGroupParams, RsaHiddenOrderGroup};

use range_proofs::bulletproofs::{Bulletproofs, PedersenComm};
use solidity::{
    // _encode_field_element,
    // =======
    //     _encode_field_element, encode_bulletproof, get_bn254_library_src,
    //     get_bulletproofs_verifier_contract_src, get_filename_src, get_pedersen_library_src,
    // >>>>>>> Stashed changes
    encode_bulletproof,
    // <<<<<<< Updated upstream
    get_bn254_library_src,
    get_filename_src,
};

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

    let rsa_test_lib_src = get_filename_src("RSATest.sol");

    let solc_config = r#"
            {
                "language": "Solidity",
                "sources": {
                    "input.sol": { "content": "<%src%>" },
                    "BigNumber.sol": { "content": "<%bignum_lib_src%>" },
                    "RSA.sol": { "content": "<%rsa_lib_src%>" }
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
    .replace("<%src%>", &rsa_test_lib_src);

    let contract = Contract::compile_from_config(&solc_config, "RSATest").unwrap();

    pub type Hog = RsaHiddenOrderGroup<TestRsaParams>;

    let g = Hog::from_nat(BigInt::from_str("231").unwrap());

    let x = BigInt::from(123);

    let y = g.power(&x);

    let m = TestRsaParams::M.deref().clone();

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
        // <<<<<<< Updated upstream
        //         encode_bytes(&g.n.to_bytes_be().1),
        //         encode_bytes(&y.n.to_bytes_be().1),
        //         encode_bytes(&m.to_bytes_be().1),
        // =======
        encode_bytes(&pad_256(&g.n.to_bytes_be().1)),
        encode_bytes(&pad_256(&y.n.to_bytes_be().1)),
        encode_bytes(&pad_256(&m.to_bytes_be().1)),
        // >>>>>>> Stashed changes
        encode_int_from_bytes(&x.to_bytes_be().1),
    ];

    let padded_y = pad_256(&y.n.to_bytes_be().1);

    let result = evm
        .call(
            contract
                .encode_call_contract_bytes("testVerifyPower", &input)
                .unwrap(),
            &contract_addr,
            &deployer,
        )
        .unwrap();
    //assert_eq!(&result.out, &to_be_bytes(&U256::from(1)));
    let res_len = result.out.len();
    let padded_res = pad_256(&result.out);

    println!("{:?}", &result);
    println!("{:?}", &padded_y);
    // println!("RSA exp check costs {:?} gas", result.gas);

    // assert_eq!(&padded_res, &padded_y);
    // assert_eq!(&padded_res, &pad_256(&[1]));

    // // Call verify function on contract
    // let input = vec![
    //     encode_bytes(&pad_256(&y.n.to_bytes_be().1))
    // ];

    // let padded_y = pad_256(&y.n.to_bytes_be().1);

    // let result = evm.call(contract.encode_call_contract_bytes("returnTrue", &input).unwrap(), &contract_addr, &deployer).unwrap();
    // println!("{:?}", result);
    // //assert_eq!(&result.out, &to_be_bytes(&U256::from(1)));
    // let padded_res = pad_256(&result.out);
    // assert_eq!(&padded_res, &padded_y);
    // // assert_eq!(&padded_res, &pad_256(&[1]));
    // // println!("{:?}", &padded_res);
    // println!("RSA identity costs {:?} gas", result.gas);
}
