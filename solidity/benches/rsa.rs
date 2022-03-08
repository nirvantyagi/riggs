use std::{ops::Deref, str::FromStr};

use primitive_types::U256;
use rand::{rngs::StdRng, SeedableRng};

use solidity_test_utils::{
    address::Address, contract::Contract, encode_bytes, encode_int_from_bytes, evm::Evm,
    to_be_bytes,
};

use rsa::bigint::BigInt;

use rsa::hog::{RsaGroupParams, RsaHiddenOrderGroup};

use solidity::get_filename_src;

use once_cell::sync::Lazy;

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

    // Compute y = g^x mod n
    pub type Hog = RsaHiddenOrderGroup<TestRsaParams>;
    let m = TestRsaParams::M.deref().clone();
    let g = Hog::from_nat(BigInt::from_str("231").unwrap());
    let x = BigInt::from(123);
    let y = g.power(&x);

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
        encode_bytes(&pad_256(&g.n.to_bytes_be().1)),
        encode_bytes(&pad_256(&y.n.to_bytes_be().1)),
        encode_bytes(&pad_256(&m.to_bytes_be().1)),
        encode_int_from_bytes(&x.to_bytes_be().1),
    ];

    let result = evm
        .call(
            contract
                .encode_call_contract_bytes("testVerifyPower", &input)
                .unwrap(),
            &contract_addr,
            &deployer,
        )
        .unwrap();

    assert_eq!(&result.out, &to_be_bytes(&U256::from(1)));
    println!("RSA exponentiation costs {:?} gas", result.gas);
    // println!("{:?}", &result);
}
