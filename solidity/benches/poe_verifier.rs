use ethabi::Token;
use num_bigint::{RandomBits, Sign};
use once_cell::sync::Lazy;
use primitive_types::U256;
use rand::{distributions::Distribution, rngs::StdRng, SeedableRng};
use sha3::Keccak256;

use std::{convert::TryInto, ops::Deref, str::FromStr};

use solidity_test_utils::{address::Address, contract::Contract, evm::Evm, to_be_bytes};

use rsa::{
    bigint::BigInt,
    hash_to_prime::pocklington::{PocklingtonCertParams, PocklingtonHash},
    hog::{RsaGroupParams, RsaHiddenOrderGroup},
    poe::{PoE, PoEParams},
};

use solidity::{
    encode_poe_proof, encode_rsa_element, get_bigint_library_src, get_filename_src,
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

pub type Hog = RsaHiddenOrderGroup<TestRsaParams>;
pub type TestWesolowski =
    PoE<TestPoEParams, TestRsaParams, PocklingtonHash<TestPocklingtonParams, Keccak256>>;

const MOD_BITS: usize = 2048;
const T: u64 = 160;

fn main() {
    // cargo bench --bench poe_verifier --profile test
    let mut rng = StdRng::seed_from_u64(2u64);
    let x = Hog::from_nat(BigInt::from_biguint(
        Sign::Plus,
        RandomBits::new(2048).sample(&mut rng),
    ));
    let y = x.power(&BigInt::from(2).pow(T.try_into().unwrap()));

    println!("Proving PoE...");
    let proof = TestWesolowski::prove(&x, &y, T.into()).unwrap();
    println!("Verifying PoE...");
    let is_valid = TestWesolowski::verify(&x, &y, T, &proof).unwrap();
    assert!(is_valid);

    println!("Compiling contract...");

    // Compile contract from template
    let bigint_src = get_bigint_library_src();
    let rsa_src = get_rsa_library_src(TestRsaParams::M.deref(), MOD_BITS, false);
    let poe_src = get_filename_src("PoEVerifier.sol", true);

    let solc_config = r#"
            {
                "language": "Solidity",
                "sources": {
                    "input.sol": { "content": "<%src%>" },
                    "BigInt.sol": { "content": "<%bigint_src%>" },
                    "RSA2048.sol": { "content": "<%rsa_src%>" }
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
    .replace("<%rsa_src%>", &rsa_src)
    .replace("<%src%>", &poe_src);

    let contract = Contract::compile_from_config(&solc_config, "PoEVerifier").unwrap();

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
        encode_rsa_element(&x),
        encode_rsa_element(&y),
        Token::Uint(U256::from(T)),
        encode_poe_proof(&proof),
    ];
    let result = evm
        .call(
            contract
                .encode_call_contract_bytes("verify", &input)
                .unwrap(),
            &contract_addr,
            &deployer,
        )
        .unwrap();
    assert_eq!(&result.out, &to_be_bytes(&U256::from(1)));
    println!("{:?}", result);
}
