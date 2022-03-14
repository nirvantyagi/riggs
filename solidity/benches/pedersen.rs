use ark_bn254::{Bn254, G1Projective as G};

use primitive_types::U256;
use rand::{rngs::StdRng, SeedableRng};

use solidity_test_utils::{
    address::Address, contract::Contract, encode_field_element, encode_group_element, evm::Evm,
    to_be_bytes,
};

use range_proofs::bulletproofs::PedersenComm;
use rsa::bigint::BigInt;
use solidity::{get_bn254_library_src, get_filename_src, get_pedersen_library_src};

fn main() {
    let mut rng = StdRng::seed_from_u64(0u64);
    let ped_pp = PedersenComm::<G>::gen_pedersen_params(&mut rng);

    let v = BigInt::from(10000);
    let (comm, v_f, opening) =
        PedersenComm::<G>::commit2(&mut rng, &ped_pp, &v.to_bytes_le().1).unwrap();

    assert!(PedersenComm::<G>::ver_open(&ped_pp, &comm, &v.to_bytes_le().1, &opening).unwrap());

    // Compile contract from template
    let bn254_src = get_bn254_library_src();

    // let pedersen_lib_src = get_filename_src("Pedersen.sol");
    // let pedersen_test_src = get_pedersen_test_src(&ped_pp);

    let pedersen_lib_src = get_pedersen_library_src(&ped_pp);
    let pedersen_test_src = get_filename_src("PedersenTest.sol");

    let solc_config = r#"
            {
                "language": "Solidity",
                "sources": {
                    "input.sol": { "content": "<%src%>" },
                    "BN254.sol": { "content": "<%bn254_src%>" },
                    "Pedersen.sol": { "content": "<%pedersen_lib_src%>" }
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
    .replace("<%opt%>", &true.to_string())
    .replace("<%bn254_src%>", &bn254_src)
    .replace("<%pedersen_lib_src%>", &pedersen_lib_src)
    .replace("<%src%>", &pedersen_test_src);

    let contract = Contract::compile_from_config(&solc_config, "PedersenTest").unwrap();

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
        encode_group_element::<Bn254>(&comm),
        encode_field_element::<Bn254>(&v_f),
        encode_field_element::<Bn254>(&opening),
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
    println!("Pedersen verification cost {:?} gas", result.gas);
}
