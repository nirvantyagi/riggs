use ark_ec::{PairingEngine, ProjectiveCurve, AffineCurve};
use ark_ff::ToBytes;

use ethabi::Token;
use primitive_types::U256;

use std::{
    error::Error as ErrorTrait,
    fmt::{self, Debug},
};

pub mod address;
pub mod contract;
pub mod evm;

pub type Error = Box<dyn ErrorTrait>;

#[derive(Debug)]
pub struct EvmTestError(String);

impl ErrorTrait for EvmTestError {
    fn source(self: &Self) -> Option<&(dyn ErrorTrait + 'static)> {
        None
    }
}

impl fmt::Display for EvmTestError {
    fn fmt(self: &Self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}


/// Helper methods for parsing group structure
/// https://github.com/Zokrates/ZoKrates/blob/develop/zokrates_core/src/proof_system/ark/mod.rs#L166
pub fn parse_g1<E: PairingEngine>(g1: &E::G1Affine) -> (Vec<u8>, Vec<u8>) {
    let mut bytes: Vec<u8> = Vec::new();
    g1.write(&mut bytes).unwrap();
    let element_length = (bytes.len() - 1) / 2; // [x, y, infinity] - infinity
    let mut x = bytes[0..element_length].to_vec();
    let mut y = bytes[element_length..2 * element_length].to_vec();
    x.reverse();
    y.reverse();
    (x, y)
}

pub fn parse_g1_to_solidity_string<E: PairingEngine>(g1: &E::G1Affine) -> String {
    let (x, y) = parse_g1::<E>(g1);
    format!("0x{}, 0x{}", hex::encode(&x), hex::encode(&y))
}

pub fn parse_g2<E:PairingEngine>(e: &E::G2Affine,) ->  (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
    let mut bytes: Vec<u8> = Vec::new();
    e.write(&mut bytes).unwrap();
    let length = bytes.len() - 1; // [x, y, infinity] - infinity
    println!("g2 length: {}", length);
    let element_length = length / 4;
    let mut elements = vec![];
    for i in 0..4 {
        let start = i * element_length;
        let end = start + element_length;
        let mut e = bytes[start..end].to_vec();
        e.reverse();
        elements.push(e);
    }
    (elements.get(1).unwrap().to_vec(),
     elements.get(0).unwrap().to_vec(),
     elements.get(3).unwrap().to_vec(),
     elements.get(2).unwrap().to_vec())
}

pub fn parse_g2_to_solidity_string<E: PairingEngine>(g2: &E::G2Affine) -> String {
    let (x1, x2, y1,  y2) = parse_g2::<E>(&g2);
    format!("[0x{}, 0x{}], [0x{}, 0x{}]", hex::encode(&x1), hex::encode(&x2), hex::encode(&y1), hex::encode(&y2))
}

pub fn parse_g1_pc<G: ProjectiveCurve>(g1: &G) -> (Vec<u8>, Vec<u8>) {
    let mut bytes: Vec<u8> = Vec::new();
    g1.write(&mut bytes).unwrap();
    let element_length = (bytes.len() - 1) / 2; // [x, y, infinity] - infinity
    let mut x = bytes[0..element_length].to_vec();
    let mut y = bytes[element_length..2 * element_length].to_vec();
    x.reverse();
    y.reverse();
    // (x, y)
    (x[x.len()-32..].to_vec(), y[y.len()-32..].to_vec())
}

pub fn parse_g1_to_solidity_string_pc<G: ProjectiveCurve>(g1: &G) -> String {
    let (x, y) = parse_g1_pc::<G>(g1);
    let hex_x = hex::encode(&x);
    let hex_y = hex::encode(&y);
    format!("0x{}, 0x{}", &hex_x[hex_x.len()-64..], &hex_y[hex_y.len()-64..])
}

pub fn parse_field<E: PairingEngine>(f: &E::Fr) -> Vec<u8> {
    let mut bytes: Vec<u8> = Vec::new();
    f.write(&mut bytes).unwrap();
    bytes.reverse();
    bytes
}

pub fn parse_field_pc<G: ProjectiveCurve>(f: &G::ScalarField) -> Vec<u8> {
    let mut bytes: Vec<u8> = Vec::new();
    f.write(&mut bytes).unwrap();
    bytes.reverse();
    bytes
}

pub fn encode_int_from_bytes(b: &[u8]) -> Token {
    Token::Uint(U256::from_big_endian(&b.to_vec()))
}

pub fn encode_bytes32(b: &[u8]) -> Token {
    Token::FixedBytes(b.to_vec())
}

pub fn encode_bytes(b: &[u8]) -> Token {
    Token::Bytes(b.to_vec())
}

pub fn encode_group_element<E: PairingEngine>(g: &E::G1Projective) -> Token {
    let (x, y) = parse_g1::<E>(&g.into_affine());
    Token::Tuple(vec![
        Token::Uint(U256::from_big_endian(&x)),
        Token::Uint(U256::from_big_endian(&y)),
    ])
}

pub fn encode_g2_element<E: PairingEngine>(g: &E::G2Affine) -> Token {
    let (x1, x2, y1, y2) = parse_g2::<E>(&g);
    let mut tokens = Vec::new();
    tokens.push(Token::FixedArray(vec![
        Token::Uint(U256::from_big_endian(&x1)),
        Token::Uint(U256::from_big_endian(&x2)),
    ]));
    tokens.push(Token::FixedArray(vec![
        Token::Uint(U256::from_big_endian(&y1)),
        Token::Uint(U256::from_big_endian(&y2)),
    ]));
    Token::Tuple(tokens)
}

pub fn encode_field_element<E: PairingEngine>(f: &E::Fr) -> Token {
    Token::Uint(U256::from_big_endian(&parse_field::<E>(f)))
}

pub fn encode_group_element_pc<G: ProjectiveCurve>(g: &G) -> Token {
    let (x, y) = parse_g1_pc::<G>(&g);
    Token::Tuple(vec![
        Token::Uint(U256::from_big_endian(&x)),
        Token::Uint(U256::from_big_endian(&y)),
    ])
}

pub fn encode_field_element_pc<G: ProjectiveCurve>(f: &G::ScalarField) -> Token {
    Token::Uint(U256::from_big_endian(&parse_field_pc::<G>(f)))
}

pub fn to_be_bytes(n: &U256) -> [u8; 32] {
    let mut input_bytes: [u8; 32] = [0; 32];
    n.to_big_endian(&mut input_bytes);
    input_bytes
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::{address::Address, contract::Contract, evm::Evm};
    use ethabi::Token;
    use rand::{rngs::StdRng, SeedableRng};

    #[test]
    fn simple_storage_contract_test() {
        let mut rng = StdRng::seed_from_u64(0u64);

        // Compile contract
        let contract_path = format!(
            "{}/contracts/simple_storage.sol",
            env!("CARGO_MANIFEST_DIR")
        );
        let contract =
            Contract::compile_from_solidity_file(contract_path, "SimpleStorage", false).unwrap();

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

        // Call get function on contract
        let get_result = evm
            .call(
                contract.encode_call_contract_bytes("get", &[]).unwrap(),
                &contract_addr,
                &deployer,
            )
            .unwrap();
        assert_eq!(&get_result.out, &to_be_bytes(&U256::from(0)));
        println!("{:?}", get_result);

        // Call set function on contract
        let set_result = evm
            .call(
                contract
                    .encode_call_contract_bytes(
                        "set",
                        &[Token::Tuple(vec![Token::Uint(U256::from(40))])],
                    )
                    .unwrap(),
                &contract_addr,
                &deployer,
            )
            .unwrap();
        println!("{:?}", set_result);

        // Call get function on contract
        let get_result = evm
            .call(
                contract.encode_call_contract_bytes("get", &[]).unwrap(),
                &contract_addr,
                &deployer,
            )
            .unwrap();
        assert_eq!(&get_result.out, &to_be_bytes(&U256::from(40)));
        println!("{:?}", get_result);
    }
}
