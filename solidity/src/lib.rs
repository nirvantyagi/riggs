use ark_ec::{ProjectiveCurve, PairingEngine};
use ark_bn254::{
    Bn254,
    G1Projective as G,
};

use ethabi::Token;
use std::{fs::File, io::Read};
use solidity_test_utils::{
    parse_g1_to_solidity_string,
    encode_group_element,
    encode_field_element,
};
use range_proofs::bulletproofs::{
    Proof, Params, PedersenParams,
    serialize_group_elem,
};
use rsa::{
    poe::hash_to_prime::hash_to_variable_output_length,
};

pub fn get_bn254_library_src() -> String {
    let contract_path = format!(
        "{}/contracts/BN254.sol",
        env!("CARGO_MANIFEST_DIR")
    );

    let mut src_file = File::open(contract_path).unwrap();
    let mut src = String::new();
    src_file.read_to_string(&mut src).unwrap();
    src = src.replace("\"", "\\\"");
    src
}

pub fn get_bulletproofs_verifier_contract_src(pp: &Params<G>, ped_pp: &PedersenParams<G>, n: u64, lg_n: u64) -> String {

    let pp_hash = {
        let mut hash_input = Vec::<u8>::new();
        hash_input.append(&mut serialize_group_elem(&ped_pp.g));
        hash_input.append(&mut serialize_group_elem(&ped_pp.h));
        for g in pp.g.iter() {
            hash_input.append(&mut serialize_group_elem(g));
        }
        for h in pp.h.iter() {
            hash_input.append(&mut serialize_group_elem(h));
        }
        hash_input.append(&mut serialize_group_elem(&pp.u));
        hash_to_variable_output_length::<sha3::Keccak256>(&hash_input, 32)
    };

    let contract_path = format!(
        "{}/contracts/BulletproofsVerifier.sol",
        env!("CARGO_MANIFEST_DIR")
    );

    let mut src_file = File::open(contract_path).unwrap();
    let mut src = String::new();
    src_file.read_to_string(&mut src).unwrap();
    src = src.replace("\"", "\\\"")
        .replace("<%pp_hash%>", &format!("0x{}", hex::encode(&pp_hash)))
        .replace("<%ped_pp_g%>", &parse_g1_to_solidity_string::<Bn254>(&ped_pp.g.into_affine()))
        .replace("<%ped_pp_h%>", &parse_g1_to_solidity_string::<Bn254>(&ped_pp.h.into_affine()))
        .replace("<%ipa_pp_u%>", &parse_g1_to_solidity_string::<Bn254>(&pp.u.into_affine()))
        .replace("<%ipa_pp_len%>", &n.to_string())
        .replace("<%ipa_log_len%>", &lg_n.to_string())
        .replace("<%ipa_final_check_len%>", &(2*n + 2*lg_n + 8).to_string())
        .replace("<%ipa_pp_vecs%>", &{
            let mut populate_ipa_pp_vec = String::new();
            for (i, (g, h)) in pp.g.iter().zip(pp.h.iter()).enumerate() {
                populate_ipa_pp_vec.push_str(&format!("pp.ipaG[{}] = BN254.G1Point({});", i, &parse_g1_to_solidity_string::<Bn254>(&g.into_affine())));
                populate_ipa_pp_vec.push_str("\n        ");
                populate_ipa_pp_vec.push_str(&format!("pp.ipaH[{}] = BN254.G1Point({});", i, &parse_g1_to_solidity_string::<Bn254>(&h.into_affine())));
                if i < pp.g.len() - 1 {
                    populate_ipa_pp_vec.push_str("\n        ");
                }
            }
            populate_ipa_pp_vec
        });
    src
}

pub fn encode_bulletproof<E: PairingEngine>(proof: &Proof<E::G1Projective>) -> Token {
    let mut tokens = Vec::new();
    tokens.push(encode_group_element::<E>(&proof.comm_bits));
    tokens.push(encode_group_element::<E>(&proof.comm_blind));
    tokens.push(encode_group_element::<E>(&proof.comm_lc1));
    tokens.push(encode_group_element::<E>(&proof.comm_lc2));
    tokens.push(encode_field_element::<E>(&proof.t_x));
    tokens.push(encode_field_element::<E>(&proof.r_t_x));
    tokens.push(encode_field_element::<E>(&proof.r_ab));
    tokens.push(Token::Array(proof.comm_ipa.iter().map(|(cl, _)| encode_group_element::<E>(cl)).collect::<Vec<_>>()));
    tokens.push(Token::Array(proof.comm_ipa.iter().map(|(_, cr)| encode_group_element::<E>(cr)).collect::<Vec<_>>()));
    tokens.push(encode_field_element::<E>(&proof.base_a));
    tokens.push(encode_field_element::<E>(&proof.base_b));
    Token::Tuple(tokens)
}
