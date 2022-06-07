// use ark_bls12_381::{Bls12_381, Fr as F};
use ark_bn254::{Bn254, Fr as F, G1Projective as G};
use ark_ed_on_bn254::{EdwardsAffine, constraints::EdwardsVar as GV, EdwardsProjective as E};
use ark_ec::{PairingEngine, ProjectiveCurve, AffineCurve, bn};
// use ark_ed_on_bls12_381::{constraints::EdwardsVar as GV, EdwardsProjective as G_Groth};
//use ark_ed_on_bn254::{constraints::EdwardsVar as GV, EdwardsProjective as EG};

use digest::Digest;
use ethabi::Token;
use num_traits::Signed;
use primitive_types::U256;
use sha3::digest;
use std::{fs::File, io::Read, str::FromStr};

use range_proofs::bulletproofs::{serialize_group_elem, Params, PedersenParams, Proof};
use rsa::{
    bigint::BigInt,
    hash_to_prime::{
        hash_to_variable_output_length,
        pocklington::{PocklingtonCert, PocklingtonCertParams, PocklingtonHash, StepCert},
    },
    hog::{RsaGroupParams, RsaHiddenOrderGroup},
    poe::Proof as PoEProof,
};
use solidity_test_utils::{ parse_g1_to_solidity_string_pc, parse_g1_pc, encode_group_element_pc,
    encode_field_element, encode_field_element_pc, encode_group_element, encode_g2_element, encode_int_from_bytes, parse_g1_to_solidity_string
};
use timed_commitments::{basic_tc, lazy_tc};

use ark_groth16::{VerifyingKey, Proof as G16Proof};

use once_cell::sync::Lazy;
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TestRsaParams;

impl RsaGroupParams for TestRsaParams {
    const G: Lazy<BigInt> = Lazy::new(|| BigInt::from(2));
    const M: Lazy<BigInt> = Lazy::new(|| {
        BigInt::from_str("25195908475657893494027183240048398571429282126204032027777137836043662020707595556264018525880784406918290641249515082189298559149176184502808489120072844992687392807287776735971418347270261896375014971824691165077613379859095700097330459748808428401797429100642458691817195118746121515172654632282216869987549182422433637259085141865462043576798423387184774447920739934236584823824281198163815010674810451660377306056201619676256133844143603833904414952634432190114657544454178424020924616515723350778707749817125772467962926386356373289912154831438167899885040445364023527381951378636564391212010397122822120720357").unwrap()
    });
}

pub fn mean(data: &[u64]) -> Option<f64> {
    let sum = data.iter().sum::<u64>() as f64;
    let count = data.len();

    match count {
        positive if positive > 0 => Some((sum / count as f64)),
        // positive if positive > 0 => Some("format!("{:01}", (sum / count as f64)").parse::<f64>().unwrap()),
        _ => None,
    }
}

pub fn std_deviation(data: &[u64]) -> Option<f64> {
    match (mean(data), data.len()) {
        (Some(data_mean), count) if count > 0 => {
            let variance = data.iter().map(|value| {
                let diff = data_mean - (*value as f64);
                diff * diff
            }).sum::<f64>() / count as f64;

            Some(variance.sqrt())
            // Some(format!("{:04}", variance.sqrt()).parse::<f64>().unwrap())
        },
        _ => None
    }
}

pub fn get_bn254_library_src() -> String {
    let contract_path = format!("{}/contracts/BN254.sol", env!("CARGO_MANIFEST_DIR"));

    let mut src_file = File::open(contract_path).unwrap();
    let mut src = String::new();
    src_file.read_to_string(&mut src).unwrap();
    src = src
        .replace("\"", "\\\"")
        .replace("<%con_or_lib%>", "library")
        .replace("<%visibility%>", "internal");
    src
}

pub fn get_bn254_deploy_src() -> String {
    let contract_path = format!("{}/contracts/BN254.sol", env!("CARGO_MANIFEST_DIR"));

    let mut src_file = File::open(contract_path).unwrap();
    let mut src = String::new();
    src_file.read_to_string(&mut src).unwrap();
    src = src
        .replace("\"", "\\\"")
        .replace("<%con_or_lib%>", "library")
        .replace("<%visibility%>", "public");
    src
}

pub fn get_bulletproofs_verifier_contract_src_2<E: ProjectiveCurve>(
    pp: &Params<E>,
    ped_pp: &PedersenParams<E>,
    n: u64,
    lg_n: u64,
    as_contract: bool,
) -> String {
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
        "{}/contracts/BulletproofsVerifierBaby.sol",
        env!("CARGO_MANIFEST_DIR")
    );

    let mut src_file = File::open(contract_path).unwrap();
    let mut src = String::new();
    src_file.read_to_string(&mut src).unwrap();
    src = src
        .replace("\"", "\\\"")
        .replace(
            "<%con_or_lib%>",
            if as_contract { "contract" } else { "library" },
        )
        .replace(
            "<%visibility%>",
            if as_contract { "public" } else { "internal" },
        )
        .replace("<%pp_hash%>", &format!("0x{}", hex::encode(&pp_hash)))
        .replace(
            "<%ipa_pp_u%>",
            &parse_g1_to_solidity_string_pc::<E>(&pp.u),
        )
        .replace("<%ipa_pp_len%>", &n.to_string())
        .replace("<%ipa_log_len%>", &lg_n.to_string())
        .replace(
            "<%ipa_final_check_len%>",
            &(2 * n + 2 * lg_n + 8).to_string(),
        )
        .replace("<%ipa_pp_vecs%>", &{
            let mut populate_ipa_pp_vec = String::new();
            for (i, (g, h)) in pp.g.iter().zip(pp.h.iter()).enumerate() {
                populate_ipa_pp_vec.push_str(&format!(
                    "pp.ipaG[{}] = BabyJubjub.G1Point({});",
                    i,
                    &parse_g1_to_solidity_string_pc::<E>(&g)
                ));
                populate_ipa_pp_vec.push_str("\n        ");
                populate_ipa_pp_vec.push_str(&format!(
                    "pp.ipaH[{}] = BabyJubjub.G1Point({});",
                    i,
                    &parse_g1_to_solidity_string_pc::<E>(&h)
                ));
                if i < pp.g.len() - 1 {
                    populate_ipa_pp_vec.push_str("\n        ");
                }
            }
            populate_ipa_pp_vec
        });
    src
}


pub fn get_bulletproofs_verifier_contract_src(
    pp: &Params<G>,
    ped_pp: &PedersenParams<G>,
    n: u64,
    lg_n: u64,
    as_contract: bool,
) -> String {
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
    src = src
        .replace("\"", "\\\"")
        .replace(
            "<%con_or_lib%>",
            if as_contract { "contract" } else { "library" },
        )
        .replace(
            "<%visibility%>",
            if as_contract { "public" } else { "internal" },
        )
        .replace("<%pp_hash%>", &format!("0x{}", hex::encode(&pp_hash)))
        .replace(
            "<%ipa_pp_u%>",
            &parse_g1_to_solidity_string::<Bn254>(&pp.u.into_affine()),
        )
        .replace("<%ipa_pp_len%>", &n.to_string())
        .replace("<%ipa_log_len%>", &lg_n.to_string())
        .replace(
            "<%ipa_final_check_len%>",
            &(2 * n + 2 * lg_n + 8).to_string(),
        )
        .replace("<%ipa_pp_vecs%>", &{
            let mut populate_ipa_pp_vec = String::new();
            for (i, (g, h)) in pp.g.iter().zip(pp.h.iter()).enumerate() {
                populate_ipa_pp_vec.push_str(&format!(
                    "pp.ipaG[{}] = BN254.G1Point({});",
                    i,
                    &parse_g1_to_solidity_string::<Bn254>(&g.into_affine())
                ));
                populate_ipa_pp_vec.push_str("\n        ");
                populate_ipa_pp_vec.push_str(&format!(
                    "pp.ipaH[{}] = BN254.G1Point({});",
                    i,
                    &parse_g1_to_solidity_string::<Bn254>(&h.into_affine())
                ));
                if i < pp.g.len() - 1 {
                    populate_ipa_pp_vec.push_str("\n        ");
                }
            }
            populate_ipa_pp_vec
        });
    src
}

pub fn get_bigint_library_src() -> String {
    let contract_path = format!("{}/contracts/BigInt.sol", env!("CARGO_MANIFEST_DIR"));

    let mut src_file = File::open(contract_path).unwrap();
    let mut src = String::new();
    src_file.read_to_string(&mut src).unwrap();
    src = src.replace("\"", "\\\"");
    src
}

pub fn get_fkps_src(h: &BigInt, z: &BigInt, m_len: usize, t: u64, as_contract: bool) -> String {
    let contract_path = format!("{}/contracts/FKPS.sol", env!("CARGO_MANIFEST_DIR"));

    let mut src_file = File::open(contract_path).unwrap();
    let mut src = String::new();
    src_file.read_to_string(&mut src).unwrap();
    src = src
        .replace("\"", "\\\"")
        .replace(
            "<%con_or_lib%>",
            if as_contract { "contract" } else { "library" },
        )
        .replace(
            "<%visibility%>",
            if as_contract { "public" } else { "internal" },
        )
        //.replace("<%pp_time%>", &format!("{}", t))
        .replace("<%pp_time%>", &format!("{}", t))
        .replace("<%pp_m_len%>", &format!("{}", m_len / 256))
        .replace("<%pp_h_populate%>", &{
            let mut populate_h = String::new();
            for (i, u256digit) in h.to_u64_digits().1.chunks(4).rev().enumerate() {
                populate_h.push_str(&format!(
                    "h_u256_digits[{}] = 0x{}{}{}{};",
                    i,
                    hex::encode(&u256digit[3].to_be_bytes()),
                    hex::encode(&u256digit[2].to_be_bytes()),
                    hex::encode(&u256digit[1].to_be_bytes()),
                    hex::encode(&u256digit[0].to_be_bytes()),
                ));
                if i < h.to_u64_digits().1.len() / 4 - 1 {
                    populate_h.push_str("\n        ");
                }
            }
            populate_h
        })
        .replace("<%pp_z_populate%>", &{
            let mut populate_z = String::new();
            for (i, u256digit) in z.to_u64_digits().1.chunks(4).rev().enumerate() {
                populate_z.push_str(&format!(
                    "z_u256_digits[{}] = 0x{}{}{}{};",
                    i,
                    hex::encode(&u256digit[3].to_be_bytes()),
                    hex::encode(&u256digit[2].to_be_bytes()),
                    hex::encode(&u256digit[1].to_be_bytes()),
                    hex::encode(&u256digit[0].to_be_bytes()),
                ));
                if i < h.to_u64_digits().1.len() / 4 - 1 {
                    populate_z.push_str("\n        ");
                }
            }
            populate_z
        });
    src
}

pub fn get_rsa_library_src(m: &BigInt, m_len: usize, as_contract: bool) -> String {
    let contract_path = format!("{}/contracts/RSA2048.sol", env!("CARGO_MANIFEST_DIR"));

    let mut src_file = File::open(contract_path).unwrap();
    let mut src = String::new();
    src_file.read_to_string(&mut src).unwrap();
    src = src
        .replace("\"", "\\\"")
        .replace(
            "<%con_or_lib%>",
            if as_contract { "contract" } else { "library" },
        )
        .replace(
            "<%visibility%>",
            if as_contract { "public" } else { "internal" },
        )
        .replace("<%pp_m_len%>", &format!("{}", m_len / 256))
        .replace("<%pp_m_populate%>", &{
            let mut populate_m = String::new();
            for (i, u256digit) in m.to_u64_digits().1.chunks(4).rev().enumerate() {
                populate_m.push_str(&format!(
                    "m_u256_digits[{}] = 0x{}{}{}{};",
                    i,
                    hex::encode(&u256digit[3].to_be_bytes()),
                    hex::encode(&u256digit[2].to_be_bytes()),
                    hex::encode(&u256digit[1].to_be_bytes()),
                    hex::encode(&u256digit[0].to_be_bytes()),
                ));
                if i < m.to_u64_digits().1.len() / 4 - 1 {
                    populate_m.push_str("\n        ");
                }
            }
            populate_m
        });
    src
}

pub fn get_pedersen_library_src2<E: ProjectiveCurve>(ped_pp: &PedersenParams<E>, as_contract: bool) -> String {
    let contract_path = format!("{}/contracts/PedersenBaby.sol", env!("CARGO_MANIFEST_DIR"));

    let mut src_file = File::open(contract_path).unwrap();
    let mut src = String::new();
    src_file.read_to_string(&mut src).unwrap();
    src = src
        .replace("\"", "\\\"")
        .replace(
            "<%con_or_lib%>",
            if as_contract { "contract" } else { "library" },
        )
        .replace(
            "<%visibility%>",
            if as_contract { "public" } else { "internal" },
        )
        .replace(
            "<%ped_pp_g%>",
            &parse_g1_to_solidity_string_pc::<E>(&ped_pp.g),
        )
        .replace(
            "<%ped_pp_h%>",
            &parse_g1_to_solidity_string_pc::<E>(&ped_pp.h),
        );
    src
}

pub fn get_pedersen_library_src(ped_pp: &PedersenParams<G>, as_contract: bool) -> String {
    let contract_path = format!("{}/contracts/Pedersen.sol", env!("CARGO_MANIFEST_DIR"));

    let mut src_file = File::open(contract_path).unwrap();
    let mut src = String::new();
    src_file.read_to_string(&mut src).unwrap();
    src = src
        .replace("\"", "\\\"")
        .replace(
            "<%con_or_lib%>",
            if as_contract { "contract" } else { "library" },
        )
        .replace(
            "<%visibility%>",
            if as_contract { "public" } else { "internal" },
        )
        .replace(
            "<%ped_pp_g%>",
            &parse_g1_to_solidity_string::<Bn254>(&ped_pp.g.into_affine()),
        )
        .replace(
            "<%ped_pp_h%>",
            &parse_g1_to_solidity_string::<Bn254>(&ped_pp.h.into_affine()),
        );
    src
}

pub fn get_pedersen_deploy_src(ped_pp: &PedersenParams<G>, as_contract: bool) -> String {
    let contract_path = format!("{}/contracts/Pedersen.sol", env!("CARGO_MANIFEST_DIR"));

    let mut src_file = File::open(contract_path).unwrap();
    let mut src = String::new();
    src_file.read_to_string(&mut src).unwrap();
    src = src
        .replace("\"", "\\\"")
        .replace(
            "<%con_or_lib%>",
            if as_contract { "library" } else { "library" },
        )
        .replace(
            "<%visibility%>",
            if as_contract { "public" } else { "public" },
        )
        .replace(
            "<%ped_pp_g%>",
            &parse_g1_to_solidity_string::<Bn254>(&ped_pp.g.into_affine()),
        )
        .replace(
            "<%ped_pp_h%>",
            &parse_g1_to_solidity_string::<Bn254>(&ped_pp.h.into_affine()),
        );
    src
}

pub fn get_filename_src(filename: &str, as_contract: bool) -> String {
    let contract_path = format!("{}/contracts/", env!("CARGO_MANIFEST_DIR"));
    let full_path: String = contract_path + filename;

    let mut src_file = File::open(full_path).unwrap();
    let mut src = String::new();
    src_file.read_to_string(&mut src).unwrap();
    src = src
        .replace("\"", "\\\"")
        .replace(
            "<%con_or_lib%>",
            if as_contract { "contract" } else { "library" },
        )
        .replace(
            "<%visibility%>",
            if as_contract { "public" } else { "internal" },
        );
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
    tokens.push(Token::Array(
        proof
            .comm_ipa
            .iter()
            .map(|(cl, _)| encode_group_element::<E>(cl))
            .collect::<Vec<_>>(),
    ));
    tokens.push(Token::Array(
        proof
            .comm_ipa
            .iter()
            .map(|(_, cr)| encode_group_element::<E>(cr))
            .collect::<Vec<_>>(),
    ));
    tokens.push(encode_field_element::<E>(&proof.base_a));
    tokens.push(encode_field_element::<E>(&proof.base_b));
    Token::Tuple(tokens)
}

pub fn encode_bulletproof_2<E: ProjectiveCurve>(proof: &Proof<E>) -> Token {
    let mut tokens = Vec::new();
    tokens.push(encode_group_element_pc::<E>(&proof.comm_bits));
    tokens.push(encode_group_element_pc::<E>(&proof.comm_blind));
    tokens.push(encode_group_element_pc::<E>(&proof.comm_lc1));
    tokens.push(encode_group_element_pc::<E>(&proof.comm_lc2));
    tokens.push(encode_field_element_pc::<E>(&proof.t_x));
    tokens.push(encode_field_element_pc::<E>(&proof.r_t_x));
    tokens.push(encode_field_element_pc::<E>(&proof.r_ab));
    tokens.push(Token::Array(
        proof
            .comm_ipa
            .iter()
            .map(|(cl, _)| encode_group_element_pc::<E>(cl))
            .collect::<Vec<_>>(),
    ));
    tokens.push(Token::Array(
        proof
            .comm_ipa
            .iter()
            .map(|(_, cr)| encode_group_element_pc::<E>(cr))
            .collect::<Vec<_>>(),
    ));
    tokens.push(encode_field_element_pc::<E>(&proof.base_a));
    tokens.push(encode_field_element_pc::<E>(&proof.base_b));
    Token::Tuple(tokens)
}

pub fn encode_bigint(n: &BigInt) -> Token {
    Token::Tuple(vec![
        Token::Bytes(pad_to_32_byte_offset(n.to_bytes_be().1)),
        Token::Bool(n.is_negative()),
    ])
}

pub fn encode_rsa_element<P: RsaGroupParams>(elmt: &RsaHiddenOrderGroup<P>) -> Token {
    Token::Tuple(vec![encode_bigint(&elmt.n)])
}

pub fn encode_pocklington_step_certificate(cert: &StepCert) -> Token {
    let mut tokens = Vec::new();
    tokens.push(encode_bigint(&cert.f));
    tokens.push(Token::Uint(U256::from(cert.n)));
    tokens.push(Token::Uint(U256::from(cert.n2)));
    tokens.push(encode_bigint(&cert.a));
    tokens.push(encode_bigint(&cert.bu));
    tokens.push(encode_bigint(&cert.bv));
    tokens.push(encode_bigint(&cert.v.as_ref().unwrap()));
    tokens.push(encode_bigint(&cert.s.as_ref().unwrap()));
    tokens.push(encode_bigint(&cert.expr_sqrt.as_ref().unwrap()));
    tokens.push(encode_bigint(&cert.p_less_one_div_f.as_ref().unwrap()));
    tokens.push(encode_bigint(&cert.p_less_one_div_two.as_ref().unwrap()));
    tokens.push(encode_bigint(&cert.b_p_div_f1.as_ref().unwrap()));
    tokens.push(encode_bigint(&cert.b_p_div_f2.as_ref().unwrap()));
    tokens.push(encode_bigint(&cert.b_p_div_two1.as_ref().unwrap()));
    tokens.push(encode_bigint(&cert.b_p_div_two2.as_ref().unwrap()));
    Token::Tuple(tokens)
}

pub fn encode_pocklington_certificate(cert: &PocklingtonCert) -> Token {
    let step_certs = Token::Array(
        cert.step_certificates
            .iter()
            .map(|c| encode_pocklington_step_certificate(c))
            .collect::<Vec<_>>(),
    );
    Token::Tuple(vec![step_certs, Token::Uint(U256::from(cert.nonce))])
}

pub fn encode_poe_proof<P: RsaGroupParams, HP: PocklingtonCertParams, D: Digest>(
    proof: &PoEProof<P, PocklingtonHash<HP, D>>,
) -> Token {
    let mut tokens = Vec::new();
    tokens.push(encode_rsa_element(&proof.q));
    tokens.push(encode_pocklington_certificate(&proof.cert));
    Token::Tuple(tokens)
}

// Commitments

pub fn encode_ped_comm_struct<E: PairingEngine>(g: &E::G1Projective) -> Token {
    let mut tokens = Vec::new();
    tokens.push(encode_group_element::<E>(&g));
    Token::Tuple(tokens)
}

pub fn encode_fkps_comm<P: RsaGroupParams>(comm: &basic_tc::Comm<P>) -> Token {
    let mut tokens = Vec::new();
    tokens.push(encode_rsa_element(&comm.x));
    tokens.push(Token::Bytes(comm.ct.clone().to_vec()));
    Token::Tuple(tokens)
}

pub fn encode_tc_comm<E: PairingEngine, P: RsaGroupParams>(
    comm: &lazy_tc::Comm<E::G1Projective, P>,
) -> Token {
    let mut tokens = Vec::new();
    tokens.push(encode_group_element::<E>(&comm.ped_comm));
    tokens.push(encode_fkps_comm(&comm.tc_comm));
    Token::Tuple(tokens)
}

// Openings

pub fn encode_fkps_opening<P: RsaGroupParams, HP: PocklingtonCertParams, D: Digest>(
    opening: &basic_tc::Opening<P, PocklingtonHash<HP, D>>,
    m: &Option<Vec<u8>>,
) -> Token {
    let mut tokens = Vec::new();

    match &opening {
        basic_tc::Opening::SELF(alpha) => {
            tokens.push(encode_int_from_bytes(&alpha.to_bytes_be().1));
        }
        basic_tc::Opening::FORCE(y, poe_proof) => {
            tokens.push(encode_rsa_element(&y));
            tokens.push(encode_poe_proof::<P, HP, D>(poe_proof));
        }
    };
    if m.is_none() {
        tokens.push(Token::Bytes([].to_vec()));
    } else {
        tokens.push(Token::Bytes(m.as_ref().unwrap().to_vec()));
    }
    Token::Tuple(tokens)
}

pub fn encode_tc_opening<P: RsaGroupParams, HP: PocklingtonCertParams, D: Digest>(
    opening: &lazy_tc::Opening<G, P, PocklingtonHash<HP, D>>,
) -> Token {
    let mut tokens = Vec::new();
    tokens.push(encode_fkps_opening(
        &opening.tc_opening,
        &opening.tc_m,
        // &opening.tc_m.as_ref().get_or_insert(&[].to_vec()),
    ));
    Token::Tuple(tokens)
}

// Public Params

pub fn encode_ped_pp_pc<G: ProjectiveCurve>(ped_pp: &PedersenParams<G>) -> Token {
    let mut tokens = Vec::new();
    tokens.push(encode_group_element_pc::<G>(&ped_pp.g));
    tokens.push(encode_group_element_pc::<G>(&ped_pp.h));
    Token::Tuple(tokens)
}

pub fn encode_ped_pp<E: PairingEngine>(ped_pp: &PedersenParams<E::G1Projective>) -> Token {
    let mut tokens = Vec::new();
    tokens.push(encode_group_element::<E>(&ped_pp.g));
    tokens.push(encode_group_element::<E>(&ped_pp.h));
    Token::Tuple(tokens)
}

pub fn encode_rsa_pp<P: RsaGroupParams>(m: &BigInt) -> Token {
    let mut tokens = Vec::new();
    tokens.push(encode_rsa_element::<P>(&RsaHiddenOrderGroup::from_nat(
        BigInt::from(2),
    )));
    tokens.push(encode_bigint(&m));
    Token::Tuple(tokens)
}

pub fn encode_fkps_pp<P: RsaGroupParams>(m: &BigInt, fkps_pp: &basic_tc::TimeParams<P>) -> Token {
    let mut tokens = Vec::new();
    tokens.push(encode_rsa_pp::<P>(&m)); // needed in solidity code
    tokens.push(encode_rsa_element(&fkps_pp.x));
    tokens.push(encode_rsa_element(&fkps_pp.y));
    tokens.push(Token::Uint(U256::from(fkps_pp.t)));
    Token::Tuple(tokens)
}

pub fn encode_tc_pp<E: PairingEngine, P: RsaGroupParams>(
    m: &BigInt,
    fkps_pp: &basic_tc::TimeParams<P>,
    ped_pp: &PedersenParams<E::G1Projective>,
) -> Token {
    let mut tokens = Vec::new();
    tokens.push(encode_ped_pp::<E>(&ped_pp));
    tokens.push(encode_fkps_pp(&m, &fkps_pp));
    Token::Tuple(tokens)
}

pub fn encode_tc_partial<E: PairingEngine, P: RsaGroupParams>(
    fkps_pp: &basic_tc::TimeParams<P>,
) -> Token {
    let mut tokens = Vec::new();
    tokens.push(encode_rsa_element(&fkps_pp.x));
    tokens.push(encode_rsa_element(&fkps_pp.y));
    tokens.push(Token::Uint(U256::from(fkps_pp.t)));
    Token::Tuple(tokens)
}

pub fn encode_new_auction<E: PairingEngine, P: RsaGroupParams>(
    erc721_contract_addr: &solidity_test_utils::address::Address,
    token_id: u32,
    bid_collection_num_blocks: u32,
    bid_self_open_num_blocks: u32,
    reward_self_open: u32,
    reward_force_open: u32,
    fkps_pp: &basic_tc::TimeParams<P>,
) -> Vec<Token> {
    let mut tokens = Vec::new();
    tokens.push(erc721_contract_addr.as_token());
    tokens.push(Token::Uint(U256::from(token_id)));
    tokens.push(Token::Uint(U256::from(bid_collection_num_blocks)));
    tokens.push(Token::Uint(U256::from(bid_self_open_num_blocks)));
    tokens.push(Token::Uint(U256::from(reward_self_open)));
    tokens.push(Token::Uint(U256::from(reward_force_open)));
    tokens.push(encode_tc_partial::<E, P>(fkps_pp));
    // Token::Tuple(tokens)
    tokens
}

fn pad_to_32_byte_offset(mut bytes: Vec<u8>) -> Vec<u8> {
    let pad_len = 32 * ((bytes.len() - 1) / 32 + 1);
    bytes.reverse();
    bytes.resize(pad_len, 0);
    debug_assert_eq!(bytes.len() % 32, 0);
    bytes.reverse();
    bytes
}

pub fn read_groth16_src(vk: &VerifyingKey<Bn254>, as_contract: bool) -> String {
    let contract_path = format!(
        "{}/contracts/Groth16Verifier.sol",
        env!("CARGO_MANIFEST_DIR")
    );

    //println!("vk alpha g1: {}", vk.alpha_g1.x.0.to_string());

    // println!("(0x{}, 0x{})", &vk.alpha_g1.x.0.to_string().to_lowercase(), 
    //             &vk.alpha_g1.y.0.to_string().to_lowercase());
    
    //println!("{}", &vk.beta_g2.to_string().as_str());

    let mut populate_gamma_abc_points = String::new();
    for i in 0..vk.gamma_abc_g1.len() {
        populate_gamma_abc_points.push_str(&format!(
            "vk.gamma_abc[{}] = Pairing.G1Point(0x{}, 0x{});\n",
            i.to_string(),
            &vk.gamma_abc_g1.get(i).unwrap().x.0.to_string(), 
            &vk.gamma_abc_g1.get(i).unwrap().y.0.to_string(), 
        ));
    }

    println!("{}", &populate_gamma_abc_points);

    let mut src_file = File::open(contract_path).unwrap();
    let mut src = String::new();
    src_file.read_to_string(&mut src).unwrap();
    src = src
        .replace("\"", "\\\"")
        .replace(
            "<%con_or_lib%>",
            if as_contract { "contract" } else { "library" },
        )
        .replace(
            "<%visibility%>", 
            if as_contract { "public" } else { "internal" },
        )
        .replace("<%vk_alpha%>", &format!("0x{}, 0x{}", &vk.alpha_g1.x.0.to_string(), &vk.alpha_g1.y.0.to_string()))
        .replace("<%vk_beta%>", &format!("[0x{}, 0x{}], [0x{}, 0x{}]",
                    &vk.beta_g2.x.c0.0.to_string().to_lowercase(),
                    &vk.beta_g2.x.c1.0.to_string().to_lowercase(),
                    &vk.beta_g2.y.c0.0.to_string().to_lowercase(),
                    &vk.beta_g2.y.c1.0.to_string().to_lowercase(),))
        .replace("<%vk_gamma%>", &format!("[0x{}, 0x{}], [0x{}, 0x{}]",
                    &vk.gamma_g2.x.c0.0.to_string().to_lowercase(),
                    &vk.gamma_g2.x.c1.0.to_string().to_lowercase(),
                    &vk.gamma_g2.y.c0.0.to_string().to_lowercase(),
                    &vk.gamma_g2.y.c1.0.to_string().to_lowercase(),))
        .replace("<%vk_delta%>", &format!("[0x{}, 0x{}], [0x{}, 0x{}]",
                    &vk.delta_g2.x.c0.0.to_string().to_lowercase(),
                    &vk.delta_g2.x.c1.0.to_string().to_lowercase(),
                    &vk.delta_g2.y.c0.0.to_string().to_lowercase(),
                    &vk.delta_g2.y.c1.0.to_string().to_lowercase(),))
        .replace("<%vk_gamma_abc_length%>", &format!("{}",
                    &vk.gamma_abc_g1.len().to_string()))
        .replace("<%input_length%>", &format!("{}",
                    &(vk.gamma_abc_g1.len()-1).to_string()))
        .replace("<%vk_gamma_abc_pts%>", &format!("{}",
                    &populate_gamma_abc_points))
        ;
    src
}

pub fn encode_groth16_inputs<E: PairingEngine>(
    public_inputs: &Vec<E::Fr>,
) -> Token {
    let mut tokens = Vec::new();
    // println!("G16 inputs: {}", public_inputs.get(0).unwrap());
    println!("len of public inputs: {}", public_inputs.len());
    for i in 0..public_inputs.len() {
        // tokens.push(encode_field_element::<E>(public_inputs.get(i).unwrap()));
        tokens.push(encode_field_element::<E>(&public_inputs.get(i).unwrap()));
    }
    Token::FixedArray(tokens)
}

pub fn encode_groth16_inputs_struct<E: PairingEngine>(
    public_inputs: &Vec<E::Fr>,
) -> Token {
    let mut tokens = Vec::new();
    // println!("G16 inputs: {}", public_inputs.get(0).unwrap());
    println!("len of public inputs: {}", public_inputs.len());
    for i in 0..2 {
        // tokens.push(encode_field_element::<E>(public_inputs.get(i).unwrap()));
        tokens.push(encode_field_element::<E>(&public_inputs.get(i).unwrap()));
    }
    
    let mut tokens2 = Vec::new();
    tokens2.push(Token::Tuple(tokens));
    Token::Tuple(tokens2)
}

use std::{fmt::Write, num::ParseIntError};

pub fn decode_hex(s: &str) -> Result<Vec<u8>, ParseIntError> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
        .collect()
}

pub fn encode_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        write!(&mut s, "{:02x}", b).unwrap();
    }
    s
}

pub fn encode_groth16_input<E: PairingEngine>(
    public_inputs: &Vec<E::Fr>,
) -> Token {
    // let mut tokens = Vec::new();
    encode_field_element::<E>(&public_inputs.get(0).unwrap())
    // Token::Tuple(tokens)
    // Token::Uint(U256::from_big_endian(decode_hex(public_inputs.get(0).unwrap()).unwrap()))
}


/*
proof.A = Pairing.G1Point(12873740738727497448187997291915224677121726020054032516825496230827252793177, 21804419174137094775122804775419507726154084057848719988004616848382402162497);
proof.A_p = Pairing.G1Point(7742452358972543465462254569134860944739929848367563713587808717088650354556, 7324522103398787664095385319014038380128814213034709026832529060148225837366);
proof.B = Pairing.G2Point(
    [8176651290984905087450403379100573157708110416512446269839297438960217797614, 15588556568726919713003060429893850972163943674590384915350025440408631945055],
    [15347511022514187557142999444367533883366476794364262773195059233657571533367, 4265071979090628150845437155927259896060451682253086069461962693761322642015]);
proof.B_p = Pairing.G1Point(2979746655438963305714517285593753729335852012083057917022078236006592638393, 6470627481646078059765266161088786576504622012540639992486470834383274712950);
proof.C = Pairing.G1Point(6851077925310461602867742977619883934042581405263014789956638244065803308498, 10336382210592135525880811046708757754106524561907815205241508542912494488506);
proof.C_p = Pairing.G1Point(12491625890066296859584468664467427202390981822868257437245835716136010795448, 13818492518017455361318553880921248537817650587494176379915981090396574171686);
proof.H = Pairing.G1Point(12091046215835229523641173286701717671667447745509192321596954139357866668225, 14446807589950902476683545679847436767890904443411534435294953056557941441758);
proof.K = Pairing.G1Point(2134108797660991640940173
*/

// pub fn parse_g1(g1: &G1Affine) -> (Vec<u8>, Vec<u8>) {
//     let mut bytes: Vec<u8> = Vec::new();
//     g1.write(&mut bytes).unwrap();

//     let element_length = (bytes.len() - 1) / 2; // [x, y, infinity] - infinity
//     let mut x = bytes[0..element_length].to_vec();
//     let mut y = bytes[element_length..2 * element_length].to_vec();
//     x.reverse();
//     y.reverse();
//     (x, y)
// }

// pub fn encode_bn254_g1point<E: PairingEngine>(input: G1Affine) -> Token {
//     let (x, y) = parse_g1(&input);
//     let mut tokens = Vec::new();
//     tokens.push(Token::Uint(U256::from_str_radix(input.x.to_string().as_str(), 16).unwrap()));
//     tokens.push(Token::Uint(U256::from_str_radix(input.y.to_string().as_str(), 16).unwrap()));
//     Token::Tuple(tokens)
// }

// pub fn encode_bn254_g2point(input: G2Affine) -> Token {
//     let mut tokens = Vec::new();
//     tokens.push(Token::Uint(U256::from_str_radix(input.x.c0.0.to_string().as_str(), 16).unwrap()));
//     tokens.push(Token::Uint(U256::from_str_radix(input.x.c1.0.to_string().as_str(), 16).unwrap()));
//     tokens.push(Token::Uint(U256::from_str_radix(input.y.c0.0.to_string().as_str(), 16).unwrap()));
//     tokens.push(Token::Uint(U256::from_str_radix(input.y.c1.0.to_string().as_str(), 16).unwrap()));
//     Token::Tuple(tokens)
// }

pub fn encode_groth16_proof<E: PairingEngine>(
    proof: &G16Proof<E>
) -> Token {
    let mut tokens = Vec::new();
    tokens.push(encode_group_element::<E>(&proof.a.into_projective()));
    tokens.push(encode_g2_element::<E>(&proof.b.into_projective()));
    tokens.push(encode_group_element::<E>(&proof.c.into_projective()));
    Token::Tuple(tokens)
}


// pub fn encode_jubjub_g1<G: ProjectiveCurve>(x: &u8) -> String {
//     let mut populate_m = String::new();
//     for (i, u256digit) in m.to_u64_digits().1.chunks(4).rev().enumerate() {
//         populate_m.push_str(&format!(
//             "m_u256_digits[{}] = 0x{}{}{}{};",
//             i,
//             hex::encode(&u256digit[3].to_be_bytes()),
//             hex::encode(&u256digit[2].to_be_bytes()),
//             hex::encode(&u256digit[1].to_be_bytes()),
//             hex::encode(&u256digit[0].to_be_bytes()),
//         ));
//         if i < m.to_u64_digits().1.len() / 4 - 1 {
//             populate_m.push_str("\n        ");
//         }
//     }
//     populate_m
// }

