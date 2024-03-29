use ethabi::{Contract as ContractAbi, Token};
use serde_json::from_str;
use solc::compile;

use std::{fs::File, io::Read, path::Path};

use crate::{Error, EvmTestError};

#[derive(Clone)]
pub struct Contract {
    pub binary: Vec<u8>,
    pub abi: ContractAbi,
}

impl Contract {
    pub fn new(binary: Vec<u8>, abi: ContractAbi) -> Self {
        Self { binary, abi }
    }

    pub fn compile_from_solidity_file<P: AsRef<Path>>(
        path: P,
        contract_name: &str,
        opt: bool,
    ) -> Result<Self, Error> {
        // Load source file
        let mut src_file = File::open(path)
            .map_err(|_| Box::new(EvmTestError("src file open failed".to_string())))?;
        let mut src = String::new();
        src_file
            .read_to_string(&mut src)
            .map_err(|_| Box::new(EvmTestError("src file read failed".to_string())))?;
        src = src.replace("\"", "\\\"");

        Self::compile_from_src_string(&src, contract_name, opt)
    }

    pub fn compile_from_src_string(
        src: &String,
        contract_name: &str,
        opt: bool,
    ) -> Result<Self, Error> {
        // Compile source file using solc
        // Configuration: https://docs.soliditylang.org/en/v0.8.10/using-the-compiler.html
        // TODO: Change output selection to only compile 'input' file
        let solc_config = r#"
            {
                "language": "Solidity",
                "sources": { "input.sol": { "content": "{src}" } },
                "settings": {
                    "optimizer": { "enabled": {opt} },
                    "outputSelection": {
                        "*": {
                            "*": [
                                "evm.bytecode.object", "abi"
                            ],
                        "": [ "*" ] } }
                }
            }"#
        .replace("{opt}", &opt.to_string())
        .replace("{src}", &src);
        Self::compile_from_config(&solc_config, contract_name)
    }

    pub fn compile_from_config(config: &String, contract_name: &str) -> Result<Self, Error> {
        // Compile source file using solc
        // Configuration: https://docs.soliditylang.org/en/v0.8.10/using-the-compiler.html
        let out = from_str::<serde_json::Value>(&compile(config))
            .map_err(|_| Box::new(EvmTestError("solc compile failed".to_string())))?;

        if out["errors"].is_array() {
            if out["errors"]
                .as_array()
                .unwrap()
                .iter()
                .any(|e| e["severity"] == "error")
            {
                return Err(Box::new(EvmTestError(format!(
                    "solc compiled with errors: {}",
                    out["errors"]
                ))));
            }
        }

        let binary = {
            let hex_code = out["contracts"]["input.sol"][contract_name]["evm"]["bytecode"]
                ["object"]
                .to_string()
                .replace("\"", "");
            let binary = hex::decode(&hex_code)
                .map_err(|_| Box::new(EvmTestError("decode hex binary failed".to_string())))?;
            //.map_err(|e| Box::new(e))?;
            binary
        };
        // println!("Binary size: {}", binary.len());
        if binary.len() > 24576 {
            return Err(Box::new(EvmTestError(
                "contract binary too large".to_string(),
            )));
        }
        let abi = {
            if out["contracts"]["input.sol"][contract_name]["abi"] == "null" {
                return Err(Box::new(EvmTestError(
                    "solc compiled with null abi".to_string(),
                )));
            }
            let abi = ContractAbi::load(
                out["contracts"]["input.sol"][contract_name]["abi"]
                    .to_string()
                    .as_bytes(),
            )
            .map_err(|_| Box::new(EvmTestError("ethabi failed loading abi".to_string())))?;
            abi
        };

        Ok(Contract { binary, abi })
    }

    pub fn compile_from_config_no_print(
        config: &String,
        contract_name: &str,
    ) -> Result<Self, Error> {
        // Compile source file using solc
        // Configuration: https://docs.soliditylang.org/en/v0.8.10/using-the-compiler.html
        let out = from_str::<serde_json::Value>(&compile(config))
            .map_err(|_| Box::new(EvmTestError("solc compile failed".to_string())))?;

        if out["errors"].is_array() {
            if out["errors"]
                .as_array()
                .unwrap()
                .iter()
                .any(|e| e["severity"] == "error")
            {
                return Err(Box::new(EvmTestError(format!(
                    "solc compiled with errors: {}",
                    out["errors"]
                ))));
            }
        }

        let binary = {
            let hex_code = out["contracts"]["input.sol"][contract_name]["evm"]["bytecode"]
                ["object"]
                .to_string()
                .replace("\"", "");
            let binary = hex::decode(&hex_code)
                .map_err(|_| Box::new(EvmTestError("decode hex binary failed".to_string())))?;
            //.map_err(|e| Box::new(e))?;
            binary
        };
        // println!("Binary size: {}", binary.len());
        if binary.len() > 24576 {
            return Err(Box::new(EvmTestError(
                "contract binary too large".to_string(),
            )));
        }
        let abi = {
            if out["contracts"]["input.sol"][contract_name]["abi"] == "null" {
                return Err(Box::new(EvmTestError(
                    "solc compiled with null abi".to_string(),
                )));
            }
            let abi = ContractAbi::load(
                out["contracts"]["input.sol"][contract_name]["abi"]
                    .to_string()
                    .as_bytes(),
            )
            .map_err(|_| Box::new(EvmTestError("ethabi failed loading abi".to_string())))?;
            abi
        };

        Ok(Contract { binary, abi })
    }

    pub fn encode_create_contract_bytes(&self, init: &[Token]) -> Result<Vec<u8>, Error> {
        match &self.abi.constructor {
            Some(constructor) => {
                let binary = constructor
                    .encode_input(self.binary.clone().into(), init)
                    .map_err(|_| {
                        Box::new(EvmTestError(
                            "abi constructor failed to encode inputs".to_string(),
                        ))
                    })?;
                Ok(binary.to_vec())
            }
            None => Ok(self.binary.clone()),
        }
    }

    pub fn encode_call_contract_bytes(
        &self,
        fn_name: &str,
        input: &[Token],
    ) -> Result<Vec<u8>, Error> {
        match self.abi.functions.get(fn_name) {
            Some(f) => {
                //let c = f[0].inputs.iter().map(|p| p.kind.clone()).collect::<Vec<_>>();
                //println!("{:?}", c);
                let call_binary = f[0].encode_input(input).map_err(|_| {
                    Box::new(EvmTestError(
                        "abi function failed to encode inputs".to_string(),
                    ))
                })?;
                Ok(call_binary.to_vec())
            }
            None => Err(Box::new(EvmTestError(
                "abi does not include function".to_string(),
            ))),
        }
    }
}
