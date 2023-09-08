# Riggs: 

_Rust implementation of the Riggs family of decentralized sealed-bit auctions_ 

**ACM CCS 2023:**
Nirvan Tyagi, Arasu Arun, Cody Freitag, Riad Wahby, Joseph Bonneau, David Mazieres. _Riggs: Decentralized Sealed-Bid Auctions_. ACM CCS 2023.

**ePrint (full version):**
Nirvan Tyagi, Arasu Arun, Cody Freitag, Riad Wahby, Joseph Bonneau, David Mazieres. _Riggs: Decentralized Sealed-Bid Auctions_. Cryptology ePrint Archive, Report 2023/???. 

## Overview

This repository is organized as a Rust workspace with a number of modular packages.
The following packages make up the core of the implementation for the VeRSA verifiable registries:
* [`rsa`](rsa): Implementation of RSA primitives and constraints.
  * [`bignat`](rsa/src/bignat): Wrapper around [`rug`](https://docs.rs/rug/latest/rug/) crate for integer arithmetic using GMP and constraints ported from [`bellman-bignat`](https://github.com/alex-ozdemir/bellman-bignat) (implementing optimizations from [`xJsnark`](https://github.com/akosba/xjsnark)).
  * [`hog`](rsa/src/hog): Implementation and constraints for RSA groups of hidden order.
  * [`hash_to_prime`](rsa/src/hash_to_prime): Implementation for hash-to-integer and hash-to-prime.
* [`timed_commitments`](timed_commitments): Implementation of 

We provide a number of tests and benchmarks which we expand on below.
Benchmarks are co-located in a separate package while tests are interspersed across the above packages.
* [`benches`](benches): Microbenchmarks for VeRSA authenticated history dictionaries.

We also evaluate the costs of running a public bulletin board via a smart contract on Ethereum (or any blockchain supporting EVM).
* [`bulletin_board`](bulletin_board): Smart contracts and benchmarks for publishing digests to the blockchain.
* [`ethereum_test_utils`](ethereum_test_utils): Helper methods for compiling solidity and benchmarking gas costs.

Lastly, the above implementations for authenticated (history) dictionaries store state in-memory using standard Rust structs.
We implement a storage interface allowing for the data structures to store state persistently in an external database like Redis in an experimental branch [`storage-layer`](https://github.com/nirvantyagi/versa/tree/storage-layer-poc/).

## Installation/Build

The packages and benchmarks are easy to compile from source. The following sequence of commands may be helpful especially if on a fresh machine. A `Dockerfile` has also been provided which will run the equivalent of these commands and spin up an instance of Ubuntu. 

Install basic prerequisites and dependencies:
```
apt update && apt install -y curl
apt install git m4 z3 cmake libboost-all-dev build-essential
```
Install rust using any method ([Rust offical installation site](https://www.rust-lang.org/tools/install)):
```
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
```

Clone the repository:
```bash
git clone https://github.com/nirvantyagi/versa.git
cd versa/
```

Build using `cargo`:
```bash
cargo build
```

## Tests and Benchmarks

The `versa` packages come with a suite of tests and benchmarks.

### Running Tests

To run the tests:
```bash
cargo test
```

Some expensive tests have been omitted from the default test run.
To run an expensive test, specify it by name as follows:
```bash
cargo test name_of_expensive_test --release -- --ignored --nocapture
```

### Running Benchmarks

To run a benchmark:
```bash
cargo bench --bench name_of_benchmark -- [--optional-arg arg1 arg2...]
```

We provide the following benchmarks:
* [`update_epoch_0_mt`](benches/benches/update_epoch_0_mt.rs): Cost to prove and verify update from epoch 0 to 1 for registries based off of Merkle tree authenticated dictionaries.
* [`update_epoch_0_rsa`](benches/benches/update_epoch_0_rsa.rs): Cost to prove and verify update from epoch 0 to 1 for registries based off of RSA authenticated dictionaries.
* [`aggregate_rsa`](benches/benches/aggregate_rsa.rs): Cost to prove and verify algebraic update proof for RSA authenticated dictionary.
* [`aggregate_groth16`](benches/benches/aggregate_groth16.rs): Cost to prove and verify Groth16 SNARK aggregation.
* [`compute_witnesses_rsa`](benches/benches/compute_witnesses_rsa.rs): Cost to compute witness proofs for all entries in RSA authenticated dictionary.
* [`update_witness_rsa`](benches/benches/update_witness_rsa.rs): Cost to maintain witness for RSA authenticated dictionary over many dictionary updates.
* [`verify_witnesses_rsa`](benches/benches/verify_witnesses_rsa.rs): Cost to verify witness for RSA authenticated dictionary.
* [`update_merkle_tree`](benches/benches/update_merkle_tree.rs): Cost to prove update from epoch 0 to 1 for baseline Merkle tree authenticated dictionary without efficient history.
* [`verify_merkle_paths`](benches/benches/verify_merkle_paths.rs): Cost to verify update from epoch 0 to 1 for baseline Merkle tree authenticated dictionary without efficient history.