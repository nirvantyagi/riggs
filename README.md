# Riggs: 

_Rust implementation of the Riggs family of decentralized sealed-bit auctions_ 

**ACM CCS 2023:**
Nirvan Tyagi, Arasu Arun, Cody Freitag, Riad Wahby, Joseph Bonneau, David Mazieres. _Riggs: Decentralized Sealed-Bid Auctions_. ACM CCS 2023.

**ePrint (full version):**
Nirvan Tyagi, Arasu Arun, Cody Freitag, Riad Wahby, Joseph Bonneau, David Mazieres. _Riggs: Decentralized Sealed-Bid Auctions_. Cryptology ePrint Archive, Report 2023/1336 (https://eprint.iacr.org/2023/1336).

## Overview

This repository is organized as a Rust workspace with a number of modular packages.
The following packages make up the core of the implementation for the VeRSA verifiable registries:
* [`rsa`](rsa): Implementation of RSA primitives and constraints.
  * [`bignat`](rsa/src/bignat): Wrapper around [`rug`](https://docs.rs/rug/latest/rug/) crate for integer arithmetic using GMP and constraints ported from [`bellman-bignat`](https://github.com/alex-ozdemir/bellman-bignat) (implementing optimizations from [`xJsnark`](https://github.com/akosba/xjsnark)).
  * [`hog`](rsa/src/hog): Implementation and constraints for RSA groups of hidden order.
  * [`hash_to_prime`](rsa/src/hash_to_prime): Implementation for hash-to-integer and hash-to-prime.
* [`timed_commitments`](timed_commitments): Implementation of the non-malleable timed-commitment scheme introduced in the paper.
* [`range_proofs`](range_proofs): Implementation of range proofs using Bulletproofs.

We provide a number of tests and benchmarks which we expand on below.
Benchmarks are co-located in a separate package while tests are interspersed across the above packages.
* [`benches`](benches): Microbenchmarks for the main auction house protocols (Figure 4 in the paper) and the various tools involved.
  * `bench_baseline`, `bench_rp_auction_house`, `bench_tc_auction_house`


## Installation/Build

The packages and benchmarks are easy to compile from source. The following sequence of commands may be helpful especially if on a fresh machine. 

Install basic prerequisites and dependencies:
```
apt update && apt install -y curl
apt install git cmake libboost-all-dev build-essential
sudo add-apt-repository ppa:ethereum/ethereum
apt-get install solc
```
Install rust using any method ([Rust offical installation site](https://www.rust-lang.org/tools/install)):
```
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
```

Clone the repository:
```bash
git clone https://github.com/nirvantyagi/riggs.git
cd riggs/
```

Build using `cargo`:
```bash
cargo build
```

### Running Benchmarks

To run a benchmark:
```bash
cargo bench --bench name_of_benchmark -- [--optional-arg arg1 arg2...]
```

We provide the following benchmarks:
* [`bench_baseline`](benches/bench_baseline.rs)
* [`bench_rp_auction_house`](benches/bench_rp_auction_house.rs)
* [`bench_tc_auction_house`](benches/bench_tc_auction_house.rs)
