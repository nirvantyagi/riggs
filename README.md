# Riggs: 

_Rust implementation of the Riggs family of decentralized sealed-bid auctions_ 

**ACM CCS 2023:**
Nirvan Tyagi, Arasu Arun, Cody Freitag, Riad Wahby, Joseph Bonneau, David Mazieres. _Riggs: Decentralized Sealed-Bid Auctions_. ACM CCS 2023.

**ePrint (full version):**
Nirvan Tyagi, Arasu Arun, Cody Freitag, Riad Wahby, Joseph Bonneau, David Mazieres. _Riggs: Decentralized Sealed-Bid Auctions_. Cryptology ePrint Archive, Report 2023/1336 (https://eprint.iacr.org/2023/1336).

## Overview

This repository is organized as a Rust workspace with a number of modular packages.
The following packages make up the core of the implementation:
* [`rsa`](rsa): Implementation of RSA primitives and constraints.
  * [`bignat`](rsa/src/bignat): Wrapper around [`rug`](https://docs.rs/rug/latest/rug/) crate for integer arithmetic using GMP and constraints ported from [`bellman-bignat`](https://github.com/alex-ozdemir/bellman-bignat).
  * [`hog`](rsa/src/hog): Implementation and constraints for RSA groups of hidden order.
  * [`hash_to_prime`](rsa/src/hash_to_prime): Implementation for hash-to-integer and hash-to-prime.
* [`timed_commitments`](timed_commitments): Implementation of three timed-commitment schemes: FKPS, the non-malleable TC scheme introduced in the paper, and a SNARK-based TC scheme.
* [`range_proofs`](range_proofs): Library for creating and verifying range proofs using the Bulletproofs protocol.

We provide a number benchmarks in the `riggs/benches` folder (expanded on below).

## Installation/Build

The packages and benchmarks are easy to compile from source on an Ubuntu machine. (We've faced compilation issues with the solidity packages on OSX). The following sequence of commands may be helpful especially if on a fresh machine. 

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

We benchmark the costs of the following operations. Each benchmark corresponds to a contract in `solidity/contracts/`.
* `bulletproofs_verifier`: verifying a bulletproof range proof
* `pedersen` commitment: verifying the opening of a Pedersen commitment 
* `rsa`: gas cost of verifying `X^e = Y` (where `X, e, Y` are all inputs) in an RSA2048 group of unknown order 
* `poe_verifier`: verifying a Wesolowski VDF proof in an RSA2048 group of unknown order 
* `fkps` timed commitment: opening of an FKPS timed-commitment 
* `tc` (introduced in paper): verifying the opening of the novel timed-commitments supporting range proofs introduced in the paper.

We provide benches for the auction house protocols described in the paper. 
Each benchmark corresponds to a column in Figure 4 and provides the computation time (in microseconds) and gas cost displayed in each row.
* [`auction_house_baseline`](benches/auction_house_baseline.rs) (with [contract](solidity/contracts/BaselineAuctionHouse.sol)): baseline auction house using per-auction collaterals 
* [`auction_house_rp`](benches/auction_house_rp.rs) (with [contract](solidity/contracts/AuctionHouseRP.sol)): auction house using range proofs but no timed commitments 
* [`auction_house_tc`](benches/auction_house_tc.rs) (with [contract](solidity/contracts/AuctionHouse.sol)): auction house using the novel timed-commitment scheme supporting range proofs 

A full benchmark for the Auction House with the SNARK-based TC will be added next. 
