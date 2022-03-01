// SPDX-License-Identifier: MIT
pragma solidity ^0.8.10;

import "./BN254.sol";
import "./Pedersen.sol";

contract PedersenTest {
  
  using BN254 for *;
  using Pedersen for *;
  
  function commit(uint b, uint r) public view returns (BN254.G1Point memory) {
    return Pedersen.commit(b, r);
  }

  function verify(BN254.G1Point memory given, uint b, uint r) public view returns (bool) {
    return Pedersen.verify(given, b, r);
  }
}