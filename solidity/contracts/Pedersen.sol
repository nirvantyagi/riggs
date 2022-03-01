// SPDX-License-Identifier: MIT
pragma solidity ^0.8.10;

import "./BN254.sol";

library Pedersen  {


  using BN254 for *;

  struct Params {
    BN254.G1Point G;
    BN254.G1Point H;
  }

  function publicParams() internal pure returns (Params memory pp) {
      pp.G = BN254.G1Point(<%ped_pp_g%>);
      pp.H = BN254.G1Point(<%ped_pp_h%>);
  }
  
  function commit(uint b, uint r) internal view returns (BN254.G1Point memory) {
    Params memory pp = publicParams();
    return BN254.g1add(BN254.g1mul(pp.G, b), BN254.g1mul(pp.H, r));
  }

  function verify(BN254.G1Point memory given, uint b, uint r) internal view returns (bool) {
    BN254.G1Point memory calc = commit(b, r);
    return given.X==calc.X && given.Y==calc.Y; 
  }

}