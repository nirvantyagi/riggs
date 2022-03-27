// SPDX-License-Identifier: MIT
pragma solidity ^0.8.10;

import "./TC.sol";

contract TCTest {
  using TC for *;
  
  function testVerOpen(RSA2048.Element memory h_hat, bytes memory ct,
  BN254.G1Point memory given, bytes memory tc_m, uint alpha, uint bid, uint r) 
  public view returns (bool) {
    TC.Params memory pp = TC.publicParams();
    TC.Comm memory tc_comm;
    tc_comm.fkps = FKPS.Comm(h_hat, ct);
    tc_comm.ped = given;
    return TC.verOpen(tc_comm, alpha, tc_m, bid, r, pp);
  }
}