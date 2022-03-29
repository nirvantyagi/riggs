// SPDX-License-Identifier: MIT
pragma solidity ^0.8.10;

import "./TC.sol";

contract TCTest {
  using TC for *;

  function testVerOpen(RSA2048.Element memory h_hat, bytes memory ct,
  BN254.G1Point memory given, TC.SelfOpening memory tc_so, uint bid, uint r) 
  public view returns (bool) {
    TC.Params memory pp = TC.publicParams();
    TC.Comm memory tc_comm;
    tc_comm.fkps = FKPS.Comm(h_hat, ct);
    tc_comm.ped = given;
    return TC.verOpen(tc_comm, tc_so, bid, r, pp);
  }


  function testVerForceOpen(RSA2048.Element memory h_hat, bytes memory ct,
  BN254.G1Point memory given, bytes memory tc_m, RSA2048.Element memory z_hat, 
  FKPS.Proof memory poe_proof,  uint bid, uint r) 
  public view returns (bool) {
    TC.Params memory pp = TC.publicParams();
    TC.Comm memory tc_comm;
    tc_comm.fkps = FKPS.Comm(h_hat, ct);
    tc_comm.ped = given;
    return TC.verForceOpen(tc_comm, z_hat, poe_proof, tc_m, bid, r, pp);
  }
}