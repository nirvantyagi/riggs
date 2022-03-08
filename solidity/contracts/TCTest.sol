// SPDX-License-Identifier: MIT
pragma solidity ^0.8.10;

import "./TC.sol";
import "./RSA.sol";

contract TCTest {
  using TC for *;
  using RSA for *;
  
  // function commit(uint b, uint r) public view returns (BN254.G1Point memory) {
  //   return Pedersen.commit(b, r);
  // }

  // Params memory pp, Comm memory comm, uint256 alpha, uint b, uint r
  function verify(bytes memory N_bytes, bytes memory g_bytes, bytes memory h_bytes, bytes memory z_bytes, 
    bytes memory h_hat_bytes, bytes memory ct, 
    BN254.G1Point memory given, 
    uint alpha, uint b, uint r) public view returns (bool) {
    TC.Params memory pp;

    RSA.Element memory N = RSA._new(N_bytes);
    RSA.Element memory g = RSA._new(g_bytes);
    RSA.Element memory h = RSA._new(h_bytes);
    RSA.Element memory z = RSA._new(z_bytes);
    RSA.Element memory h_hat = RSA._new(h_hat_bytes);

    pp.fkps_pp = FKPS.Params(N, g, h, z);

    pp.pc_pp.G = BN254.G1Point(<%ped_pp_g%>);
    pp.pc_pp.H = BN254.G1Point(<%ped_pp_h%>);

    // TC.Comm memory given_tc;
    // given_tc.fkps = FKPS.Comm(h_hat, bytes32(ct));
    // given_tc.pc = given;

    return FKPS.verOpen(FKPS.Params(N, g, h, z), 
        FKPS.Comm(h_hat, bytes32(ct)), alpha, b);
    //return TC.verOpen(pp, given_tc, alpha, b, r);
  }
}