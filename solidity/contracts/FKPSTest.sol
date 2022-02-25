// SPDX-License-Identifier: MIT
pragma solidity ^0.8.10;

import "./FKPS.sol";

contract FKPSTest {
    using FKPS for *; 

    function testVerOpen(
      bytes memory N_bytes,
      bytes memory g_bytes,
      bytes memory h_bytes,
      bytes memory z_bytes,
      bytes memory h_hat_bytes,
      bytes memory ct,   
      uint alpha, uint bid) 
    public view returns (bool) {
      RSA.Element memory N = RSA._new(N_bytes);
      RSA.Element memory g = RSA._new(g_bytes);
      RSA.Element memory h = RSA._new(h_bytes);
      RSA.Element memory z = RSA._new(z_bytes);

      RSA.Element memory h_hat = RSA._new(h_hat_bytes);

      return FKPS.verOpenTest(FKPS.Params(N, g, h, z), 
        FKPS.Comm(h_hat, bytes32(ct)), alpha, bid);
    }
}