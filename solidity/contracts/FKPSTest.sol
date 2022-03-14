// SPDX-License-Identifier: MIT
pragma solidity ^0.8.10;

import "./FKPS.sol";

contract FKPSTest {
    using FKPS for *; 

    function testVerOpen(RSA2048.Element memory h_hat, bytes memory ct, uint alpha, 
    uint bid)  public view returns (bool) {
      FKPS.Params memory pp = FKPS.publicParams();
      return FKPS.verOpen(FKPS.Comm(h_hat, bytes32(ct)), alpha, bid, pp);
    }
}