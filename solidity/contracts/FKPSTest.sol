// SPDX-License-Identifier: MIT
pragma solidity ^0.8.10;

import "./FKPS.sol";
contract FKPSTest {
    using FKPS for *; 

    function testVerOpen(RSA2048.Element memory h_hat, bytes memory ct, 
    FKPS.SelfOpening memory sopen) 
    public view returns (bool) {
      FKPS.Params memory pp = FKPS.publicParams();
      return FKPS.verOpen(FKPS.Comm(h_hat, ct), sopen, pp);
    }

    function testVerForceOpen(RSA2048.Element memory h_hat, bytes memory ct,
    RSA2048.Element memory z_hat, FKPS.Proof memory proof, bytes memory bid) 
    public returns (bool) {
      FKPS.Params memory pp = FKPS.publicParams();
      // return PoElib.verify(h_hat, z_hat, uint32(40), poe_proof);
      return FKPS.verForceOpen(FKPS.Comm(h_hat, ct), z_hat, proof, bid, pp);
      //return FKPS.verOpen(FKPS.Comm(h_hat, ct), uint(100000), bid, pp);
    }
}



