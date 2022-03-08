// SPDX-License-Identifier: MIT
pragma solidity ^0.8.10;

import "./FKPS.sol";

contract FKPSTest {
    using FKPS for *; 

    function testVerOpen(
      bytes memory h_hat_bytes,
      bytes memory ct,   
      uint alpha, uint bid) 
    public view returns (bool) {
      RSA.Element memory N = RSA._new(hex"<%rsa_n%>");
      RSA.Element memory g = RSA._new(hex"<%rsa_g%>");
      RSA.Element memory h = RSA._new(hex"<%rsa_h%>");
      RSA.Element memory z = RSA._new(hex"<%rsa_z%>");

      RSA.Element memory h_hat = RSA._new(h_hat_bytes);

      return FKPS.verOpen(FKPS.Params(N, g, h, z),  FKPS.Comm(h_hat, bytes32(ct)), alpha, bid);
    }
}