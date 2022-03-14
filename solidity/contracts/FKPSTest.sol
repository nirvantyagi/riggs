// SPDX-License-Identifier: MIT
pragma solidity ^0.8.10;

import "./FKPS.sol";

contract FKPSTest {
    using FKPS for *; 

    function testVerOpen(
      RSA2048.Element memory h_hat,
      bytes memory ct,   
      uint alpha, uint bid) 
    public view returns (bool) {
    //   RSA.Element memory N = RSA._new(hex"<%rsa_n%>");
    //   RSA.Element memory g = RSA._new(hex"<%rsa_g%>");
    //   RSA.Element memory h = RSA._new(hex"<%rsa_h%>");
    //   RSA.Element memory z = RSA._new(hex"<%rsa_z%>");

      return FKPS.verOpen(FKPS.Comm(h_hat, bytes32(ct)), alpha, bid);
    }
}