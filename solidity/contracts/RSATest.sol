// SPDX-License-Identifier: MIT
pragma solidity ^0.8.10;

import "./RSA.sol";

contract RSATest {
    using RSA for *; 

    function testVerifyPower(bytes memory G, bytes memory Y, bytes memory N, uint log) 
    public view returns (bool) {
      RSA.Element memory G_rsa = RSA._new(G);
      RSA.Element memory Y_rsa = RSA._new(Y);
      RSA.Element memory N_rsa = RSA._new(N);
      return RSA.is_equal(Y_rsa, RSA.power(G_rsa, log, N_rsa));
      // return RSA.as_bytes(G_rsa);
    }

    function testPower(bytes memory G, bytes memory Y, bytes memory N, uint log) 
    public view returns (bytes memory) {
      RSA.Element memory G_rsa = RSA._new(G);
      RSA.Element memory Y_rsa = RSA._new(Y);
      RSA.Element memory N_rsa = RSA._new(N);
      // return RSA.as_bytes(RSA.power(G_rsa, log, N_rsa));
    }

    

    function testIdentity(bytes memory G) 
    public view returns (bytes memory) {
      RSA.Element memory G_rsa = RSA._new(G);
      return RSA.as_bytes(G_rsa);
    }


}