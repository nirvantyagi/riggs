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
      return RSA.cmp(Y_rsa, RSA.power(G_rsa, log, N_rsa), N_rsa);
      // return RSA.as_bytes(G_rsa);
    }

    function testPowerInt(bytes memory G, bytes memory Y, bytes memory N, uint log) 
    public view returns (uint) {
      RSA.Element memory G_rsa = RSA._new(G);
      RSA.Element memory Y_rsa = RSA._new(Y);
      RSA.Element memory N_rsa = RSA._new(N);
      return Y_rsa.bn.bitlen;
      // return RSA.as_bytes(G_rsa);
    }

    function testPower(bytes memory G, bytes memory Y, bytes memory N, uint log) 
    public view returns (bytes memory) {
      RSA.Element memory G_rsa = RSA._new(G);
      RSA.Element memory Y_rsa = RSA._new(Y);
      RSA.Element memory N_rsa = RSA._new(N);
      // return RSA.as_bytes(RSA.power(G_rsa, log, N_rsa));
      return RSA.power(G_rsa, log, N_rsa).bn.val;
    }

    function returnTrue(bytes memory G) 
    public view returns (bool) {
      // RSA.Element memory G_rsa = RSA._new(G);
      return true;
    }

    

    function testIdentity(bytes memory G) 
    public view returns (bytes memory) {
      RSA.Element memory G_rsa = RSA._new(G);
      return hex"1212121212121212";
    }


}