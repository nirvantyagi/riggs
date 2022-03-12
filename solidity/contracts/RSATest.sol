// SPDX-License-Identifier: MIT
pragma solidity ^0.8.10;

import "./RSA2048.sol";
import "./BigInt.sol";

contract RSATest {
    using RSA2048 for *; 
    using BigInt for *; 

    function testVerify(
      RSA2048.Element memory X, uint256 e, RSA2048.Element memory Y)
    public view returns (bool) {
      RSA2048.Params memory pp = RSA2048.publicParams();
      return RSA2048.eq(Y, RSA2048.reduce(RSA2048.power(X, BigInt.from_uint256(e), pp), pp));
    }

    function testIdentity(
      RSA2048.Element memory X, uint256 e, RSA2048.Element memory Y)
    public view returns (bool){
      RSA2048.Params memory pp = RSA2048.publicParams();
      return RSA2048.eq(Y, RSA2048.power(X, BigInt.from_uint256(e), pp));
    }


}