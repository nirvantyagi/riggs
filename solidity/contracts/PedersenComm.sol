// SPDX-License-Identifier: MIT

pragma solidity ^0.8.11;

library PedersenComm  {

  struct Params {
    uint GX;
    uint GY;
    uint HX;
    uint HY;
  }

  // Generator coordinate `x` of the EC curve
  uint256 public constant GX = 1;
  // Generator coordinate `y` of the EC curve
  uint256 public constant GY = 2;

  uint256 public constant HX = 20765039372871530718554589730410158162413780974122112544611863764810626751360;
  uint256 public constant HY = 2444183914824638066910831265243126275246160293098948571390980460351548298384;

  // 20765039372871530718554589730410158162413780974122112544611863764810626751360,2444183914824638066910831265243126275246160293098948571390980460351548298384

  function ec_add(uint256[2] memory input_a, uint256[2] memory input_b) internal returns (uint256[2] memory) {
    uint[4] memory input;
    input[0] = input_a[0];
    input[1] = input_a[1];
    input[2] = input_b[0];
    input[3] = input_b[1];
    bool success;
    uint256[2] memory result;
    assembly {
      success := call(not(0), 0x06, 0, input, 128, result, 64)
    }
    require(success, "bn256 addition failed");

    return result;
    //return (result[0], result[1]);
  }

  function ec_multiply(uint256[3] memory input) internal returns (uint256[2] memory) {
    bool success;
    uint256[2] memory result;
    assembly {
      success := call(not(0), 0x07, 0, input, 96, result, 64)
      //success := staticcall(not(0), 0x07, input, 96, result, 64)
    }
    require(success, "elliptic curve multiplication failed");

    return result;
    //return (result[0], result[1]);
  }

  function commit(uint b, uint r) public returns (uint[2] memory) {
    uint[2] memory Gb = ec_multiply([GX, GY, b]);
    uint[2] memory Hr = ec_multiply([HX, HY, r]);
    return ec_add(Gb, Hr);
  }

  function verify(uint[2] memory given, uint b, uint r) public returns (bool) {
    uint[2] memory calc = commit(b, r);
    return given[0]==calc[0] && given[1]==calc[1]; 
  }

} 