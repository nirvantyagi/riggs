// SPDX-License-Identifier: MIT
pragma solidity ^0.8.10;

import "./BigInt.sol";
import "./RSA2048.sol";

contract PoEVerifier {
    using RSA2048 for *;

    struct PocklingtonStep {
        BigInt.BigInt f;
        uint32 n;
        uint32 n2;
        BigInt.BigInt a;
        BigInt.BigInt bu;
        BigInt.BigInt bv;
    }

    struct PocklingtonCertificate {
        PocklingtonStep[] steps;
        uint32 nonce;
    }

    function verify(uint256 exp) public view returns (bytes memory) {
        RSA2048.Params memory pp = RSA2048.publicParams();
        RSA2048.Element memory out = pp.g.power(BigInt.from_uint256(exp), pp);
        return abi.encodePacked(out.n.val);
    }

    function verifyHashToPrime(bytes memory) public view returns (bool) {
        return true;
    }

    // Hashes to 277 bit integer (277 bit is what is needed for 256 bits of entropy)
    function hashToBigInt(bytes memory input) private view returns (BigInt.BigInt memory h) {
        uint256 h1 = uint256(keccak256(abi.encodePacked(input, uint32(0))));
        uint256 h2 = uint256(keccak256(abi.encodePacked(input, uint32(1))));
    }


}