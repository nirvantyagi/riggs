// SPDX-License-Identifier: MIT
pragma solidity ^0.8.10;

library BN254 {
    // Prime p order of G1
    //uint internal constant P =  21888242871839275222246405745257275088548364400416034343698204186575808495617;
    uint internal constant P =  0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001;
    // Prime q in the base field F_q for G1
    //uint internal constant Q = 21888242871839275222246405745257275088696311157297823662689037894645226208583;
    uint internal constant Q = 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47;

    struct G1Point {
        uint256 X;
        uint256 Y;
    }
    /// @return the negation of p, i.e. p.addition(p.negate()) should be zero.
    function g1negate(G1Point memory p) pure internal returns (G1Point memory) {
        if (p.X == 0 && p.Y == 0)
            return G1Point(0, 0);
        return G1Point(p.X, Q - (p.Y % Q));
    }
    /// @return r the sum of two points of G1
    function g1add(G1Point memory p1, G1Point memory p2) internal view returns (G1Point memory r) {
        uint[4] memory input;
        input[0] = p1.X;
        input[1] = p1.Y;
        input[2] = p2.X;
        input[3] = p2.Y;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 6, input, 0xc0, r, 0x60)
        // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require(success);
    }
    /// @return r the product of a point on G1 and a scalar, i.e.
    /// p == p.scalar_mul(1) and p.addition(p) == p.scalar_mul(2) for all points p.
    function g1mul(G1Point memory p, uint256 s) internal view returns (G1Point memory r) {
        uint[3] memory input;
        input[0] = p.X;
        input[1] = p.Y;
        input[2] = s;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 7, input, 0x80, r, 0x60)
        // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require (success);
    }

    function submod(uint a, uint b) internal pure returns (uint){
        uint a_nn;
        if(a > b) {
            a_nn = a;
        } else {
            a_nn = a + P;
        }
        return addmod(a_nn - b, 0, P);
    }

    // TODO: Inversion algorithm: https://github.com/arkworks-rs/algebra/blob/master/ff/src/fields/models/fp/montgomery_backend.rs#L211:w
    function inverse(uint a) internal view returns (uint){
        return expmod(a, P - 1, P);
    }

    function expmod(uint256 _base, uint256 _exponent, uint256 _modulus) internal view returns (uint256 retval){
        bool success;
        uint256[1] memory output;
        uint[6] memory input;
        input[0] = 0x20;        // baseLen = new(big.Int).SetBytes(getData(input, 0, 32))
        input[1] = 0x20;        // expLen  = new(big.Int).SetBytes(getData(input, 32, 32))
        input[2] = 0x20;        // modLen  = new(big.Int).SetBytes(getData(input, 64, 32))
        input[3] = _base;
        input[4] = _exponent;
        input[5] = _modulus;
        assembly {
            success := staticcall(sub(gas(), 2000), 5, input, 0xc0, output, 0x20)
        // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require(success);
        return output[0];
    }
}


contract BulletproofsVerifier {
    struct Params {
        bytes32 hash;
        BN254.G1Point pedG;
        BN254.G1Point pedH;
        BN254.G1Point[] ipaG;
        BN254.G1Point[] ipaH;
        BN254.G1Point ipaU;
    }

    struct Proof {
        BN254.G1Point commBits;
        BN254.G1Point commBlind;
        BN254.G1Point commLC1;
        BN254.G1Point commLC2;
        uint256 tx;
        uint256 rtx;
        uint256 rAB;
        BN254.G1Point[] commIPAL;
        BN254.G1Point[] commIPAR;
        uint256 baseA;
        uint256 baseB;
    }

    function publicParams() internal pure returns (Params memory pp) {
        pp.hash = <%pp_hash%>;
        pp.pedG = BN254.G1Point(<%ped_pp_g%>);
        pp.pedH = BN254.G1Point(<%ped_pp_h%>);
        pp.ipaU = BN254.G1Point(<%ipa_pp_u%>);
        pp.ipaG = new BN254.G1Point[](<%ipa_pp_len%>);
        pp.ipaH = new BN254.G1Point[](<%ipa_pp_len%>);
        <%ipa_pp_vecs%>
    }

    function verify(BN254.G1Point memory comm, uint64 n, Proof memory proof) public view returns (bytes32) {
        Params memory pp = publicParams();
        bytes32 digest = keccak256(abi.encodePacked(pp.hash, comm.X, comm.Y, n, proof.commBits.X, proof.commBits.Y, proof.commBlind.X, proof.commBlind.Y));
        return digest;
    }

}