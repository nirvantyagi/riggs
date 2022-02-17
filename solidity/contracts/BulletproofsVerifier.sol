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

    function submod(uint256 a, uint256 b) internal pure returns (uint256){
        uint a_nn;
        if(a > b) {
            a_nn = a;
        } else {
            a_nn = a + P;
        }
        return addmod(a_nn - b, 0, P);
    }

    // TODO: Inversion algorithm: https://github.com/arkworks-rs/algebra/blob/master/ff/src/fields/models/fp/montgomery_backend.rs#L211:w
    function inverse(uint256 a) internal view returns (uint256){
        return expmod(a, P - 2, P);
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

    function verify(BN254.G1Point memory comm, Proof memory proof) public view returns (bool) {
        Params memory pp = publicParams();
        uint256[5] memory ch_yzxu;
        uint256[<%ipa_log_len%>] memory ch_recurse;
        {
            bytes32 digest = keccak256(abi.encodePacked(pp.hash, comm.X, comm.Y, uint64(<%ipa_pp_len%>), proof.commBits.X, proof.commBits.Y, proof.commBlind.X, proof.commBlind.Y));
            (uint256 ch_y, uint256 ch_z) = splitHashToScalarChallenges(digest);

            digest = keccak256(abi.encodePacked(digest, proof.commLC1.X, proof.commLC1.Y, proof.commLC2.X, proof.commLC2.Y));
            (uint256 ch_x, ) = splitHashToScalarChallenges(digest);

            digest = keccak256(abi.encodePacked(digest, proof.tx, proof.rtx, proof.rAB));
            (uint256 ch_u, ) = splitHashToScalarChallenges(digest);

            for (uint i = 0; i < <%ipa_log_len%>; i++) {
                digest = keccak256(abi.encodePacked(digest, proof.commIPAL[i].X, proof.commIPAL[i].Y, proof.commIPAR[i].X, proof.commIPAR[i].Y));
                (uint256 ch_x_recurse, ) = splitHashToScalarChallenges(digest);
                ch_recurse[i] = ch_x_recurse;
            }

            digest = keccak256(abi.encodePacked(digest, proof.baseA, proof.baseB));
            (uint256 ch_c, ) = splitHashToScalarChallenges(digest);

            ch_yzxu[0] = ch_y;
            ch_yzxu[1] = ch_z;
            ch_yzxu[2] = ch_x;
            ch_yzxu[3] = ch_u;
            ch_yzxu[4] = ch_c;
        }

        uint256[<%ipa_pp_len%>][3] memory powers;
        {
            uint256[<%ipa_pp_len%>] memory ch_y_powers = scalarPowers(ch_yzxu[0]);
            uint256[<%ipa_pp_len%>] memory ch_y_inv_powers = scalarPowers(BN254.inverse(ch_yzxu[0]));
            uint256[<%ipa_pp_len%>] memory two_powers = scalarPowers(2);
            powers[0] = ch_y_powers;
            powers[1] = ch_y_inv_powers;
            powers[2] = two_powers;
        }

        uint256[<%ipa_final_check_len%>] memory final_check_exps;
        BN254.G1Point[<%ipa_final_check_len%>] memory final_check_bases;

        // Populate IPA exponents and bases
        {
            for (uint i = 0; i < <%ipa_pp_len%>; i++) {
                final_check_bases[i] = pp.ipaG[i];
                final_check_bases[i + <%ipa_pp_len%>] = pp.ipaH[i];
            }
            for (uint i = 0; i < <%ipa_log_len%>; i++) {
                final_check_bases[i + 2*<%ipa_pp_len%>] = proof.commIPAL[i];
                final_check_bases[i + 2*<%ipa_pp_len%> + <%ipa_log_len%>] = proof.commIPAR[i];
            }
            final_check_bases[0 + 2*<%ipa_pp_len%> + 2*<%ipa_log_len%>] = pp.ipaU;
            final_check_bases[1 + 2*<%ipa_pp_len%> + 2*<%ipa_log_len%>] = proof.commBits;
            final_check_bases[2 + 2*<%ipa_pp_len%> + 2*<%ipa_log_len%>] = proof.commBlind;
        }
        {
            final_check_exps[0] = 1;
            final_check_exps[0 + <%ipa_pp_len%>] = 1;
            for (uint i = 0; i < <%ipa_log_len%>; i++) {
                uint256 ch_x = ch_recurse[<%ipa_log_len%> - 1 - i];
                uint256 ch_x_inv = BN254.inverse(ch_recurse[<%ipa_log_len%> - 1 - i]);
                // IPA commitment exponents
                final_check_exps[<%ipa_log_len%> - 1 - i + 2*<%ipa_pp_len%>] = BN254.submod(0, ch_x);
                final_check_exps[<%ipa_log_len%> - 1 - i + 2*<%ipa_pp_len%> + <%ipa_log_len%>] = BN254.submod(0, ch_x_inv);
                for (uint j = 0; j < 2**i; j++) {
                    final_check_exps[(2**i - 1) + j + 1] = mulmod(final_check_exps[j], ch_x_inv, BN254.P);
                    final_check_exps[(2**i - 1) + j + <%ipa_pp_len%> + 1] = mulmod(final_check_exps[j + <%ipa_pp_len%>], ch_x, BN254.P);
                }
            }
            // G and H exponents
            uint256 ch_z_squared = mulmod(ch_yzxu[1], ch_yzxu[1], BN254.P);
            for (uint i = 0; i < <%ipa_pp_len%>; i++) {
                final_check_exps[i] = addmod(mulmod(final_check_exps[i], proof.baseA, BN254.P), ch_yzxu[1], BN254.P);
                final_check_exps[i + <%ipa_pp_len%>] = BN254.submod(mulmod(powers[1][i], BN254.submod(mulmod(final_check_exps[i + <%ipa_pp_len%>], proof.baseB, BN254.P), mulmod(ch_z_squared, powers[2][i], BN254.P)), BN254.P), ch_yzxu[1]);
            }
        }
        {
            final_check_exps[0 + 2*<%ipa_pp_len%> + 2*<%ipa_log_len%>] = BN254.submod(mulmod(mulmod(proof.baseA, proof.baseB, BN254.P), ch_yzxu[3], BN254.P), BN254.submod(mulmod(proof.tx, ch_yzxu[3], BN254.P), proof.rAB));
            final_check_exps[1 + 2*<%ipa_pp_len%> + 2*<%ipa_log_len%>] = BN254.submod(0, 1);
            final_check_exps[2 + 2*<%ipa_pp_len%> + 2*<%ipa_log_len%>] = BN254.submod(0, ch_yzxu[2]);
        }

        // Populate LC exponents and bases
        {
            uint256 ch_z_squared = mulmod(ch_yzxu[1], ch_yzxu[1], BN254.P);
            uint256 ch_z_cubed = mulmod(ch_z_squared, ch_yzxu[1], BN254.P);
            uint256 ch_y_powers_sum;
            uint256 two_powers_sum;
            for (uint i = 0; i < <%ipa_pp_len%>; i++) {
                ch_y_powers_sum = addmod(ch_y_powers_sum, powers[0][i], BN254.P);
                two_powers_sum = addmod(two_powers_sum, powers[2][i], BN254.P);
            }
            uint256 delta = BN254.submod(mulmod(BN254.submod(ch_yzxu[1], ch_z_squared), ch_y_powers_sum, BN254.P), mulmod(two_powers_sum, ch_z_cubed, BN254.P));
            final_check_exps[0 + 2*<%ipa_pp_len%> + 2*<%ipa_log_len%> + 3] = mulmod(BN254.submod(proof.tx, delta), ch_yzxu[4], BN254.P);
            final_check_exps[1 + 2*<%ipa_pp_len%> + 2*<%ipa_log_len%> + 3] = mulmod(proof.rtx, ch_yzxu[4], BN254.P);
            final_check_exps[2 + 2*<%ipa_pp_len%> + 2*<%ipa_log_len%> + 3] = mulmod(BN254.submod(0, ch_z_squared), ch_yzxu[4], BN254.P);
            final_check_exps[3 + 2*<%ipa_pp_len%> + 2*<%ipa_log_len%> + 3] = mulmod(BN254.submod(0, ch_yzxu[2]), ch_yzxu[4], BN254.P);
            final_check_exps[4 + 2*<%ipa_pp_len%> + 2*<%ipa_log_len%> + 3] = mulmod(BN254.submod(0, mulmod(ch_yzxu[2], ch_yzxu[2], BN254.P)), ch_yzxu[4], BN254.P);
        }

        final_check_bases[0 + 2*<%ipa_pp_len%> + 2*<%ipa_log_len%> + 3] = pp.pedG;
        final_check_bases[1 + 2*<%ipa_pp_len%> + 2*<%ipa_log_len%> + 3] = pp.pedH;
        final_check_bases[2 + 2*<%ipa_pp_len%> + 2*<%ipa_log_len%> + 3] = comm;
        final_check_bases[3 + 2*<%ipa_pp_len%> + 2*<%ipa_log_len%> + 3] = proof.commLC1;
        final_check_bases[4 + 2*<%ipa_pp_len%> + 2*<%ipa_log_len%> + 3] = proof.commLC2;

        BN254.G1Point memory out = variableBaseMSM(final_check_bases, final_check_exps);
        return (out.X == 0) && (out.Y == 0);
    }

    function splitHashToScalarChallenges(bytes32 h) internal pure returns (uint256 ch1, uint256 ch2) {
        ch1 += uint256(h) & ((1 << 128) - 1);
        ch2 += (uint256(h) >> 128) & ((1 << 128) - 1);
    }

    function scalarPowers(uint256 s) internal pure returns (uint256[<%ipa_pp_len%>] memory s_powers) {
        uint256 s_pow = 1;
        for (uint i = 0; i < <%ipa_pp_len%>; i++) {
            s_powers[i] = s_pow;
            s_pow = mulmod(s_pow, s, BN254.P);
        }
    }

    function variableBaseMSM(BN254.G1Point[<%ipa_final_check_len%>] memory bases, uint256[<%ipa_final_check_len%>] memory exps) internal view returns (BN254.G1Point memory out) {
        out = BN254.g1mul(bases[0], exps[0]);
        for (uint i = 1; i < <%ipa_final_check_len%>; i++) {
            out = BN254.g1add(out, BN254.g1mul(bases[i], exps[i]));
        }
    }


}