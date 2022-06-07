// SPDX-License-Identifier: MIT
pragma solidity ^0.8.10;

import "./BabyJubjub.sol";
import "./PedersenBaby.sol";

<%con_or_lib%> BulletproofsVerifier {
    struct Params {
        bytes32 hash;
        PedersenBaby.Params ped_pp;
        BabyJubjub.G1Point[] ipaG;
        BabyJubjub.G1Point[] ipaH;
        BabyJubjub.G1Point ipaU;
    }

    struct Proof {
        BabyJubjub.G1Point commBits;
        BabyJubjub.G1Point commBlind;
        BabyJubjub.G1Point commLC1;
        BabyJubjub.G1Point commLC2;
        uint256 tx;
        uint256 rtx;
        uint256 rAB;
        BabyJubjub.G1Point[] commIPAL;
        BabyJubjub.G1Point[] commIPAR;
        uint256 baseA;
        uint256 baseB;
    }

    function publicParams() internal pure returns (Params memory pp) {
        pp.hash = <%pp_hash%>;
        pp.ped_pp = PedersenBaby.publicParams();
        pp.ipaU = BabyJubjub.G1Point(<%ipa_pp_u%>);
        pp.ipaG = new BabyJubjub.G1Point[](<%ipa_pp_len%>);
        pp.ipaH = new BabyJubjub.G1Point[](<%ipa_pp_len%>);
        <%ipa_pp_vecs%>
    }

    // function variableBaseMSM(BabyJubjub.G1Point[<%ipa_final_check_len%>] memory bases, uint256[<%ipa_final_check_len%>] memory exps) internal view returns (BabyJubjub.G1Point memory out) {
    //     out = BabyJubjub.g1mul(bases[0], exps[0]);
    //     for (uint i = 1; i < <%ipa_final_check_len%>; i++) {
    //         out = BabyJubjub.g1add(out, BabyJubjub.g1mul(bases[i], exps[i]));
    //     }
    // }

    function variableBaseMSM(BabyJubjub.G1Point[<%ipa_final_check_len%>] memory bases, uint256[<%ipa_final_check_len%>] memory exps) internal view returns (BabyJubjub.G1Point memory out) {
       uint c = 5;
       BabyJubjub.G1Point[51] memory window_sums;
       //for (uint window_start = 0; window_start < 254; window_start += c) {
       for (uint j = 0; j < 51; j++) {
           uint window_start = j * c;
           BabyJubjub.G1Point memory res;
           res.X = 0;
           res.Y = 0;
           BabyJubjub.G1Point[32] memory buckets;
           for (uint i = 0; i < <%ipa_final_check_len%>; i++) {
               uint256 scalar = exps[i];
               if ((scalar == 1) && (window_start == 0)) {
                   res = BabyJubjub.g1add(res, bases[i]);
               } else {
                   scalar >>= window_start;
                   scalar %= (1 << c);
                   if (scalar != 0) {
                       buckets[scalar] = BabyJubjub.g1add(buckets[scalar], bases[i]);
                   }
               }
           }
           BabyJubjub.G1Point memory sum;
           sum.X = 0;
           sum.Y = 0;
           for (uint i = 1; i < 32; i++) {
               sum = BabyJubjub.g1add(sum, buckets[32 - i]);
               res = BabyJubjub.g1add(res, sum);
           }
           window_sums[j] = res;
       }
       BabyJubjub.G1Point memory out;
       out.X = 0;
       out.Y = 0;
       for (uint i = 1; i < 51; i++) {
           out = BabyJubjub.g1add(out, window_sums[51 - i]);
           for (uint j = 0; j < c; j++) {
               out = BabyJubjub.g1add(out, out);
           }
       }
       out = BabyJubjub.g1add(out, window_sums[0]);
    }

    function verify(BabyJubjub.G1Point memory comm, Proof memory proof) public view returns (bool) {
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
            uint256[<%ipa_pp_len%>] memory ch_y_inv_powers = scalarPowers(BabyJubjub.inverse(ch_yzxu[0]));
            uint256[<%ipa_pp_len%>] memory two_powers = scalarPowers(2);
            powers[0] = ch_y_powers;
            powers[1] = ch_y_inv_powers;
            powers[2] = two_powers;
        }

        uint256[<%ipa_final_check_len%>] memory final_check_exps;
        BabyJubjub.G1Point[<%ipa_final_check_len%>] memory final_check_bases;

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
                uint256 ch_x_inv = BabyJubjub.inverse(ch_recurse[<%ipa_log_len%> - 1 - i]);
                // IPA commitment exponents
                final_check_exps[<%ipa_log_len%> - 1 - i + 2*<%ipa_pp_len%>] = BabyJubjub.submod(0, ch_x);
                final_check_exps[<%ipa_log_len%> - 1 - i + 2*<%ipa_pp_len%> + <%ipa_log_len%>] = BabyJubjub.submod(0, ch_x_inv);
                for (uint j = 0; j < 2**i; j++) {
                    final_check_exps[(2**i - 1) + j + 1] = mulmod(final_check_exps[j], ch_x_inv, BabyJubjub.P);
                    final_check_exps[(2**i - 1) + j + <%ipa_pp_len%> + 1] = mulmod(final_check_exps[j + <%ipa_pp_len%>], ch_x, BabyJubjub.P);
                }
            }
            // G and H exponents
            uint256 ch_z_squared = mulmod(ch_yzxu[1], ch_yzxu[1], BabyJubjub.P);
            for (uint i = 0; i < <%ipa_pp_len%>; i++) {
                final_check_exps[i] = addmod(mulmod(final_check_exps[i], proof.baseA, BabyJubjub.P), ch_yzxu[1], BabyJubjub.P);
                final_check_exps[i + <%ipa_pp_len%>] = BabyJubjub.submod(mulmod(powers[1][i], BabyJubjub.submod(mulmod(final_check_exps[i + <%ipa_pp_len%>], proof.baseB, BabyJubjub.P), mulmod(ch_z_squared, powers[2][i], BabyJubjub.P)), BabyJubjub.P), ch_yzxu[1]);
            }
        }
        {
            final_check_exps[0 + 2*<%ipa_pp_len%> + 2*<%ipa_log_len%>] = BabyJubjub.submod(mulmod(mulmod(proof.baseA, proof.baseB, BabyJubjub.P), ch_yzxu[3], BabyJubjub.P), BabyJubjub.submod(mulmod(proof.tx, ch_yzxu[3], BabyJubjub.P), proof.rAB));
            final_check_exps[1 + 2*<%ipa_pp_len%> + 2*<%ipa_log_len%>] = BabyJubjub.submod(0, 1);
            final_check_exps[2 + 2*<%ipa_pp_len%> + 2*<%ipa_log_len%>] = BabyJubjub.submod(0, ch_yzxu[2]);
        }

        // Populate LC exponents and bases
        {
            uint256 ch_z_squared = mulmod(ch_yzxu[1], ch_yzxu[1], BabyJubjub.P);
            uint256 ch_z_cubed = mulmod(ch_z_squared, ch_yzxu[1], BabyJubjub.P);
            uint256 ch_y_powers_sum;
            uint256 two_powers_sum;
            for (uint i = 0; i < <%ipa_pp_len%>; i++) {
                ch_y_powers_sum = addmod(ch_y_powers_sum, powers[0][i], BabyJubjub.P);
                two_powers_sum = addmod(two_powers_sum, powers[2][i], BabyJubjub.P);
            }
            uint256 delta = BabyJubjub.submod(mulmod(BabyJubjub.submod(ch_yzxu[1], ch_z_squared), ch_y_powers_sum, BabyJubjub.P), mulmod(two_powers_sum, ch_z_cubed, BabyJubjub.P));
            final_check_exps[0 + 2*<%ipa_pp_len%> + 2*<%ipa_log_len%> + 3] = mulmod(BabyJubjub.submod(proof.tx, delta), ch_yzxu[4], BabyJubjub.P);
            final_check_exps[1 + 2*<%ipa_pp_len%> + 2*<%ipa_log_len%> + 3] = mulmod(proof.rtx, ch_yzxu[4], BabyJubjub.P);
            final_check_exps[2 + 2*<%ipa_pp_len%> + 2*<%ipa_log_len%> + 3] = mulmod(BabyJubjub.submod(0, ch_z_squared), ch_yzxu[4], BabyJubjub.P);
            final_check_exps[3 + 2*<%ipa_pp_len%> + 2*<%ipa_log_len%> + 3] = mulmod(BabyJubjub.submod(0, ch_yzxu[2]), ch_yzxu[4], BabyJubjub.P);
            final_check_exps[4 + 2*<%ipa_pp_len%> + 2*<%ipa_log_len%> + 3] = mulmod(BabyJubjub.submod(0, mulmod(ch_yzxu[2], ch_yzxu[2], BabyJubjub.P)), ch_yzxu[4], BabyJubjub.P);
        }

        final_check_bases[0 + 2*<%ipa_pp_len%> + 2*<%ipa_log_len%> + 3] = pp.ped_pp.G;
        final_check_bases[1 + 2*<%ipa_pp_len%> + 2*<%ipa_log_len%> + 3] = pp.ped_pp.H;
        final_check_bases[2 + 2*<%ipa_pp_len%> + 2*<%ipa_log_len%> + 3] = comm;
        final_check_bases[3 + 2*<%ipa_pp_len%> + 2*<%ipa_log_len%> + 3] = proof.commLC1;
        final_check_bases[4 + 2*<%ipa_pp_len%> + 2*<%ipa_log_len%> + 3] = proof.commLC2;

        BabyJubjub.G1Point memory out = variableBaseMSM(final_check_bases, final_check_exps);
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
            s_pow = mulmod(s_pow, s, BabyJubjub.P);
        }
    }

}