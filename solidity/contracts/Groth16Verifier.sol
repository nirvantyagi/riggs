// This file is MIT Licensed.
//
// Copyright 2017 Christian Reitwiessner
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

import "./Pairing.sol";


contract Groth16Verifier {
    using Pairing for *;

    struct VerifyingKey {
        Pairing.G1Point alpha;
        Pairing.G2Point beta;
        Pairing.G2Point gamma;
        Pairing.G2Point delta;
        Pairing.G1Point[] gamma_abc;
    }

    struct Proof {
        Pairing.G1Point a;
        Pairing.G2Point b;
        Pairing.G1Point c;
    }

    function verifyingKey() view public returns (VerifyingKey memory vk) {
        vk.alpha = Pairing.G1Point(<%vk_alpha%>);
        vk.beta = Pairing.G2Point(<%vk_beta%>);
        vk.gamma = Pairing.G2Point(<%vk_gamma%>);
        vk.delta = Pairing.G2Point(<%vk_delta%>);
        vk.gamma_abc = new Pairing.G1Point[](<%vk_gamma_abc_length%>);
        <%vk_gamma_abc_pts%>
    }

    function verify(uint[<%input_length%>] memory input, Proof memory proof) public returns (uint a) {
		
        uint256 snark_scalar_field = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
        
        VerifyingKey memory vk = verifyingKey();
        require(input.length + 1 == vk.gamma_abc.length);
        // Compute the linear combination vk_x
        Pairing.G1Point memory vk_x = Pairing.G1Point(0, 0);

        for (uint i = 0; i < input.length; i++) {
            require(input[i] < snark_scalar_field);

            if (i==0) {
                uint[3] memory input2;
                input2[0] = vk.gamma_abc[i + 1].X;
                input2[1] = vk.gamma_abc[i + 1].Y;
                input2[2] = input[i];
                uint[2] memory output;
                bool success;
                assembly {
                    success := staticcall(gas(), 0x07, input2, 0x80, output, 0x60)
                    // Use "invalid" to make gas estimation work
                    switch success case 0 { invalid() }
                }
                vk_x = Pairing.scalar_mul(vk.gamma_abc[66], 2);
                return 12;
            } else {
                vk_x = Pairing.addition(vk_x, Pairing.scalar_mul(vk.gamma_abc[i + 1], input[i]));
            }
        }

        vk_x = Pairing.addition(vk_x, vk.gamma_abc[0]);
        
        // if(!Pairing.pairingProd4(
        //      proof.a, proof.b,
        //      Pairing.negate(vk_x), vk.gamma,
        //      Pairing.negate(proof.c), vk.delta,
        //      Pairing.negate(vk.alpha), vk.beta)) return 1;
        return 0;
    }

    // function verifyTx(
    //         Proof memory proof<%input_argument%>
    //     ) public view returns (bool r) {
    //     uint[] memory inputValues = new uint[](<%vk_input_length%>);
    //     <%input_loop%>
    //     if (verify(inputValues, proof) == 0) {
    //         return true;
    //     } else {
    //         return false;
    //     }
    // }
}