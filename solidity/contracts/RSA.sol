// SPDX-License-Identifier: MIT
pragma solidity ^0.8.10;

import "./BigNumber.sol";

library RSA {
    using BigNumber for *; 

    struct Element {
        BigNumber.instance bn;
    }

    struct Modulus {
        uint bitlength;
        Element N;
    }

    function _new(bytes memory val) 
    internal pure returns (Element memory) {
        bytes memory full_bytes = new bytes(256);
        uint i=0;
        while (i+val.length < 256) {
            full_bytes[i] = 0;
            i = i+1;
        }
        uint j=0;
        while (j<val.length) {
            full_bytes[i+j] = val[j];
            j=j+1;
        }
        BigNumber.instance memory bni = BigNumber.instance(full_bytes, false, 2048);
        Element memory ret = Element(bni);
        return ret;
    }

    function _modulus(bytes memory n, uint bitlength) 
    internal pure returns (Modulus memory) {
        return Modulus(bitlength, _new(n));
    }

    function zero() 
    internal pure returns (Element memory) {
        BigNumber.instance memory bni = BigNumber.instance(hex"0000000000000000000000000000000000000000000000000000000000000000",false,2048); 
        Element memory ret = Element(bni);
        return ret;
    }

    function one() 
    internal pure returns (Element memory) {
        BigNumber.instance memory bni = BigNumber.instance(hex"0000000000000000000000000000000000000000000000000000000000000001",false,2048); 
        Element memory ret = Element(bni);
        return ret;
    }

    function two() 
    internal pure returns (Element memory) {
        BigNumber.instance memory bni = BigNumber.instance(hex"0000000000000000000000000000000000000000000000000000000000000002",false,2048); 
        Element memory ret = Element(bni);
        return ret;
    }

    function as_bytes(Element memory a) 
    internal pure returns (bytes memory) {
        bytes memory full_bytes = new bytes(256);
        uint i=0;
        while (i+a.bn.val.length < 256) {
            full_bytes[i] = 0;
            i = i+1;
        }
        uint j=0;
        while (j<a.bn.val.length) {
            full_bytes[i+j] = a.bn.val[j];
            j=j+1;
        }
        return full_bytes;
        // return a.bn.val;
    }

    // //   function mul(Element memory a, uint b, Element memory modulus) 
    // //   internal view returns (Element memory) {
    // //       Element memory b_elem = _new(abi.encodePacked(b));
    // //       return Element((a.bn).modmul(b_elem.bn, modulus.bn));
    // //   }

    // function mul(Element memory a, Element memory b, Element memory modulus) 
    // internal view returns (Element memory) {
    //     return Element(BigNumber.modmul(a.bn, b.bn, modulus.bn));
    //     //return Element((a.bn).modmul(b.bn, modulus.bn));
    // }

    function add(Element memory a, Element memory b, Element memory modulus) 
    internal view returns (Element memory) {
        Element memory a_plus_b_unmod = Element(BigNumber.prepare_add(a.bn, b.bn));
        return Element(BigNumber.bn_mod(a_plus_b_unmod.bn, modulus.bn));
    }

    // right-shifts byte array by 1 bit
    // assumes big-endian
    function halve(Element memory a) internal pure returns (Element memory) {
        bool carryover = false;
        for (uint i=0; i<a.bn.val.length; i++) {
            a.bn.val[i] = a.bn.val[i];
            if (carryover) {
                carryover = (uint8(a.bn.val[i]) % 2) == 0;
                a.bn.val[i] = bytes1(uint8(a.bn.val[i])>>1 + uint8(8));
            } else {
                carryover = (uint8(a.bn.val[i]) % 2) == 0;
                a.bn.val[i] = bytes1(uint8(a.bn.val[i])>>1);
            }
        }
        return a;
    }


    // compute mul as (a+b)^2 = a^2 + b^2 + 2ab  mod N
    // --> 2ab = (a+b)^2 -a^2 -b^2 mod N
    function new_mul(Element memory a, Element memory b, Element memory n) 
    internal view returns (Element memory) {
        // (a+b)^2 % n
        Element memory a_plus_b_unmod = Element(BigNumber.prepare_add(a.bn, b.bn));
        Element memory a_plus_b = Element(BigNumber.bn_mod(a_plus_b_unmod.bn, n.bn));
        Element memory a_plus_b_sq = RSA.power(a_plus_b, 2, n);

        // a^2 + b^2 % n
        Element memory a_sq = RSA.power(a, 2, n);
        Element memory b_sq = RSA.power(b, 2, n);
        Element memory asq_plus_bsq = add(a_sq, b_sq, n);

        // -(a^2 + b^2) % n
        Element memory neg_asq_plus_bsq = Element(BigNumber.prepare_sub(n.bn, asq_plus_bsq.bn));

        // (a+b)^2 -(a^2 + b^2) % n ---> equals 2ab
        Element memory two_ab = add(a_plus_b_sq, neg_asq_plus_bsq, n);

        // right-shift 2ab ---> ab
        Element memory ab = halve(two_ab);
        return ab;
    }

    // when e is uint256
    function power(Element memory base, uint e, Element memory modulus) 
    internal view returns (Element memory) {
        Element memory e_elem = _new(abi.encodePacked(e));
        return Element((base.bn).prepare_modexp(e_elem.bn, modulus.bn));
    }

    // when e is RSA.Element
    function power(Element memory base, Element memory exponent, Element memory modulus) 
    internal view returns (Element memory) {
        return Element((base.bn).prepare_modexp(exponent.bn, modulus.bn));
    }

    // when base is bytes[] array
    function power_bytes(bytes memory base, uint256 exponent, bytes memory modulus) 
    internal view returns (Element memory) {
        return power(_new(base), exponent, _new(modulus));
        //   return Element((base.bn).prepare_modexp(exponent.bn, modulus.bn));
    }

    // returns true iff a==b
    function is_equal(Element memory a, Element memory b) 
    internal pure returns (bool) {
        uint a_len = a.bn.val.length;
        uint b_len = b.bn.val.length;

        uint ml = a_len;
        if (a_len > b_len) {
            ml = b_len;
        }  

        for (uint i=0; i< ml; i++) {
            if (a.bn.val[a_len-1-i] != b.bn.val[b_len-1-i]) return false;
        }
        if (a_len > b_len) {
            for (uint i=b_len; i<a_len; i++) {
                if (a.bn.val[a_len-1-i] != 0) return false;
            }
        } else if (a_len < b_len) {
            for (uint i=a_len; i<b_len; i++) {
                if (b.bn.val[b_len-1-i] != 0) return false;
            }
        }
        return true;
    }

    // returns true iff a==b
    // function cmp(Element memory a, Element memory b) 
    // internal pure returns (bool) {
    //     return BigNumber.cmp(a.bn, b.bn, false) == 0;
    // }

}