pragma solidity 0.8.11;

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
        BigNumber.instance memory bni = BigNumber.instance(val, false, 2048);
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
        return a.bn.val;
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
        for (uint i=0; i<a.bn.val.length; i++) {
            if (a.bn.val[i] != b.bn.val[i]) return false;
        }
        return true;
    }

}