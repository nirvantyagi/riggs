// SPDX-License-Identifier: MIT
pragma solidity ^0.8.10;

import "./BigInt.sol";

library RSA2048 {

    struct Element {
        BigInt.BigInt n;
    }

    struct Params {
        Element g;
        BigInt.BigInt m;
    }

    function publicParams() internal pure returns (Params memory pp) {
        pp.g.n = BigInt.from_uint256(2);
        uint256[] memory m_u256_digits = new uint256[](<%pp_m_len%>);
        <%pp_m_populate%>
        pp.m.val = abi.encodePacked(m_u256_digits);
    }

    //function add(Element memory a, Element memory b, Params memory pp)
    //internal view returns (Element memory) {
    //    return Element(BigInt.bn_mod(BigInt.prepare_add(a.n, b.n), pp.m));
    //}

    function op(Element memory a, Element memory b, Params memory pp)
    internal view returns (Element memory) {
        return Element(BigInt.modmul(a.n, b.n, pp.m));
    }

    function power(Element memory base, BigInt.BigInt memory e, Params memory pp)
    internal view returns (Element memory) {
        return Element(BigInt.prepare_modexp(base.n, e, pp.m));
    }

    // returns true iff a==b
    //function cmp(Element memory a, Element memory b, Element memory n)
    //internal view returns (bool) {
    //    // require(a.bn.val.length >= 256);
    //    // require(b.bn.val.length >= 256);
    //    BigNumber.instance memory abn = BigNumber.bn_mod(a.bn, n.bn);
    //    BigNumber.instance memory bbn = BigNumber.bn_mod(b.bn, n.bn);
    //    return BigNumber.cmp(abn, bbn, false) == 0;
    //}

}