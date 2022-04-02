// SPDX-License-Identifier: MIT
pragma solidity ^0.8.10;

import "./BigInt.sol";

<%con_or_lib%> RSA2048 {

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

    function op(Element memory a, Element memory b, Params memory pp)
    internal view returns (Element memory) {
        return Element(BigInt.modmul(a.n, b.n, pp.m));
    }

    // when e is uint256
    function power(Element memory base, uint256 e, Params memory pp)
    internal view returns (Element memory) {
        return power(base, BigInt.from_uint256(e), pp);
    }

    function power(Element memory base, BigInt.BigInt memory e, Params memory pp)
    internal view returns (Element memory) {
        return Element(BigInt.prepare_modexp(base.n, e, pp.m));
    }

    function power_and_reduce(Element memory base, uint256 e, Params memory pp)
    internal view returns (Element memory) {
        return reduce(power(base, e, pp), pp);
    }


    // Reduce to canonical form
    function reduce(Element memory elmt, Params memory pp)
    internal view returns (Element memory out) {
        BigInt.BigInt memory a = BigInt.bn_mod(elmt.n, pp.m);
        BigInt.BigInt memory ma = BigInt.prepare_sub(pp.m, a);
        if (BigInt.cmp(a, ma, false) == 1) { // a > ma
            out.n = ma;
        } else {
            out.n = a;
        }
    }

    // Compare two RSA elements in canonical form
    function eq(Element memory a, Element memory b)
    internal view returns (bool) {
        return BigInt.cmp(a.n, b.n, false) == 0;
    }

    // function to test if X^e == Y
    function verify(RSA2048.Element memory X, uint256 e, RSA2048.Element memory Y, Params memory pp)
    <%visibility%> view returns (bool) {
      return RSA2048.eq(Y, RSA2048.reduce(RSA2048.power(X, BigInt.from_uint256(e), pp), pp));
    }

}