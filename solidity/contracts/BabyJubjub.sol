pragma solidity ^0.8.10;


library BabyJubjub {
    struct G1Point {
        uint256 X;
        uint256 Y;
    }

    // Curve parameters
    // E: 168700x^2 + y^2 = 1 + 168696x^2y^2
    // A = 168700
    uint256 public constant A = 0x292FC;
    // D = 168696 
    uint256 public constant D = 0x292F8;
    // Prime Q = 21888242871839275222246405745257275088548364400416034343698204186575808495617
    uint256 public constant Q = 0x30644E72E131A029B85045B68181585D2833E84879B9709143E1F593F0000001;

    uint256 public constant P = 0x30644E72E131A029B85045B68181585D2833E84879B9709143E1F593F0000001;

    function g1negate(G1Point memory p) internal view returns (G1Point memory) {
        if (p.X == 0 && p.Y == 0)
            return G1Point(0, 0);
        return G1Point(p.X, Q - (p.Y % Q));
    }
    
    function g1add(G1Point memory p1, G1Point memory p2) internal view returns (G1Point memory r) {
        
        (uint256 _x1, uint256 _y1, uint256 _x2, uint256 _y2) = (p1.X, p1.Y, p2.X, p2.Y);

        if (_x1 == 0 && _y1 == 0) {
            return G1Point(_x2, _y2);
        }

        if (_x2 == 0 && _y1 == 0) {
            return G1Point(_x1, _y1);
        }

        uint256 x1x2 = mulmod(_x1, _x2, Q);
        uint256 y1y2 = mulmod(_y1, _y2, Q);
        uint256 dx1x2y1y2 = mulmod(D, mulmod(x1x2, y1y2, Q), Q);
        uint256 x3Num = addmod(mulmod(_x1, _y2, Q), mulmod(_y1, _x2, Q), Q);
        uint256 y3Num = submod(y1y2, mulmod(A, x1x2, Q), Q);

        r.X = mulmod(x3Num, inverse(addmod(1, dx1x2y1y2, Q)), Q);
        r.Y = mulmod(y3Num, inverse(submod(1, dx1x2y1y2, Q)), Q);
    }

    // /**
    //  * @dev Double a point on baby jubjub curve
    //  * Doubling can be performed with the same formula as addition
    //  */
    function g1double(G1Point memory p) internal view returns (G1Point memory) {
        return g1add(p, p);
    }

    
    function g1mul(G1Point memory _p, uint256 _d) internal view returns (G1Point memory output) {

        (uint _x1, uint _y1) = (_p.X, _p.Y);

        uint256 remaining = _d;

        G1Point memory a = G1Point(0,0);
        G1Point memory p = _p;

        while (remaining != 0) {
            if ((remaining & 1) != 0) {
                // Binary digit is 1 so add
                p = g1add(a, p);
            }

            p = g1double(p);

            remaining = remaining / 2;
        }

        output = a;
    }

    // /**
    //  * @dev Check if a given point is on the curve
    //  * (168700x^2 + y^2) - (1 + 168696x^2y^2) == 0
    //  */
    // function isOnCurve(uint256 _x, uint256 _y) internal pure returns (bool) {
    //     uint256 xSq = mulmod(_x, _x, Q);
    //     uint256 ySq = mulmod(_y, _y, Q);
    //     uint256 lhs = addmod(mulmod(A, xSq, Q), ySq, Q);
    //     uint256 rhs = addmod(1, mulmod(mulmod(D, xSq, Q), ySq, Q), Q);
    //     return submod(lhs, rhs, Q) == 0;
    // }

    // /**
    //  * @dev Perform modular subtraction
    //  */
    function submod(uint256 _a, uint256 _b, uint256 _mod) internal pure returns (uint256) {
        uint256 aNN = _a;

        if (_a <= _b) {
            aNN += _mod;
        }

        return addmod(aNN - _b, 0, _mod);
    }

    function submod(uint256 _a, uint256 _b) internal pure returns (uint256) {
        uint256 aNN = _a;

        if (_a <= _b) {
            aNN += Q;
        }

        return addmod(aNN - _b, 0, Q);
    }
    

    /**
     * @dev Compute modular inverse of a number
     */
    function inverse(uint256 _a) internal view returns (uint256) {
        // We can use Euler's theorem instead of the extended Euclidean algorithm
        // Since m = Q and Q is prime we have: a^-1 = a^(m - 2) (mod m)
        return expmod(_a, Q - 2, Q);
    }

    /**
     * @dev Helper function to call the bigModExp precompile
     */
    function expmod(uint256 _b, uint256 _e, uint256 _m) internal view returns (uint256 o) {
        assembly {
            let memPtr := mload(0x40)
            mstore(memPtr, 0x20) // Length of base _b
            mstore(add(memPtr, 0x20), 0x20) // Length of exponent _e
            mstore(add(memPtr, 0x40), 0x20) // Length of modulus _m
            mstore(add(memPtr, 0x60), _b) // Base _b
            mstore(add(memPtr, 0x80), _e) // Exponent _e
            mstore(add(memPtr, 0xa0), _m) // Modulus _m

            // The bigModExp precompile is at 0x05
            let success := staticcall(gas(), 0x05, memPtr, 0xc0, memPtr, 0x20)
            switch success
            case 0 {
                revert(0x0, 0x0)
            } default {
                o := mload(memPtr)
            }
        }
    }
}