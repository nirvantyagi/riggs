// SPDX-License-Identifier: MIT
pragma solidity ^0.8.10;

import "./BabyJubjub.sol";

<%con_or_lib%> PedersenBaby  {
  using BabyJubjub for *;

  struct Params {
    BabyJubjub.G1Point G;
    BabyJubjub.G1Point H;
  }

  struct Comm {
    BabyJubjub.G1Point g;
  }

  function publicParams() internal pure returns (Params memory pp) {
    pp.G = BabyJubjub.G1Point(<%ped_pp_g%>);
    pp.H = BabyJubjub.G1Point(<%ped_pp_h%>);
    // pp.G = BabyJubjub.G1Point(0x0E90634C730FBCF748634693EC43A48C3A1C0933EC74F29D81015044227F75B7, 0x03568B5169A77577FCE40E6762FA06DB756174BC19C423F89CE0213A771996D8);
    // pp.H = BabyJubjub.G1Point(0x1288AAE6210DACE9C44A742EE3E34637F8E3B341320FB31AF16C19156D75AB66, 0x039CFC782EC96FB94E6375591AF5BA6D3552F826F50BFECE6E4E53170C013351);
  }

  function commit(uint256 b, uint256 r, Params memory pp) internal view returns (BabyJubjub.G1Point memory) {
    return BabyJubjub.g1add(BabyJubjub.g1mul(pp.G, b), BabyJubjub.g1mul(pp.H, r));
  }

  function verify(BabyJubjub.G1Point memory given, uint256 b, uint256 r, Params memory pp)
  <%visibility%>  view returns (bool) {
    BabyJubjub.G1Point memory calc = commit(b, r, pp);
    return given.X==calc.X && given.Y==calc.Y; 
  }

}