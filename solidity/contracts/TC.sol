// SPDX-License-Identifier: MIT
pragma solidity ^0.8.10;

import "./FKPS.sol";
import "./Pedersen.sol";

library TC {
  using FKPS for *; 
  using Pedersen for *; 

  struct Comm {
    FKPS.Comm fkps;
    BN254.G1Point ped;
  }

  struct Params {
    FKPS.Params fkps_pp;
    Pedersen.Params ped_pp;
  }
  
  function publicParams() internal pure returns (Params memory pp) {
    pp.fkps_pp = FKPS.publicParams();
    pp.ped_pp = Pedersen.publicParams();
  }

  // proof has b +  alpha for FKPS + r for PC  
  function verOpen(Comm memory comm, uint256 alpha, uint b, uint r, 
  Params memory pp) internal view returns (bool) {
    bool fkps_check = true;
    bool pc_check = true;
    fkps_check = FKPS.verOpen(comm.fkps, alpha, b, pp.fkps_pp);
    pc_check = Pedersen.verify(comm.ped, b, r, pp.ped_pp);
    return fkps_check && pc_check;
  }
  
}