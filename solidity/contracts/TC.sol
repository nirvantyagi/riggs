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
  
  struct SelfOpening {
    FKPS.SelfOpening fkps_so;
    // bytes tc_m;
  }

  struct ForceOpening {
    FKPS.ForceOpening fkps_fo;
    // bytes tc_m;
  }

  function publicParams() internal pure returns (Params memory pp) {
    pp.fkps_pp = FKPS.publicParams();
    pp.ped_pp = Pedersen.publicParams();
  }

  // // proof has b +  alpha for FKPS + r for PC  
  // function verOpen(Comm memory comm, uint256 alpha, bytes memory tc_m, uint bid, uint r, 
  // Params memory pp) internal view returns (bool) {
  //   bool fkps_check = true;
  //   bool pc_check = true;
    
  //   pc_check = Pedersen.verify(comm.ped, bid, r, pp.ped_pp);

  //   fkps_check = FKPS.verOpen(comm.fkps, alpha, tc_m, pp.fkps_pp);
    
  //   return pc_check && fkps_check;
  // }

  function verOpen(Comm memory comm, SelfOpening memory so, uint bid, uint r, 
  Params memory pp) internal view returns (bool) {
    bool fkps_check = true;
    bool pc_check = true;
    
    pc_check = Pedersen.verify(comm.ped, bid, r, pp.ped_pp);

    fkps_check = FKPS.verOpen(comm.fkps, so.fkps_so, pp.fkps_pp);
    
    return pc_check && fkps_check;
  }

  function verForceOpen(Comm memory comm, RSA2048.Element memory z_hat, 
  FKPS.Proof memory poe_proof, bytes memory tc_m, uint bid, uint r, 
  Params memory pp) internal view returns (bool) {
    bool fkps_check = true;
    bool pc_check = true;
    
    pc_check = Pedersen.verify(comm.ped, bid, r, pp.ped_pp);

    fkps_check = FKPS.verForceOpen(comm.fkps, z_hat, poe_proof, tc_m, pp.fkps_pp);
    
    return pc_check && fkps_check;
  }
  
}