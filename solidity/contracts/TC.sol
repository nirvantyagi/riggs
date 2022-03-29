// SPDX-License-Identifier: MIT
pragma solidity ^0.8.10;

import "./FKPS.sol";
import "./Pedersen.sol";

library TC {
  using FKPS for *; 
  using Pedersen for *; 

  struct Comm {
    BN254.G1Point ped;
    FKPS.Comm fkps;
  }

  struct Params {
    Pedersen.Params ped_pp;
    FKPS.Params fkps_pp;
  }
  
  struct SelfOpening {
    FKPS.SelfOpening fkps_so;
  }

  struct ForceOpening {
    FKPS.ForceOpening fkps_fo;
  }

  function publicParams() internal pure returns (Params memory pp) {
    pp.fkps_pp = FKPS.publicParams();
    pp.ped_pp = Pedersen.publicParams();
  }
  

  function verOpen(Comm memory comm, SelfOpening memory so, uint bid, 
  Params memory pp) internal view returns (bool) {
    bool fkps_check = true;
    bool pc_check = true;

    bytes32 ped_r = bytesToBytes32(so.fkps_so.message, so.fkps_so.message.length-uint(32));

    pc_check = Pedersen.verify(comm.ped, bid, uint(ped_r), pp.ped_pp);
    fkps_check = FKPS.verOpen(comm.fkps, so.fkps_so, pp.fkps_pp);

    return pc_check && fkps_check;
  }

  function verForceOpen(Comm memory comm, ForceOpening memory tc_fo, uint bid, 
  Params memory pp) internal view returns (bool) {
    bool fkps_check = true;
    bool pc_check = true;

    bytes32 ped_r = bytesToBytes32(tc_fo.fkps_fo.message, tc_fo.fkps_fo.message.length-uint(32));

    pc_check = Pedersen.verify(comm.ped, bid, uint(ped_r), pp.ped_pp);
    fkps_check = FKPS.verForceOpen(comm.fkps, tc_fo.fkps_fo, pp.fkps_pp);
    
    return pc_check && fkps_check;
  }

  // Utility function
  function bytesToBytes32(bytes memory b, uint offset) private pure returns (bytes32) {
    bytes32 out;
    for (uint i = 0; i < 32; i++) {
      if (b.length < offset+i+1) {
        out |= bytes32(bytes1(0) & 0xFF) >> (i * 8);
      } else {
        out |= bytes32(b[offset + i] & 0xFF) >> (i * 8);
      }
    }
    return out;
  }
  
}