// SPDX-License-Identifier: MIT
pragma solidity ^0.8.10;

import "./FKPS.sol";
import "./Pedersen.sol";

<%con_or_lib%> TC {
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
  Params memory pp) <%visibility%> view returns (bool) {
    bool fkps_check = true;
    bool ped_valid = true;

    if (so.fkps_so.message.length >= 32) {
      bytes32 ped_r = bytesToBytes32(so.fkps_so.message, so.fkps_so.message.length-uint(32));
      ped_valid = Pedersen.verify(comm.ped, bid, uint(ped_r), pp.ped_pp);
    }

    fkps_check = FKPS.verOpen(comm.fkps, so.fkps_so, pp.fkps_pp);

    return ped_valid && fkps_check;
  }

  function verForceOpen(Comm memory comm, ForceOpening memory force, bytes memory m, uint bid, 
  Params memory pp) <%visibility%> view returns (bool) {

    require(FKPS.verForceOpen(comm.fkps, force.fkps_fo, pp.fkps_pp));
    bytes memory tc_m = force.fkps_fo.message;
    if (tc_m.length >= 32) {
      uint ped_r = uint(bytesToBytes32(tc_m, tc_m.length-uint(32)));
      bool ped_valid = Pedersen.verify(comm.ped, bid, ped_r, pp.ped_pp);

      if (m.length > 0) {
        return ped_valid && bytesCompare(m, tc_m);
      } else {
        return !ped_valid;
      }
    } 
    else {
      return m.length == 0;
    }
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

  function bytesCompare(bytes memory a, bytes memory b) private pure returns (bool) {
    if (a.length > b.length) return false;
    for (uint i=0; i<a.length; i++) {
      if (a[i] != b[i]) return false; 
    }
    return true;
  }
  
}