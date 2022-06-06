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

  struct PartialParams {
    RSA2048.Element h; 
    RSA2048.Element z;
    uint64 t;
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

  function publicParams(PartialParams memory partial_params) internal pure returns (Params memory pp) {
    pp.fkps_pp = FKPS.publicParams();
    pp.fkps_pp.h = partial_params.h;
    pp.fkps_pp.z = partial_params.z;
    pp.fkps_pp.t = partial_params.t;
    pp.ped_pp = Pedersen.publicParams();
  }

  function verOpen(Comm memory comm, SelfOpening memory opening, uint256 m, Params memory pp) public view returns (bool) {
    bool fkps_check = FKPS.verOpen(comm.fkps, opening.fkps_so, pp.fkps_pp);
    if (!fkps_check) { return false; }
    return verOpenPedersenHelper(comm, opening.fkps_so.message, m, pp);
  }

  function verForceOpen(Comm memory comm, ForceOpening memory opening, uint256 m, Params memory pp) public view returns (bool) {
    bool fkps_check = FKPS.verForceOpen(comm.fkps, opening.fkps_fo, pp.fkps_pp);
    if (!fkps_check) { return false; }
    if (opening.fkps_fo.message.length == 0) {
      // if FKPS opens to empty, TC opens to empty
      return (m == 0);
    }
    return verOpenPedersenHelper(comm, opening.fkps_fo.message, m, pp);
  }

  function verOpenPedersenHelper(Comm memory comm, bytes memory fkps_m, uint256 m, Params memory pp) internal view returns (bool) {
    // check Pedersen commitment
    bytes32 ped_r = FKPS.bytes_to_bytes32(FKPS.bytes_slice(fkps_m, fkps_m.length - 32, fkps_m.length));
    bool ped_valid = Pedersen.verify(comm.ped, m, uint(ped_r), pp.ped_pp);
    if (!ped_valid) {
      // if Pedersen opening fails, TC opens to empty
      return (m == 0);
    } else {
      // if Pedersen opening succeeds, verify FKPS message matches claimed message
      bool check_len = (fkps_m.length <= 64);
      bool check_eq = (keccak256(abi.encodePacked(reverse(m))) == keccak256(abi.encodePacked(FKPS.bytes_slice(fkps_m, 0, fkps_m.length - 32), new bytes(64 - fkps_m.length))));
      return (check_len && check_eq);
    }
  }

  function reverse(uint256 input) internal pure returns (uint256 v) {
    v = input;
    v = ((v & 0xFF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00) >> 8) |
    ((v & 0x00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF) << 8);

    // swap 2-byte long pairs
    v = ((v & 0xFFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000) >> 16) |
    ((v & 0x0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF) << 16);

    // swap 4-byte long pairs
    v = ((v & 0xFFFFFFFF00000000FFFFFFFF00000000FFFFFFFF00000000FFFFFFFF00000000) >> 32) |
    ((v & 0x00000000FFFFFFFF00000000FFFFFFFF00000000FFFFFFFF00000000FFFFFFFF) << 32);

    v = ((v & 0xFFFFFFFFFFFFFFFF0000000000000000FFFFFFFFFFFFFFFF0000000000000000) >> 64) |
    ((v & 0x0000000000000000FFFFFFFFFFFFFFFF0000000000000000FFFFFFFFFFFFFFFF) << 64);

    // swap 16-byte long pairs
    v = (v >> 128) | (v << 128);
  }
}