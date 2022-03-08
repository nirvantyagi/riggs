// SPDX-License-Identifier: MIT
pragma solidity ^0.8.10;

import "./FKPS.sol";
import "./Pedersen.sol";

library TC {
  using FKPS for *; 
  using Pedersen for *; 

  struct Comm {
    FKPS.Comm fkps;
    BN254.G1Point pc;
  }

  struct Params {
    FKPS.Params fkps_pp;
    Pedersen.Params pc_pp;
  }

  // need PoE Keygen pk, vk
  bytes constant z_bytes = "0x65237841623487152384716253418732654216523784162348715238471625346523784162348715238471625341873265421652378416234871523847162534652378416234871523847162534187326542165237841623487152384716253465237841623487152384716253418732654216523784162348715238471625346523784162348715238471625341873265421652378416234871523847162534652378416234871523847162534187326542165237841623487152384716253465237841623487152384716253418732654216523784162348715238471625346523784162348715238471625341873265421652378416234871523847162534";


  // pp - pedersen 
  bytes constant G_pc = "0x6523784162348715238471625341873265421652378416234871523847162534";
  bytes constant H_pc = "0x6523784162348715238471625341873265421652378416234871523847162535";

  // comm = (h_hat, ct, pc)
  // function _new(bytes memory h_hat, bytes32 ct, uint[2] memory pc) internal pure returns (Comm memory comm) {
  //   comm.fkps = FKPS._new(h_hat, ct);
  //   comm.pc = pc;
  // }

  // proof has b +  alpha for FKPS + r for PC  
  function verOpen(Params memory pp, Comm memory comm, uint256 alpha, uint b, uint r) 
  internal view returns (bool) {
    bool fkps_check = true;
    bool pc_check = true;
    fkps_check = FKPS.verOpen(pp.fkps_pp, comm.fkps, alpha, b);
    // pc_check = Pedersen.verify(pp.pc_pp, comm.pc, b, r);
    return fkps_check && pc_check;
  }
  
}