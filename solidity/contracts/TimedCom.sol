pragma solidity 0.8.11;

import "./FKPS.sol";
import "./PedersenComm.sol";

library TCPi {
  using FKPS for *; 
  using PedersenComm for *; 

  struct Comm {
    FKPS.Comm fkps;
    uint[2] pc;
  }

  struct Params {
    FKPS.Params pp_fkps;
    PedersenComm.Params pp_ped;
  }

  // need PoE Keygen pk, vk
  bytes constant z_bytes = "0x65237841623487152384716253418732654216523784162348715238471625346523784162348715238471625341873265421652378416234871523847162534652378416234871523847162534187326542165237841623487152384716253465237841623487152384716253418732654216523784162348715238471625346523784162348715238471625341873265421652378416234871523847162534652378416234871523847162534187326542165237841623487152384716253465237841623487152384716253418732654216523784162348715238471625346523784162348715238471625341873265421652378416234871523847162534";


  // pp - pedersen 
  bytes constant G_pc = "0x6523784162348715238471625341873265421652378416234871523847162534";
  bytes constant H_pc = "0x6523784162348715238471625341873265421652378416234871523847162535";

  // comm = (h_hat, ct, pc)
  function _new(bytes memory h_hat, bytes32 ct, uint[2] memory pc) internal pure returns (Comm memory comm) {
    comm.fkps = FKPS._new(h_hat, ct);
    comm.pc = pc;
  }

  // proof has b +  alpha for FKPS + r for PC  
  function verOpen(Comm memory comm, uint256 alpha, uint b, uint r) 
  internal returns (bool) {
    bool fkps_check = FKPS.verOpen(comm.fkps, alpha, b);
    bool pc_check = PedersenComm.verify(comm.pc, b, r);
    return fkps_check && pc_check;
  }
  
}