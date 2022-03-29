// SPDX-License-Identifier: MIT
pragma solidity ^0.8.10;

import "./FKPS.sol";
contract FKPSTest {
    using FKPS for *;
    
    function testVerOpen(FKPS.Comm memory fkps_comm, 
    FKPS.SelfOpening memory sopen) 
    public view returns (bool) {
      FKPS.Params memory pp = FKPS.publicParams();
      return FKPS.verOpen(fkps_comm, sopen, pp);
    }

    function testVerForceOpen(FKPS.Comm memory fkps_comm, 
    FKPS.ForceOpening memory fkps_force) 
    public returns (bool) {
      FKPS.Params memory pp = FKPS.publicParams();
      return FKPS.verForceOpen(fkps_comm, fkps_force, pp);
    }
}



