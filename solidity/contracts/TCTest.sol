// SPDX-License-Identifier: MIT
pragma solidity ^0.8.10;

import "./TC.sol";

contract TCTest {
  using TC for *;

  function testVerOpen(TC.Comm memory tc_comm, TC.SelfOpening memory tc_so, uint bid) 
  public view returns (bool) {
    TC.Params memory pp = TC.publicParams();
    return TC.verOpen(tc_comm, tc_so, bid, pp);
  }

  function testVerForceOpen(TC.Comm memory tc_comm, TC.ForceOpening memory tc_fo, uint bid) 
  public view returns (bool) {
    TC.Params memory pp = TC.publicParams();
    return TC.verForceOpen(tc_comm,tc_fo, bid, pp);
  }
}