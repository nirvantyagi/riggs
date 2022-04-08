// SPDX-License-Identifier: MIT
pragma solidity ^0.8.10;

import "./RSA2048.sol";
import "./PoEVerifier.sol";

<%con_or_lib%> FKPS {
  using RSA2048 for *; 

  struct Params {
    RSA2048.Params rsa_pp;
    RSA2048.Element h;
    RSA2048.Element z;
    uint32 t;
  }

  struct Comm {
    RSA2048.Element h_hat;    
    bytes ct;
  }

  struct SelfOpening {
    uint256 alpha;
    bytes message;
  }

  struct ForceOpening {
    RSA2048.Element z_hat;
    PoEVerifier.Proof poe_proof;
    bytes message;
  }

  function publicParams() internal pure returns (Params memory pp) {
    pp.rsa_pp = RSA2048.publicParams();
    pp.t = <%pp_time%>;

    uint256[] memory h_u256_digits = new uint256[](<%pp_m_len%>);
    <%pp_h_populate%>
    pp.h.n.val = abi.encodePacked(h_u256_digits);
    
    uint256[] memory z_u256_digits = new uint256[](<%pp_m_len%>);
    <%pp_z_populate%>
    pp.z.n.val = abi.encodePacked(z_u256_digits);
  }

  function verOpen(Comm memory comm, SelfOpening memory self_opening, Params memory pp) 
  <%visibility%> view returns (bool) {
    uint alpha = self_opening.alpha;
    bytes memory message = self_opening.message; 

    // Compute z_hat = z ^ a
    RSA2048.Element memory z_hat = RSA2048.power_and_reduce(pp.z, alpha, pp.rsa_pp);

    // Obtain key as k = H(z_hat)
    bytes32 k = keccak256(z_hat.n.val);

    // Decrypt ciphertext
    (bool ok, bytes memory pt) = decrypt(k, comm.ct, pp.t);

    // Check h^alpha
    RSA2048.Element memory h_hat = RSA2048.power_and_reduce(pp.h, alpha, pp.rsa_pp);

    // Check equality
    return ok && h_hat.eq(comm.h_hat) && keccak256(message) == keccak256(pt);
}
  
  function verForceOpen(Comm memory comm, ForceOpening memory force_opening, Params memory pp)
  <%visibility%> view returns (bool) {

    RSA2048.Element memory z_hat = force_opening.z_hat;
    PoEVerifier.Proof memory poe_proof = force_opening.poe_proof;
    bytes memory message = force_opening.message;

    // Obtain key as k = H(z_hat)
    bytes32 k = keccak256(z_hat.n.val);

    // Decrypt ciphertext
    (bool ok, bytes memory pt) = decrypt(k, comm.ct, pp.t);

    // Verify PoE and compare decryption
    bool poe_check = PoEVerifier.verify(comm.h_hat, z_hat, pp.t, poe_proof);
    bool pt_check = keccak256(pt) == keccak256(message);
    return pt_check;

    //return poe_check && pt_check;
  }


  function decrypt(bytes32 key, bytes memory ct, uint32 ad) internal pure returns (bool mac_valid, bytes memory pt) {
    require(ct.length > 32);
    // (enc_key, mac_key)
    bytes16[2] memory keys = split_bytes32(key);

    uint num_blocks = (ct.length - 32 - 1) / 32 + 1;
    bytes32[] memory pad_blocks = new bytes32[](num_blocks);
    for (uint i=0; i < num_blocks; i++) {
      pad_blocks[i] = keccak256(abi.encodePacked(keys[0], uint8(i)));
    }
    bytes memory ct_ct = bytes_slice(ct, 0, ct.length - 32);
    bytes memory ct_mac = bytes_slice(ct, ct.length - 32, ct.length);
    pt = bytes_xor(ct_ct, bytes_slice(abi.encodePacked(pad_blocks), 0, ct.length - 32));

    // Check MAC
    mac_valid = bytes_to_bytes32(ct_mac) == keccak256(abi.encodePacked(keys[1], ct_ct, ad));
  }

  //////////////////////// Utility Functions /////////////////////

  function split_bytes32(bytes32 x) internal pure returns (bytes16[2] memory y)  {
    assembly {
      mstore(y, x)
      mstore(add(y, 16), x)
    }
  }

  function bytes_to_bytes32(bytes memory b) internal pure returns (bytes32 out) {
    require(b.length == 32);
    for (uint i = 0; i < 32; i++) {
      out |= bytes32(b[i]) >> (i * 8);
    }
    out |= bytes32(b[0]);
    return out;
  }

  function bytes_xor(bytes memory b1, bytes memory b2) internal pure returns (bytes memory) {
    require(b1.length == b2.length);
    bytes memory out = new bytes(b1.length);
    for (uint i = 0; i < b1.length; i++) {
      out[i] = b1[i] ^ b2[i];
    }
    return out;
  }

function bytes_slice(bytes memory arr, uint256 begin, uint256 end) internal pure returns (bytes memory) {
    bytes memory slice = new bytes(end - begin);
    for(uint i=0; i < end-begin; i++){
      slice[i] = arr[i + begin];
    }
    return slice;
  }
}