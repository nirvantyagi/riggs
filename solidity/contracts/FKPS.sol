// SPDX-License-Identifier: MIT
pragma solidity ^0.8.10;

import "./RSA2048.sol";

library FKPS {
  using RSA2048 for *; 

  // currently not used
  // we could have a struct to define this struct to set params in other contracts
  struct Params {
    RSA2048.Params rsa_pp;
    RSA2048.Element h;
    RSA2048.Element z;
  }

  struct Comm {
    RSA2048.Element h_hat;    
    bytes ct;
  }

  // public parameters
  // q1, q2, N, G, g, h
  // bytes constant N_bytes = hex"ae72f2faa211ea0fd805879d622dd408f5ac7047b55c8509547c63b662c98145104a827940ba9668d710acf915a2c8d75a95fea046268eba3db260a186bce53d4b5c69269f14df81340fe9f25a188e57cbb26b709dde47c1d2818bafd0e11eeb5d7e9402ce41581ffe80e301ab46587549067dcb955d75ec989babac79e3d57b220795a2bb0b9c162ed9bf040a3af64945b98e6430695e3153ec3a78a95b6df7abf6724223fcc4ea34ac82e4907fc26fd9be0c1970ceda00819559d4d3523d4e0f9071ffa30b821d823ceea0415caea342d5a9c9205df3dbb19ff00f3697f923c881efca25d8a1879577be78c2a66fc6b29be260e3e2b4143ad2a667180d62ad";
  // bytes constant g_bytes = hex"51a321cc9c2c8c431ebd150259b7e264e132f3f07e0d3df29da6d65d561b6d7af7254e049655e442c2d70d92be0a7854f2ec66d707b003d078534171a5186c4ca246e8cb15a120acb08bcf4ad5a8a291ceadd0e15b3e62e9e4f2bffbe8456640a17ec0d0ddc7ef757fd63a1f874685ed26e160ac89bf55042b2c09bc1afdfc21415947115fa9c6d03cdd91ede9a10eb5c70265468025271036809a5c6ce6df4f0b4adec31020e2d4321cccd8a7eca82959016409ac3ad3918126c36c727972374b954d6d622bbd97664263841ad45eefbe702a1259e3da26179e1611da88876403cbadae91754c3be671e90b777fe7ce99fae6aed83cac060cc5f72cae29614c";
  bytes constant h_bytes = hex"435fbb8ca4c6d760a186c4e39a65f3a841176ae3936aa40427108ef143d13df73d7e5fe2bc408934c560ac3ec4a4fce86a045a8c54f3a757e429ca89ff31c0269e80937b5f8ee9c7a82c418f5952f56c942535653870c307b73f1b9b742589b606ef15a1af58e92cae903398699e51ef860cc1309afce6f6eef425be7d8f3b80eb6d0ee45a22b4400b4ee6f2333c59e08831fd97e619f679097e1fbc73052b389b32858d1aeebe5f1f3c5450f22602c1ce7dee3b16d249a58bc9238bc8c8805c143a888d7ed5b2aab7f683660424326d632a0bda2e8b7ef00a0dd8b8ac80797435ba420912da88d08eff8e15e588b3f9b7500a528e0a17f8f7a1403dbe8efba1";

  // z
  bytes constant z_bytes = "0x65237841623487152384716253418732654216523784162348715238471625346523784162348715238471625341873265421652378416234871523847162534652378416234871523847162534187326542165237841623487152384716253465237841623487152384716253418732654216523784162348715238471625346523784162348715238471625341873265421652378416234871523847162534652378416234871523847162534187326542165237841623487152384716253465237841623487152384716253418732654216523784162348715238471625346523784162348715238471625341873265421652378416234871523847162534";

  // Public Parameters
  // m, g are taken the RSA contract
  // h, z are defined below

  // TODO: PoE keys

  function publicParams() internal pure returns (Params memory pp) {
    pp.rsa_pp = RSA2048.publicParams();

    uint256[] memory h_u256_digits = new uint256[](<%pp_m_len%>);
    <%pp_h_populate%>
    pp.h.n.val = abi.encodePacked(h_u256_digits);
    
    uint256[] memory z_u256_digits = new uint256[](<%pp_m_len%>);
    <%pp_z_populate%>
    pp.z.n.val = abi.encodePacked(z_u256_digits);
  }

    function verOpen(Comm memory comm, uint256 alpha, bytes memory message, Params memory pp) 
  internal view returns (bool) {
    // 1. compute z_hat = z ^ a
    RSA2048.Element memory z_hat = RSA2048.power_and_reduce(pp.z, alpha, pp.rsa_pp);

    // 2. obtain key as k = H(z, pp)
    // TODO: add pp to the hash input
    bytes32 k = keccak256(z_hat.n.val);

    // 3. decrypt ciphertext
    bytes32[] memory pt;
    bytes32 mac;
    pt = decrypt(k, comm.ct);

    // 4. Check h^alpha
    RSA2048.Element memory h_hat = RSA2048.power_and_reduce(pp.h, alpha, pp.rsa_pp);

    // 4. Check equality
    // return bid == uint256(pt) && h_hat.eq(comm.h_hat);

    bool ret_value = h_hat.eq(comm.h_hat);

    return ret_value;

    uint num_blocks = (message.length)/32;
    if (message.length % 32 != 0) {
      num_blocks +=1;
    }

    for (uint i=0; i<num_blocks; i++) {
      ret_value = ret_value && (bytesToBytes32(message, i*32) == pt[i]);
    }
    return ret_value;
  }

  function decrypt(bytes32 key, bytes memory ct) internal pure 
  returns (bytes32[] memory) {

    uint num_blocks = ct.length/32;
    if (ct.length % 32 != 0) {
      num_blocks +=1;
    }

    bytes32[] memory pt = new bytes32[](num_blocks);

    for (uint i=0; i<num_blocks; i++) {
      bytes32 cur_ct_block = bytesToBytes32(ct, i*32);

      bytes memory ctr = new bytes(1);
      ctr[0] = bytes1(uint8(i));
      bytes32 cur_pad = keccak256(bytes.concat(key, ctr));
      bytes32 cur_pt = cur_pad ^ cur_ct_block;

      pt[i] = cur_pt;
    }

    return pt;
  }

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