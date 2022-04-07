// SPDX-License-Identifier: MIT
pragma solidity ^0.8.10;

import "./RSA2048.sol";
// import "./PoElib.sol";

<%con_or_lib%> FKPS {
  using RSA2048 for *; 
  // using PoElib for *; 

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
    Proof poe_proof; 
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
    //(bool ok, bytes memory pt) = decrypt(k, comm.ct, pp.t);
    (bool ok, bytes memory pt) = decrypt(k, comm.ct, pp.t);

    // Check h^alpha
    RSA2048.Element memory h_hat = RSA2048.power_and_reduce(pp.h, alpha, pp.rsa_pp);

    // Check equality
    return ok && h_hat.eq(comm.h_hat) && keccak256(message) == keccak256(pt);
}
  
  //function verForceOpen(Comm memory comm, ForceOpening memory force_opening, Params memory pp)
  //<%visibility%> view returns (bool) {

  //  RSA2048.Element memory z_hat = force_opening.z_hat;
  //  Proof memory poe_proof = force_opening.poe_proof;
  //  bytes memory message = force_opening.message;

  //  // Obtain key as k = H(z_hat)
  //  bytes32 k = keccak256(z_hat.n.val);

  //  // Decrypt ciphertext
  //  (bool ok, bytes memory pt) = decrypt(k, comm.ct, pp.t);

  //  // Verify PoE and compare decryption
  //  bool poe_check = verify(comm.h_hat, z_hat, pp.t, poe_proof);
  //  bool pt_check = keccak256(pt) == keccak256(message);

  //  return poe_check && pt_check;
  //}


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

  function split_bytes32(bytes32 x) private pure returns (bytes16[2] memory y)  {
    assembly {
      mstore(y, x)
      mstore(add(y, 16), x)
    }
  }

  function bytes_to_bytes32(bytes memory b) public pure returns (bytes32 out) {
    require(b.length == 32);
    for (uint i = 0; i < 32; i++) {
      out |= bytes32(b[i]) >> (i * 8);
    }
    out |= bytes32(b[0]);
    return out;
  }

  function bytes_xor(bytes memory b1, bytes memory b2) public pure returns (bytes memory) {
    require(b1.length == b2.length);
    bytes memory out = new bytes(b1.length);
    for (uint i = 0; i < b1.length; i++) {
      out[i] = b1[i] ^ b2[i];
    }
    return out;
  }

function bytes_slice(bytes memory arr, uint256 begin, uint256 end) public pure returns (bytes memory) {
    bytes memory slice = new bytes(end - begin);
    for(uint i=0; i < end-begin; i++){
      slice[i] = arr[i + begin];
    }
    return slice;
  }

  //////////////////////// PoE Verifier stuff /////////////////////

      struct Proof {
        RSA2048.Element q;
        PocklingtonCertificate cert;
    }

    //TODO: Pad BigInts to offset 32 bytes after input to save input space
    //TODO: Or change bn-add and bn-sub to support non-32 byte offset, perhaps by padding there
    struct PocklingtonStep {
        BigInt.BigInt f;
        uint32 n;
        uint32 n2;
        BigInt.BigInt a;
        BigInt.BigInt bu;
        BigInt.BigInt bv;
        BigInt.BigInt v;
        BigInt.BigInt s;
        BigInt.BigInt sqrt;
        BigInt.BigInt p_less_one_div_f;
        BigInt.BigInt p_less_one_div_two;
        BigInt.BigInt b_p_div_f1;
        BigInt.BigInt b_p_div_f2;
        BigInt.BigInt b_p_div_two1;
        BigInt.BigInt b_p_div_two2;
    }

    struct PocklingtonCertificate {
        PocklingtonStep[] steps;
        uint32 nonce;
    }

    

    function verify(RSA2048.Element memory x, RSA2048.Element memory y, uint32 t, Proof memory proof) public view returns (bool) {
        RSA2048.Params memory pp = RSA2048.publicParams();
        BigInt.BigInt memory h = hashToBigInt(abi.encodePacked(x.n.val, y.n.val, t, proof.cert.nonce));
        require(verifyHashToPrime(h, proof.cert));
        BigInt.BigInt memory r = BigInt.prepare_modexp(BigInt.from_uint256(2), BigInt.from_uint32(t), h);
        return y.eq(proof.q.power(h, pp).op(x.power(r, pp), pp).reduce(pp));
    }

    function verifyHashToPrime(BigInt.BigInt memory h, PocklingtonCertificate memory cert) public view returns (bool) {
        BigInt.BigInt memory p = h;
        for (uint i = 0; i < cert.steps.length; i++) {
            verifyPocklingtonStep(p, cert.steps[i]);
            p = cert.steps[i].f;
        }
        // Verify final prime using Miller-Rabin for 32 bit integers
        require(BigInt.cmp(BigInt.from_uint256(1 << 32), p, false) == 1);
        require(checkMillerRabin32B(p));
        return true;
    }

    function verifyPocklingtonStep(BigInt.BigInt memory p, PocklingtonStep memory cert) public view returns (bool) {
        BigInt.BigInt memory u = BigInt.prepare_modexp(BigInt.from_uint32(2), BigInt.from_uint32(cert.n2), p);
        u = BigInt.bn_mul(u, BigInt.prepare_modexp(cert.f, BigInt.from_uint32(cert.n), p));
        BigInt.BigInt memory p_less_one = BigInt.prepare_sub(p, BigInt.from_uint256(1));
        require(BigInt.check_bn_div(p_less_one, u, cert.v) == 1);
        BigInt.BigInt memory r;
        {
            BigInt.BigInt memory u_twice = BigInt.bn_mul(BigInt.from_uint256(2), u);
            //TODO: Optimization: r is computed within check_bn_div
            r = BigInt.bn_mod(cert.v, u_twice);
            BigInt.check_bn_div(cert.v, u_twice, cert.s);
        }
        {
            BigInt.BigInt memory one = BigInt.from_uint256(1);
            BigInt.BigInt memory u_plus_one = BigInt.prepare_add(u, one);
            BigInt.BigInt memory u_squared_times2 = BigInt.bn_mul(BigInt.square(u), BigInt.from_uint256(2));
            BigInt.BigInt memory u_times_r = BigInt.bn_mul(u, BigInt.prepare_sub(r, one));
            BigInt.BigInt memory checkf1 = BigInt.bn_mul(u_plus_one, BigInt.prepare_add(u_squared_times2, BigInt.prepare_add(u_times_r, one)));
            require(BigInt.cmp(checkf1, p, false) == 1);
        }
        {
            bool checkf2 = false;
            if (BigInt.cmp(cert.s, BigInt.from_uint32(0), false) == 0) {
                checkf2 = true;
            } else {
                // Verify sqrt witness
                BigInt.BigInt memory expr = BigInt.prepare_sub(BigInt.square(r), BigInt.bn_mul(BigInt.from_uint256(8), cert.s));
                // expr > sqrt^2 ^ expr < (sqrt+1)^2
                if (BigInt.cmp(expr, BigInt.square(cert.sqrt), true) == 1) {
                    if (BigInt.cmp(expr, BigInt.square(BigInt.prepare_add(cert.sqrt, BigInt.from_uint256(1))), false) == -1) {
                        checkf2 = true;
                    }
                }
            }
            require(checkf2);
        }
        BigInt.check_bn_div(p_less_one, cert.f, cert.p_less_one_div_f);
        BigInt.check_bn_div(p_less_one, BigInt.from_uint256(2), cert.p_less_one_div_two);
        {
            // checka1
            require(BigInt.cmp(BigInt.prepare_modexp(cert.a, p_less_one, p), BigInt.from_uint32(1), false) == 0);
            // checka2
            require(checkCoprime(
                        BigInt.prepare_sub(BigInt.prepare_modexp(cert.a, cert.p_less_one_div_f, p), BigInt.from_uint256(1)),
                        p,
                        cert.b_p_div_f1,
                        cert.b_p_div_f2
            ));
            // checka3
            require(checkCoprime(
                    BigInt.prepare_sub(BigInt.prepare_modexp(cert.a, cert.p_less_one_div_two, p), BigInt.from_uint256(1)),
                    p,
                    cert.b_p_div_two1,
                    cert.b_p_div_two2
            ));
        }
        {
            require(BigInt.is_odd(u) == 0);
            require(BigInt.is_odd(cert.v) == 1);
            require(checkCoprime(u, cert.v, cert.bu, cert.bv));
        }
        return true;
    }

    // Hashes to 277 bit integer (277 bit is what is needed for 256 bits of entropy)
    function hashToBigInt(bytes memory input) private view returns (BigInt.BigInt memory h) {
        uint256 h1 = uint256(keccak256(abi.encodePacked(input, uint32(0))));
        uint256 h2 = uint256(keccak256(abi.encodePacked(input, uint32(1))));
        // Keep 21 bits = 277 - 256 of h1
        h1 = h1 & uint256(0x1FFFFF);
        // Set high bit
        h1 = h1 | uint256(0x100000);
        h.val = abi.encodePacked(h1, h2);
    }

    function checkCoprime(BigInt.BigInt memory a, BigInt.BigInt memory b, BigInt.BigInt memory ba, BigInt.BigInt memory bb) private view returns (bool) {
        return BigInt.cmp(BigInt.prepare_add(BigInt.bn_mul(a, ba), BigInt.bn_mul(b, bb)), BigInt.from_uint32(1), true) == 0;
    }

    function checkMillerRabin(BigInt.BigInt memory n, BigInt.BigInt memory b) private view returns (bool) {
        require(BigInt.is_odd(n) == 1);
        BigInt.BigInt memory n_less_one = BigInt.prepare_sub(n, BigInt.from_uint256(1));
        BigInt.BigInt memory d = BigInt.prepare_sub(n, BigInt.from_uint256(1));
        uint s;
        for (s = 0; BigInt.is_odd(d) == 0; s++) {
            d = BigInt.in_place_right_shift(d, 1);
        }

        BigInt.BigInt memory pow = BigInt.prepare_modexp(b, d, n);
        if ((BigInt.cmp(pow, BigInt.from_uint32(1), false) == 0) || (BigInt.cmp(pow, n_less_one, false) == 0)) {
            return true;
        }
        for (uint i = 0; i < s - 1; i++) {
            pow = BigInt.bn_mod(BigInt.square(pow), n);
            if (BigInt.cmp(pow, n_less_one, false) == 0) {
                return true;
            }
        }
        return false;
    }

    function checkMillerRabin32B(BigInt.BigInt memory n) private view returns (bool) {
        return checkMillerRabin(n, BigInt.from_uint256(2))
                && checkMillerRabin(n, BigInt.from_uint256(7))
                && checkMillerRabin(n, BigInt.from_uint256(61));
    }

}