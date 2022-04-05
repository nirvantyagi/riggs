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
    return h_hat.eq(comm.h_hat) && compare_bytes_bytes32(pt, message);
  }
  
  function verForceOpen(Comm memory comm, ForceOpening memory force_opening, Params memory pp) 
  <%visibility%> view returns (bool) {

    // 1. z_hat is given 
    RSA2048.Element memory z_hat = force_opening.z_hat;
    Proof memory poe_proof = force_opening.poe_proof;
    bytes memory message = force_opening.message; 

    // 2. obtain key as k = H(z, pp)
    // TODO: add pp to the hash input
    bytes32 k = keccak256(z_hat.n.val);

    // 3. decrypt ciphertext
    bytes32[] memory pt;
    bytes32 mac;
    pt = decrypt(k, comm.ct);

    // 4. Verify PoE and compare decryption
    bool poe_check = verify(comm.h_hat, z_hat, uint32(40), poe_proof);
    bool pt_check = compare_bytes_bytes32(pt, message);

    return poe_check && pt_check;
  }


  function decrypt(bytes32 key, bytes memory ct) 
  internal pure returns (bytes32[] memory) {

    require(ct.length >= 1);
    
    uint num_blocks = (ct.length-1)/32 + 1;
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

  //////////////////////// Utility Functions /////////////////////

  function compare_bytes_bytes32(bytes32[] memory pt, bytes memory message) 
  private pure returns (bool) {
    if (message.length == 0) {return true;}
    uint num_blocks = (message.length)/32;
    if (message.length % 32 != 0) {
      num_blocks +=1;
    }
    bool ret_value = true;
    for (uint i=0; i<num_blocks-1; i++) {
      ret_value = ret_value && (bytesToBytes32(message, i*32) == pt[i]);
    }

    // now compare last block
    bytes memory lb = abi.encodePacked(pt[num_blocks-1]);
    uint lb_offset = (num_blocks-1)*32;
    for (uint j=0; j<(message.length % 32); j++) {
      ret_value = ret_value && (lb[j] == message[lb_offset+j]);
    }

    return ret_value;
  }

  function bytesToBytes32(bytes memory b, uint offset) public pure returns (bytes32) {
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