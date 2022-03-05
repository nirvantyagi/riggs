# vim: syntax=python
# simple primality certificates
# (C) 2022 Riad S. Wahby <riad@cmu.edu>
# Licensed under the terms of the WTFPL www.wtfpl.net

from collections import namedtuple

P_LIMIT = 1 << 32

##### Pocklington certificates
# see `pocklington()` and `verify_pocklington()` below for high-level entry points
#
# High-level idea: generate a (256 + log(256) + 16)~=280-bit prime via
# hash-and-test:
#
# for nonce in range(65536):
#     prime_cand = hash_to_280_bits(transcript, encode_as_2_bytes(nonce)) | 1
#     if not is_prime(prime_cand):
#         continue
#     cert = pocklington(prime_cand)
#     if cert is None:
#         continue
#     if len(cert) > cert_length_threshold:   # 4? 5? not clear to me.
#         continue
#     return (prime_cand, nonce, cert)
#
# => if no candidate is found, re-randomize the proof and start over.

def primegen_opt1(bits):
    while True:
        b1 = bits // 2
        f1 = getrandbits(b1)
        f2 = getrandbits(bits - b1 - 1)
        p_cand = f1 * f2 * 2 + 1
        if is_prime(p_cand):
            return p_cand

#
# really, this would be implemented as:
# 1. generate (1.1 * bits // 3 - 10) bits by hashing; call this value f11
# 2. for f12 in [0, 1024), test if ((f11 << 11) + (f12 << 1) + 1) is prime.
# 3. Call the first resulting prime f1. The hash input and f12 are the witness.
# 4. Using a PRG seeded by a hash, generate the remaining bits (b2, below)
#
# The eventual Pocklington certificate for the big prime also naturally proves
# the little prime f1's primality, which is handy.
#
def primegen_opt2(bits):
    lb = 1 << (bits // 3 + 1)
    ub = 11 * lb // 10
    f1 = random_prime(ub, lbound=lb)
    brem = bits - int(f1).bit_length()
    while True:
        f2 = getrandbits(brem)
        p_cand = f1 * f2 * 2 + 1
        assert(p_cand % 2 == 1)
        if is_prime(p_cand):
            nf = 1
            while f2 % f1 == 0:
                f2 //= f1
                nf += 1
            n2 = 0
            d2 = p_cand - 1
            while d2 % 2 == 0:
                d2 //= 2
                n2 += 1
            return (p_cand, [(2, n2), (f1, nf)])

def test_pock_a(p, f, a):
    if pow(a, p - 1, p) != 1:
        return False
    if gcd(pow(a, (p - 1) // f, p) - 1, p) != 1:
        return False
    if gcd(pow(a, (p - 1) // 2, p) - 1, p) != 1:
        return False
    return True

def test_pock_f(p, f, n, n2):
    F1 = (2 ** n2) * (f ** n)
    R1 = (p - 1) // F1
    if R1 <= 1:
        return None

    r = R1 % (2 * F1)
    s = R1 // (2 * F1)
    if r ** 2 - 8 * s < 0:
        return None
    assert R1 == 2 * F1 * s + r

    if p >= (F1 + 1) * (2 * F1 * F1 + (r - 1) * F1 + 1):
        return None
    return (F1, R1, r, s)

PockCert = namedtuple("Pock", ['f', 'n', 'n2', 'a', 't', 'bf', 'br'])
def pocklington_step(p, ff=None):
    assert(is_prime(p))
    if p < P_LIMIT:
        return None

    # choose smallest usable f
    if ff is None:
        ff = factor(p-1)
    assert ff[0][0] == 2
    n2 = ff[0][1]

    (f, n, F1, R1, r, s) = [None] * 6
    for (ff, nn) in ff[1:]:
        res = test_pock_f(p, ff, nn, n2)
        if res is not None:
            (F1, R1, r, s) = res
            (f, n) = (ff, nn)
            break
    if any(x is None for x in (f, n, F1, R1, r, s)):
        return None
    # include Bezout coeffs in the cert to save a GCD computation for the Verifier
    (g, bf, br) = xgcd(F1, R1)
    if g != 1:
        return None

    a = None
    for aa in range(2, p - 1):
        # requiring same a for f and 2 gives ~2.5% failure, cheaper verification
        if test_pock_a(p, f, aa):
            a = aa
            break
    if a is None:
        return None

    targ = r ** 2 - 8 * s
    if s == 0:
        t = 0
    elif is_square(targ):
        return None
    else:
        t = isqrt(targ)

    return PockCert(f = f, n = n, n2 = n2, a = a, t = t, bf = bf, br = br)

def verify_pocklington_step(p, cert):
    if p < P_LIMIT:
        return deterministic_rabin_miller(p)
    assert isinstance(cert, PockCert)
    (f, n, n2, a, t, bf, br) = cert

    if not test_pock_a(p, f, a):
        return False

    f_res = test_pock_f(p, f, n, n2)
    if f_res is None:
        return False
    (F1, R1, r, s) = f_res

    # conditions on F1 and R1
    fev = F1 % 2 == 0
    rod = R1 % 2 == 1
    rsz = R1 > 1
    frp = F1 * R1 == p - 1
    frg = bf * F1 + br * R1 == 1
    if not (fev and rod and rsz and frp and frg):
        return False

    if t == 0 and s == 0:
        return True

    rstrg = r ** 2 - 8 * s
    if t ** 2 < rstrg and (t + 1) ** 2 > rstrg:
        return True

    return False

def pocklington(p, ff=None):
    assert is_prime(p)
    cert = []
    while p > P_LIMIT:
        this_cert = pocklington_step(p, ff)
        ff = None
        if this_cert is None:
            return None
        cert.append(this_cert)
        p = this_cert.f
    return cert

def random_pocklington(bits, ptype=0):
    if ptype == 0:
        p = random_prime(1 << bits)
        ff = None
    elif ptype == 1:
        p = primegen_opt1(bits)
        ff = None
    else:
        (p, ff) = primegen_opt2(bits)
    return pocklington(p, ff)

def verify_pocklington(p, cert):
    for this_cert in cert:
        if not verify_pocklington_step(p, this_cert):
            return False
        p = this_cert.f
    return p < P_LIMIT and deterministic_rabin_miller(p)


# from Wikipedia:
#
# 32 bits: a = 2, 7, 61
# 40 bits: a = 2, 13, 23, 1662803
# 41 bits: a = 2, 3, 5, 7, 11, 13
# 48 bits: a = 2, 3, 5, 7, 11, 13, 17
#
# we might be able to optimize cost by selecting P_LIMIT dynamically...

def deterministic_rabin_miller(p):
    # validity check
    LOG_P_LIMIT = int(P_LIMIT - 1).bit_length()
    assert P_LIMIT == 1 << LOG_P_LIMIT

    assert 1 < p < P_LIMIT
    if p < 10:
        if p in (2, 3, 5, 7):
            return True
        return False

    # choose R-M bases depending on P_LIMIT
    if LOG_P_LIMIT == 32:
        bases = [2, 7, 61]
    elif LOG_P_LIMIT == 40:
        bases = [2, 13, 23, 1662803]
    elif LOG_P_LIMIT == 41:
        bases = [2, 3, 5, 7, 11, 13]
    elif LOG_P_LIMIT == 48:
        bases = [2, 3, 5, 7, 11, 13, 17]
    else:
        raise RuntimeError("unsupported P_LIMIT value")

    d = p - 1
    r = 0
    while d % 2 == 0:
        r += 1
        d //= 2
    assert d % 2 == 1
    assert d * 2**r == p - 1

    for a in bases:
        if a >= p - 1:
            continue

        x = pow(a, d, p)
        if x in (1, p - 1):
            continue

        cont = False
        for _ in range(r - 1):
            x = pow(x, 2, p)
            if x == p - 1:
                cont = True
                break
        if cont:
            continue

        assert not is_prime(p)
        return False

    assert is_prime(p)
    return True

##### Pratt certs seem strictly bigger, but have no chance of failure
#
# PrattCert = namedtuple("Pratt", ['a', 'ff'])
# def pratt_step(p):
#     assert(is_prime(p))
#     if p < P_LIMIT:
#         return None
#
#     a = primitive_root(p)
#     ff = factor(p - 1)
#     return PrattCert(a = a, ff = ff)
#
# def verify_pratt_step(p, cert):
#     if p < P_LIMIT:
#         return is_prime(p)
#     assert isinstance(cert, PrattCert)
#     (a, ff) = cert
#
#     if pow(a, p-1, p) != 1:
#         return False
#
#     accum = 1
#     for (f, n) in ff:
#         accum *= f ** n
#         if pow(a, (p-1)//f, p) == 1:
#             return False
#     return accum == p-1
#
# # def pratt(p, cert=None):
# #     if cert is None:
# #         cert = {}
# #     assert(is_prime(p))
# #     if p in cert:
# #         return cert
# #     if p < P_LIMIT:
# #         return cert
# #
# #     a = primitive_root(p)
# #     ff = factor(p-1)
# #     cert[p] = (a, ff)
# #     for (f, _) in ff:
# #         pratt(f, cert)
# #     return cert
# #
# # def verify_pratt(p, cert, checked=None):
# #     if checked is None:
# #         checked = {}
# #
# #     if p in checked:
# #         return checked[p]
# #
# #     if p < 2**32:
# #         return is_prime(p)
# #
# #     if p not in cert:
# #         return False
# #     (a, ff) = cert[p]
# #
# #     if pow(a, p-1, p) != 1:
# #         return False
# #
# #     accum = 1
# #     for (f, n) in ff:
# #         accum *= f ** n
# #         if pow(a, (p-1)/f, p) == 1:
# #             return False
# #         checked[f] = verify_pratt(f, cert, checked)
# #         if not checked[f]:
# #             return False
# #
# #     return accum == p-1
