from pure25519.basic import (bytes_to_clamped_scalar,
                             bytes_to_scalar, scalar_to_bytes,
                             bytes_to_element, Base)
import hashlib
import binascii
import csv
import os

L = 2**252 + 27742317777372353535851937790883648493


def H(m):
    return hashlib.sha512(m).digest()


def public_key(seed):
    # turn first half of SHA512(seed) into scalar, then into point
    assert len(seed) == 32
    a = bytes_to_clamped_scalar(H(seed)[:32])
    A = Base.scalarmult(a)
    return A.to_bytes()


def Hint(m):
    h = H(m)
    return int(binascii.hexlify(h[::-1]), 16)


def sign(m, sk, pk):
    assert len(sk) == 32  # seed
    assert len(pk) == 32
    h = H(sk[:32])
    a_bytes, inter = h[:32], h[32:]
    a = bytes_to_clamped_scalar(a_bytes)
    r = Hint(inter + m)
    R = Base.scalarmult(r)
    R_bytes = R.to_bytes()
    S = r + Hint(R_bytes + pk + m) * a
    return R_bytes + scalar_to_bytes(S)


def verify(s, m, pk):
    if len(s) != 64:
        raise Exception("signature length is wrong")
    if len(pk) != 32:
        raise Exception("public-key length is wrong")
    R = bytes_to_element(s[:32])
    A = bytes_to_element(pk)
    S = bytes_to_scalar(s[32:])
    h = Hint(s[:32] + pk + m)
    v1 = Base.scalarmult(S)
    v2 = R.add(A.scalarmult(h))
    return v1 == v2

# **************************  NEW  **************************


def inv2(x):
    return pow(x, L-2, L)


def sign2(m, sk):
    assert len(sk) == 32
    h = H(sk[:32])
    a_bytes, inter = h[:32], h[32:]
    a = bytes_to_clamped_scalar(a_bytes)
    r = Hint(inter + m)
    R = Base.scalarmult(r)
    R_bytes = R.to_bytes()
    S = r + Hint(R_bytes + m) * a
    return R_bytes + scalar_to_bytes(S)


def extract_pk(s, m):
    if len(s) != 64:
        raise Exception("signature length is wrong")
    R = bytes_to_element(s[:32])
    S = bytes_to_scalar(s[32:])
    h = Hint(s[:32] + m)
    h_inv = inv2(h)
    R_neg = R.scalarmult(L-1)
    v1 = Base.scalarmult(S)
    v2 = v1.add(R_neg)
    A = v2.scalarmult(h_inv)
    return A


def check_pk(pk, ext_pk):
    if len(pk) != 32:
        raise Exception("public-key length is wrong")
    A = bytes_to_element(pk)
    if A != ext_pk:
        raise Exception("wrong public key extracted")

# *************************  main  **************************


if __name__ == '__main__':
    header = ['pk', 'seed', 'm', 's']

    with open('testdata.csv', 'w', encoding='UTF8') as f:
        writer = csv.writer(f)
        writer.writerow(header)

        for i in range(0, 1000):
            seed = os.urandom(32)
            pk = public_key(seed)
            m = os.urandom(32)
            s = sign2(m, seed)
            writer.writerow([pk.hex(), seed.hex(), m.hex(), s.hex()])

# **************************  go  ***************************


def go_sign2(msg, key):
    m = bytes.fromhex(msg)
    sk = bytes.fromhex(key)
    sig = sign2(m, sk)
    print(sig.hex())


def go_extract_pk(s, msg):
    sig = bytes.fromhex(s)
    m = bytes.fromhex(msg)
    ext_pk = extract_pk(sig, m)
    print(ext_pk.to_bytes().hex())
