from basic import *
from random import randint
import hashlib

def ecdsa_sign(private_key: int, msg: bytes, k: int) -> Tuple[int, int]:
    p = point_mul(G, k)
    r = p[0] % N
    e = int.from_bytes(hashlib.sha256(msg).digest(), 'big')
    s = (inverse_mod(k, N) * (e + r * private_key)) % N
    return r, s

def same_d_k_attack():
    private_key, public_key = generate_keypair()
    user_id = "1234567812345678"
    msg = b"Same d and k attack"
    k = randint(1, N-1)

    # ECDSA 签名（使用相同 k）
    ecdsa_r, ecdsa_s = ecdsa_sign(private_key, msg, k)
    e_ecdsa = int.from_bytes(hashlib.sha256(msg).digest(), 'big')

    # SM2 签名（使用相同 k）
    za = compute_za(user_id, public_key)
    m = za + msg
    e_sm2 = int.from_bytes(sm3_hash(m), 'big')
    p = point_mul(G, k)
    sm2_r = (e_sm2 + p[0]) % N
    sm2_s = (inverse_mod(1 + private_key, N) * (k - sm2_r * private_key)) % N

    # 恢复私钥
    num = (e_ecdsa * inverse_mod(ecdsa_s, N) - sm2_s) % N
    den = (sm2_r + sm2_s - (ecdsa_r * inverse_mod(ecdsa_s, N)) % N) % N
    private_key_recovered = (num * inverse_mod(den, N)) % N

    print(f"Original private key: {hex(private_key)}")
    print(f"Recovered private key: {hex(private_key_recovered)}")
    print(f"Recovery successful: {private_key == private_key_recovered}")

if __name__ == "__main__":
    same_d_k_attack()