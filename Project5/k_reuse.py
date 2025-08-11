from basic import *
from random import randint

def k_reuse_attack():
    # 生成两个用户的密钥对
    dA, PA = generate_keypair()
    dB, PB = generate_keypair()
    user_id = "1234567812345678"
    
    # 用户A用相同的k签名两个不同消息
    k = randint(1, N-1)
    
    # 签名第一个消息
    msg1 = b"Message 1"
    za = compute_za(user_id, PA)
    m1 = za + msg1
    e1 = int.from_bytes(sm3_hash(m1), 'big')
    p = point_mul(G, k)
    r1 = (e1 + p[0]) % N
    s1 = (inverse_mod(1 + dA, N) * (k - r1 * dA)) % N
    
    # 签名第二个消息
    msg2 = b"Message 2"
    za = compute_za(user_id, PA)
    m2 = za + msg2
    e2 = int.from_bytes(sm3_hash(m2), 'big')
    p = point_mul(G, k)  # 重用k
    r2 = (e2 + p[0]) % N
    s2 = (inverse_mod(1 + dA, N) * (k - r2 * dA)) % N
    
    # 攻击者可以推导出私钥dA
    numerator = (s2 - s1) % N
    denominator = (s1 - s2 + r1 - r2) % N
    dA_recovered = (numerator * inverse_mod(denominator, N)) % N
    
    print(f"Original private key: {hex(dA)}")
    print(f"Recovered private key: {hex(dA_recovered)}")
    print(f"Recovery successful: {dA == dA_recovered}")

if __name__ == "__main__":
    k_reuse_attack()