import hashlib
import secrets
from typing import Tuple

# SM2参数（简化版本，实际应使用标准参数）
P = 0x8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3
A = 0x787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498
B = 0x63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A
N = 0x8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7
G = (0x421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D,
     0x0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2)

def mod_inverse(a: int, m: int) -> int:
    """计算模逆"""
    return pow(a, -1, m)

def point_multiply(k: int, point: Tuple[int, int]) -> Tuple[int, int]:
    """椭圆曲线点乘运算（简化实现）"""
    # 实际实现需要完整的椭圆曲线运算
    # 这里返回模拟结果
    x = pow(k, 2, P) ^ point[0]
    y = pow(k, 3, P) ^ point[1]
    return (x % P, y % P)

def sm2_sign(message: str, private_key: int, k: int) -> Tuple[int, int, int]:
    """SM2签名（简化版）"""
    # 计算消息哈希
    e = int(hashlib.sha256(message.encode()).hexdigest(), 16) % N
    
    # 计算kG
    kg_point = point_multiply(k, G)
    x1 = kg_point[0]
    
    # 计算r
    r = (e + x1) % N
    if r == 0 or (r + k) % N == 0:
        raise ValueError("需要重新选择k")
    
    # 计算s
    inv_1_plus_d = mod_inverse((1 + private_key) % N, N)
    s = (inv_1_plus_d * (k - r * private_key)) % N
    if s == 0:
        raise ValueError("需要重新选择k")
    
    return r, s, k

def attack_reused_k_different_users(k: int, r2: int, s2: int) -> int:
    """不同用户重复使用k时的攻击"""
    # d_B = (k - s2) / (s2 + r2) mod n
    numerator = (k - s2) % N
    denominator = (s2 + r2) % N
    
    if denominator == 0:
        raise ValueError("分母为0，无法计算")
    
    inv_denominator = mod_inverse(denominator, N)
    private_key_b = (numerator * inv_denominator) % N
    
    return private_key_b

# 演示攻击
def demo_different_users_k_reuse():
    message_a = "Alice's message"
    message_b = "Bob's message"
    private_key_a = secrets.randbelow(N)
    private_key_b = secrets.randbelow(N)
    k_shared = secrets.randbelow(N)
    
    print(f"Alice私钥: {hex(private_key_a)}")
    print(f"Bob私钥: {hex(private_key_b)}")
    
    try:
        # Alice和Bob使用相同的k
        r1, s1, k = sm2_sign(message_a, private_key_a, k_shared)
        r2, s2, _ = sm2_sign(message_b, private_key_b, k_shared)
        
        print(f"Alice签名: r={hex(r1)}, s={hex(s1)}")
        print(f"Bob签名: r={hex(r2)}, s={hex(s2)}")
        
        # Alice利用已知的k攻击Bob
        recovered_key_b = attack_reused_k_different_users(k, r2, s2)
        print(f"恢复的Bob私钥: {hex(recovered_key_b)}")
        print(f"攻击成功: {private_key_b == recovered_key_b}")
        
        # Bob同样可以攻击Alice
        recovered_key_a = attack_reused_k_different_users(k, r1, s1)
        print(f"恢复的Alice私钥: {hex(recovered_key_a)}")
        print(f"攻击成功: {private_key_a == recovered_key_a}")
    except ValueError as e:
        print(f"攻击失败: {e}")

demo_different_users_k_reuse()