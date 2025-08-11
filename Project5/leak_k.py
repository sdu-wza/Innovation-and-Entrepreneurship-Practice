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

def attack_leaked_k(message: str, r: int, s: int, k: int) -> int:
    """利用泄露的k恢复私钥"""
    e = int(hashlib.sha256(message.encode()).hexdigest(), 16) % N
    
    # d_A = (s + r)^(-1) · (k - s) mod n
    inv_s_plus_r = mod_inverse((s + r) % N, N)
    private_key = (inv_s_plus_r * (k - s)) % N
    
    return private_key

# 演示攻击
if __name__ == "__main__":
    message = "Hello SM2"
    original_private_key = secrets.randbelow(N)
    k_leaked = secrets.randbelow(N)
    
    print(f"原始私钥: {hex(original_private_key)}")
    
    # 正常签名
    try:
        r, s, k = sm2_sign(message, original_private_key, k_leaked)
        print(f"签名: r={hex(r)}, s={hex(s)}")
        
        # 攻击：利用泄露的k恢复私钥
        recovered_key = attack_leaked_k(message, r, s, k_leaked)
        print(f"恢复的私钥: {hex(recovered_key)}")
        print(f"攻击成功: {original_private_key == recovered_key}")
    except ValueError as e:
        print(f"签名失败: {e}")