import hashlib
import secrets
from typing import Tuple

# SM2参数 (256位素数域)
P = 0x8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3
A = 0x787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498
B = 0x63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A
G_X = 0x421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D
G_Y = 0x0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2
G = (G_X, G_Y)
N = 0x8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7
H = 0x1  # 协因子

# 辅助函数
def inverse_mod(a: int, p: int) -> int:
    """使用扩展欧几里得算法求模逆"""
    if a == 0:
        return 0
    lm, hm = 1, 0
    low, high = a % p, p
    while low > 1:
        ratio = high // low
        nm = hm - lm * ratio
        new = high - low * ratio
        hm, lm = lm, nm
        high, low = low, new
    return lm % p

def point_add(p1: Tuple[int, int], p2: Tuple[int, int]) -> Tuple[int, int]:
    """椭圆曲线点加法"""
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and y1 != y2:
        return None
    if x1 == x2:
        m = (3 * x1 * x1 + A) * inverse_mod(2 * y1, P)
    else:
        m = (y1 - y2) * inverse_mod(x1 - x2, P)
    x3 = m * m - x1 - x2
    y3 = y1 + m * (x3 - x1)
    return (x3 % P, -y3 % P)

def point_mul(p: Tuple[int, int], n: int) -> Tuple[int, int]:
    """椭圆曲线点乘法（使用double-and-add算法）"""
    r = None
    for i in range(n.bit_length()):
        if (n >> i) & 1:
            r = point_add(r, p)
        p = point_add(p, p)
    return r

def sm3_hash(msg: bytes) -> bytes:
    """SM3哈希函数（简化版，实际应使用完整实现）"""
    return hashlib.sha256(msg).digest()  # 实际应使用SM3

def generate_keypair() -> Tuple[int, Tuple[int, int]]:
    """生成SM2密钥对"""
    private_key = secrets.randbelow(N-1) + 1
    public_key = point_mul(G, private_key)
    return private_key, public_key

def compute_za(user_id: str, public_key: Tuple[int, int]) -> bytes:
    """计算ZA值"""
    entla = len(user_id.encode('utf-8')) * 8
    entla_bytes = entla.to_bytes(2, 'big')
    user_id_bytes = user_id.encode('utf-8')
    a_bytes = A.to_bytes(32, 'big')
    b_bytes = B.to_bytes(32, 'big')
    gx_bytes = G_X.to_bytes(32, 'big')
    gy_bytes = G_Y.to_bytes(32, 'big')
    x_bytes = public_key[0].to_bytes(32, 'big')
    y_bytes = public_key[1].to_bytes(32, 'big')
    
    data = entla_bytes + user_id_bytes + a_bytes + b_bytes + gx_bytes + gy_bytes + x_bytes + y_bytes
    return sm3_hash(data)

def sm2_sign(private_key: int, msg: bytes, user_id: str = "1234567812345678") -> Tuple[int, int]:
    """SM2签名算法"""
    public_key = point_mul(G, private_key)
    za = compute_za(user_id, public_key)
    m = za + msg
    e = int.from_bytes(sm3_hash(m), 'big')
    
    while True:
        k = secrets.randbelow(N-1) + 1
        p = point_mul(G, k)
        r = (e + p[0]) % N
        if r == 0 or r + k == N:
            continue
        
        s = (inverse_mod(1 + private_key, N) * (k - r * private_key)) % N
        if s == 0:
            continue
        
        return r, s

def sm2_verify(public_key: Tuple[int, int], msg: bytes, signature: Tuple[int, int], user_id: str = "1234567812345678") -> bool:
    """SM2验证签名"""
    r, s = signature
    if not (1 <= r < N and 1 <= s < N):
        return False
    
    za = compute_za(user_id, public_key)
    m = za + msg
    e = int.from_bytes(sm3_hash(m), 'big')
    
    t = (r + s) % N
    if t == 0:
        return False
    
    p = point_add(point_mul(G, s), point_mul(public_key, t))
    if p is None:
        return False
    
    R = (e + p[0]) % N
    return R == r

def test_sm2():
    # 生成密钥对
    private_key, public_key = generate_keypair()
    print(f"Private key: {hex(private_key)}")
    print(f"Public key: ({hex(public_key[0])}, {hex(public_key[1])})")
    
    # 签名消息
    message = b"Hello, SM2!"
    signature = sm2_sign(private_key, message)
    print(f"Signature (r, s): ({hex(signature[0])}, {hex(signature[1])})")
    
    # 验证签名
    is_valid = sm2_verify(public_key, message, signature)
    print(f"Signature valid: {is_valid}")
    
    # 测试错误签名
    wrong_signature = (signature[0], (signature[1] + 1) % (0x8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7))
    is_valid = sm2_verify(public_key, message, wrong_signature)
    print(f"Wrong signature valid: {is_valid}")

if __name__ == "__main__":
    test_sm2()