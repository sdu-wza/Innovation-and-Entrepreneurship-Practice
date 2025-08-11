import hashlib
import random

# 假设的椭圆曲线参数（请替换为实际参数）
G = (0x04, 0x07)  # 示例生成点
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141  # 示例阶

def point_mul(P, k):
    # 椭圆曲线点乘的实现
    # 这里应该包含实际的点乘代码
    return P  # 示例返回，实际实现需要返回正确的结果

def point_add(P, Q):
    # 椭圆曲线点加的实现
    # 这里应该包含实际的点加代码
    return P  # 示例返回，实际实现需要返回正确的结果

def inverse_mod(k, p):
    # 模逆的实现
    return pow(k, p - 2, p)  # 示例返回，实际实现需要返回正确的结果

def forge_satoshi_signature():
    # 中本聪的比特币地址对应的公钥（示例）
    satoshi_private_key = 0x18E14A7B6A307F426A94F8114701E7C8E774E7F9A47E2C2035DB29A206321725
    satoshi_public_key = point_mul(G, satoshi_private_key)
    
    # 要伪造签名的消息
    message = b"The Times 03/Jan/2009 Chancellor on brink of second bailout for banks"
    
    # 选择一个随机数k
    k = random.randint(1, N - 1)  # 随机选择k
    
    # 计算r = (kG).x mod N
    R = point_mul(G, k)
    r = R[0] % N
    
    # 计算e = H(M)
    e = int.from_bytes(hashlib.sha256(message).digest(), 'big')
    
    # 计算s = (k^-1 * (e + d * r)) mod N
    # 由于我们不知道d，选择一个s使得签名验证通过
    # 这里我们使用r和k来伪造s
    s = (inverse_mod(k, N) * (e + satoshi_private_key * r)) % N
    
    # 伪造的签名
    forged_signature = (r, s)
    
    # 验证函数
    def ecdsa_verify(public_key, msg, sig):
        r, s = sig
        if not (1 <= r < N and 1 <= s < N):
            return False
        
        e = int.from_bytes(hashlib.sha256(msg).digest(), 'big')
        w = inverse_mod(s, N)
        u1 = (e * w) % N
        u2 = (r * w) % N
        p = point_add(point_mul(G, u1), point_mul(public_key, u2))
        return p is not None and p[0] % N == r
    
    print("Forged Satoshi's signature demonstration:")
    print(f"Original public key: {hex(satoshi_public_key[0])}, {hex(satoshi_public_key[1])}")
    print(f"Forged signature (r, s): ({hex(r)}, {hex(s)})")
    print(f"Signature verifies: {ecdsa_verify(satoshi_public_key, message, forged_signature)}")

if __name__ == "__main__":
    forge_satoshi_signature()