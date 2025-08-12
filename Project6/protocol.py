import hashlib
import os
import math

# P-256 (secp256r1) curve order n (constant)
# Source: SEC2, RFC 5639 etc.
P256_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

class GPC_ECC_Demo:
    def __init__(self, key_len=2, hash_len=32):
        # key_len 为哈希前缀字节数（用于分桶）
        self.key_len = key_len
        self.hash_len = hash_len
        self.server_secret = None  # b

    def _hash_credentials(self, username: str, password: str) -> bytes:
        """SHA-256 对 username:password 做哈希，返回 hash_len 字节"""
        credential = f"{username}:{password}".encode()
        h = hashlib.sha256(credential).digest()
        return h[:self.hash_len]

    def _hash_to_scalar(self, h: bytes) -> int:
        """
        将哈希映射到曲线标量 s in [1, n-1]
        这里用简单 mod n 的方法：s = int(h) % n ，并保证非零（若为0则置为1）。
        注：真实安全实现应使用标准 hash-to-curve。
        """
        s = int.from_bytes(h, 'big') % P256_ORDER
        if s == 0:
            s = 1
        return s

    def server_setup(self, credential_database):
        """
        服务器初始化：生成服务器私钥 b，并把泄露凭据映射成标量并按前缀分桶。
        Returns: server_db (dict: prefix_bytes -> list of scalar y)
        """
        # 随机生成服务器私钥 b (1..n-1)
        b = int.from_bytes(os.urandom(32), 'big') % (P256_ORDER - 1)
        if b == 0:
            b = 1
        self.server_secret = b

        server_db = {}
        for username, password in credential_database:
            h = self._hash_credentials(username, password)
            prefix = h[:self.key_len]
            s = self._hash_to_scalar(h)  # scalar s represents point s*G
            if prefix not in server_db:
                server_db[prefix] = []
            server_db[prefix].append(s)
        return server_db

    def client_prepare_check(self, username: str, password: str):
        """
        客户端准备：生成私钥 a，计算哈希标量 s，并返回 (a, prefix, blinded_scalar = a*s mod n)
        """
        a = int.from_bytes(os.urandom(32), 'big') % (P256_ORDER - 1)
        if a == 0:
            a = 1

        h = self._hash_credentials(username, password)
        prefix = h[:self.key_len]
        s = self._hash_to_scalar(h)

        blinded = (s * a) % P256_ORDER  # 标量表示的 a*s（等价于 a*(s*G)）
        # 调试输出（可选）
        # print("client: a =", a)
        # print("client: s =", s)
        # print("client: blinded (a*s) =", blinded)
        return a, prefix, blinded

    def server_lookup(self, server_db, prefix: bytes, client_blinded):
        """
        服务器接收到客户端的 blinded（a*s），返回：
         - A_prime = b * (a*s) mod n = a*b*s (用于客户端直接比较)
         - bucket_b = [b * y mod n for y in bucket]  （服务器对桶内每个 y 做单加密）
        """
        b = self.server_secret
        bucket = server_db.get(prefix, [])
        # A' = (a*s) * b = a*b*s mod n
        A_prime = (client_blinded * b) % P256_ORDER
        # 服务器把桶内每个 y -> y^b (即 b * y mod n)
        bucket_b = [ (y * b) % P256_ORDER for y in bucket ]
        return A_prime, bucket_b

    def client_process_response(self, a, server_response):
        """
        客户端收到 (A_prime, bucket_b)：
         - 把每个 bucket_b 元素再乘 a，得到 (b*y)*a = a*b*y
         - 如果 A_prime 在这些值中，则匹配成功（泄露）
        """
        A_prime, bucket_b = server_response
        # 客户端计算每个 (y^b)^a = (b*y)*a mod n = a*b*y mod n
        bucket_ba = [ (entry * a) % P256_ORDER for entry in bucket_b ]
        # 调试输出（可选）
        # print("client: A_prime =", A_prime)
        # print("client: bucket_ba =", bucket_ba)
        return A_prime in set(bucket_ba)


if __name__ == "__main__":
    leaked_creds = [
        ("user1", "password123"),
        ("user2", "qwerty"),
        ("test", "password"),
        ("admin", "admin123"),
    ]

    demo = GPC_ECC_Demo()
    server_db = demo.server_setup(leaked_creds)

    username = "test"
    password = "password"

    a, prefix, blinded = demo.client_prepare_check(username, password)
    server_response = demo.server_lookup(server_db, prefix, blinded)
    is_leaked = demo.client_process_response(a, server_response)

    print(f"Password for '{username}' is {'LEAKED' if is_leaked else 'safe'}")
