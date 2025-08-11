# sm2_fixed.py
import hashlib
import secrets
from typing import Tuple, List, Dict, Optional

# ---------------------------- SM2参数定义 ----------------------------
# SM2椭圆曲线参数 (256位素数域)
P = 0x8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3
A = 0x787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498
B = 0x63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A
G_X = 0x421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D
G_Y = 0x0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2
N = 0x8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7
H = 1  # 协因子

# ---------------------------- 辅助函数 ----------------------------
def inverse_mod(a: int, p: int) -> int:
    """扩展欧几里得算法求模逆。若无逆则抛出 ZeroDivisionError。"""
    a = a % p
    if a == 0:
        raise ZeroDivisionError("Inverse does not exist for 0 modulo p")
    # Python's pow with -1 is implemented and efficient in 3.8+, but implement EEA for clarity:
    return pow(a, -1, p)

def sm3_hash(msg: bytes) -> bytes:
    """模拟SM3哈希（实际应用应替换为真实SM3实现）"""
    return hashlib.sha256(msg).digest()

# ---------------------------- 椭圆曲线点运算（雅可比坐标） ----------------------------
Point = Optional[Tuple[int, int]]            # Affine (x,y) or None
JacPoint = Optional[Tuple[int, int, int]]    # Jacobian (X,Y,Z) or None

def point_to_jacobian(p: Point) -> JacPoint:
    if p is None:
        return None
    return (p[0], p[1], 1)

def jacobian_to_point(P: JacPoint, p_mod: int = P) -> Point:
    if P is None:
        return None
    X, Y, Z = P
    if Z % p_mod == 0:
        return None
    z_inv = inverse_mod(Z, p_mod)
    z_inv2 = (z_inv * z_inv) % p_mod
    z_inv3 = (z_inv2 * z_inv) % p_mod
    x = (X * z_inv2) % p_mod
    y = (Y * z_inv3) % p_mod
    return (x, y)

def jacobian_point_double(P: JacPoint, p_mod: int = P, a_coef: int = A) -> JacPoint:
    """标准雅可比点倍（通用公式）"""
    if P is None:
        return None
    X1, Y1, Z1 = P
    if Y1 % p_mod == 0:
        return None
    Y1_sq = (Y1 * Y1) % p_mod
    S = (4 * X1 * Y1_sq) % p_mod           # S = 4 * X1 * Y1^2
    X1_sq = (X1 * X1) % p_mod
    Z1_sq = (Z1 * Z1) % p_mod
    Z1_4 = (Z1_sq * Z1_sq) % p_mod
    M = (3 * X1_sq + a_coef * Z1_4) % p_mod
    X3 = (M * M - 2 * S) % p_mod
    Y3 = (M * (S - X3) - 8 * (Y1_sq * Y1_sq % p_mod)) % p_mod
    Z3 = (2 * Y1 * Z1) % p_mod
    return (X3 % p_mod, Y3 % p_mod, Z3 % p_mod)

def jacobian_point_add(P: JacPoint, Q: JacPoint, p_mod: int = P) -> JacPoint:
    """保守通用的雅可比点加法 (handles all cases)."""
    if P is None:
        return Q
    if Q is None:
        return P
    X1, Y1, Z1 = P
    X2, Y2, Z2 = Q
    # U1 = X1 * Z2^2, U2 = X2 * Z1^2
    Z1_sq = (Z1 * Z1) % p_mod
    Z2_sq = (Z2 * Z2) % p_mod
    U1 = (X1 * Z2_sq) % p_mod
    U2 = (X2 * Z1_sq) % p_mod
    # S1 = Y1 * Z2^3, S2 = Y2 * Z1^3
    Z1_cu = (Z1_sq * Z1) % p_mod
    Z2_cu = (Z2_sq * Z2) % p_mod
    S1 = (Y1 * Z2_cu) % p_mod
    S2 = (Y2 * Z1_cu) % p_mod
    if U1 == U2:
        if S1 != S2:
            return None
        return jacobian_point_double(P, p_mod)
    H = (U2 - U1) % p_mod
    R = (S2 - S1) % p_mod
    H_sq = (H * H) % p_mod
    H_cu = (H_sq * H) % p_mod
    X3 = (R * R - H_cu - 2 * U1 * H_sq) % p_mod
    Y3 = (R * (U1 * H_sq - X3) - S1 * H_cu) % p_mod
    Z3 = (H * Z1 * Z2) % p_mod
    return (X3 % p_mod, Y3 % p_mod, Z3 % p_mod)

# ---------------------------- 简单 baseline 标量乘（double-and-add） ----------------------------
def double_and_add_mul(k: int, P_aff: Point, p_mod: int = P) -> Point:
    """可靠但不一定最快的基线实现，用于生成正确的公钥/核验一致性"""
    if P_aff is None or k % N == 0:
        return None
    Pj = point_to_jacobian(P_aff)
    R = None
    for bit in bin(k)[2:]:
        if R is not None:
            R = jacobian_point_double(R, p_mod)
        if bit == '1':
            if R is None:
                R = Pj
            else:
                R = jacobian_point_add(R, Pj, p_mod)
    return jacobian_to_point(R, p_mod)

# ---------------------------- wNAF + 预表（用于加速点乘） ----------------------------
def compute_wnaf(k: int, w: int):
    """返回 wNAF（little-endian list of signed digits）"""
    if k == 0:
        return []
    k = int(k)
    wnaf = []
    two_w = 1 << w
    two_w_minus1 = 1 << (w-1)
    while k > 0:
        if k & 1:
            d = k % two_w
            if d >= two_w_minus1:
                d = d - two_w
            k = k - d
            wnaf.append(d)
        else:
            wnaf.append(0)
        k >>= 1
    return wnaf

def precompute_window(P_aff: Point, w: int, p_mod: int = P):
    """
    预计算 odd multiples: P, 3P, 5P, ..., up to (2^{w-1}-1)P
    返回 dict: odd -> affine point
    """
    max_odd = (1 << (w-1)) - 1
    tbl = {}
    Pj = point_to_jacobian(P_aff)
    tbl[1] = P_aff
    if max_odd < 3:
        return tbl
    twoP = jacobian_point_double(Pj, p_mod)
    twoP_aff = jacobian_to_point(twoP, p_mod)
    odd = P_aff
    # odd = 1*P, then odd + 2P -> 3P, etc
    for i in range(3, max_odd + 1, 2):
        # odd = odd + 2P
        odd_j = point_to_jacobian(odd)
        next_j = jacobian_point_add(odd_j, twoP, p_mod)
        odd = jacobian_to_point(next_j, p_mod)
        tbl[i] = odd
    return tbl

def wnaf_mul(k: int, P_aff: Point, w: int = 5, p_mod: int = P) -> Point:
    """基于 wNAF 的标量乘（支持任意点）"""
    if P_aff is None:
        return None
    n = N
    k = k % n
    if k == 0:
        return None
    wnaf = compute_wnaf(k, w)
    tbl = precompute_window(P_aff, w, p_mod)
    R = None
    # process from most-significant digit to least -> reversed(wnaf)
    for d in reversed(wnaf):
        # R = 2*R
        if R is not None:
            R = jacobian_point_double(R, p_mod)
        if d != 0:
            if d > 0:
                add_aff = tbl.get(d)
                if add_aff is None:
                    # should not happen, but fallback: compute by double_and_add
                    add_aff = double_and_add_mul(d, P_aff, p_mod)
                R = jacobian_point_add(R, point_to_jacobian(add_aff), p_mod)
            else:
                # negative
                add_aff = tbl.get(-d)
                if add_aff is None:
                    add_aff = double_and_add_mul(-d, P_aff, p_mod)
                neg = (add_aff[0], (-add_aff[1]) % p_mod)
                R = jacobian_point_add(R, point_to_jacobian(neg), p_mod)
    return jacobian_to_point(R, p_mod)

# ---------------------------- 固定点 G 的预计算表（优化） ----------------------------
G_TABLE: Optional[Dict[int, JacPoint]] = None

def init_g_table(w: int = 5):
    """初始化固定点 G 的预计算表（存储奇数倍 G,3G,5G,... up to (2^{w-1}-1)G）"""
    global G_TABLE
    if G_TABLE is not None:
        return
    G_TABLE = {}
    G_j = (G_X, G_Y, 1)
    G_TABLE[1] = G_j
    # 计算 2G
    twoG = jacobian_point_double(G_j, P)
    # 依次得到 3G,5G,... by odd += 2G
    odd = G_j
    max_odd = (1 << (w-1)) - 1
    for k in range(3, max_odd + 1, 2):
        odd = jacobian_point_add(odd, twoG, P)
        G_TABLE[k] = odd

def fixed_point_mul(k: int, table: Dict[int, JacPoint], w: int = 5) -> Point:
    """
    使用奇数倍表的固定点乘法（窗口宽度 w）
    算法：将 k 分片，每片 w 位；逐片执行 w 次点倍（左移）然后加上对应的表项（若为偶数转换为奇数+G）
    这里实现一个稳妥版本：我们简单把 k 转成一系列窗口值，从高到低处理。
    """
    if table is None:
        return None
    if k % N == 0:
        return None
    max_bit = k.bit_length()
    # choose number of windows
    result = None
    # process from high to low windows
    for i in range(max_bit - 1, -1, -w):
        # do up to w doublings
        if result is not None:
            # double w times (or fewer if near msb)
            times = min(w, i + 1)
            for _ in range(times):
                result = jacobian_point_double(result, P)
        # extract window value
        start = max(0, i - w + 1)
        chunk = (k >> start) & ((1 << (i - start + 1)) - 1)
        if chunk == 0:
            continue
        # if chunk is odd and in table
        if chunk % 2 == 1 and chunk in table:
            add_j = table[chunk]
        else:
            # fallback: compute chunk * G via wnaf_mul on affine G
            add_aff = wnaf_mul(chunk, (G_X, G_Y), w, P)
            add_j = point_to_jacobian(add_aff) if add_aff is not None else None
        if add_j is None:
            continue
        if result is None:
            result = add_j
        else:
            result = jacobian_point_add(result, add_j, P)
    return jacobian_to_point(result, P) if result is not None else None

# ---------------------------- ZA, 密钥与签名相关 ----------------------------
def compute_za(user_id: str, public_key: Tuple[int, int]) -> bytes:
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

def generate_keypair() -> Tuple[int, Tuple[int, int]]:
    """使用可靠的 baseline 生成密钥对"""
    private_key = secrets.randbelow(N - 1) + 1
    public_key = double_and_add_mul(private_key, (G_X, G_Y), P)
    return private_key, public_key

def sm2_sign(private_key: int, msg: bytes, user_id: str = "1234567812345678") -> Tuple[int, int]:
    """SM2签名（使用 double-and-add 生成公钥保证正确性；对 k 的点乘使用 wNAF）"""
    # 初始化预计算表（可选）
    init_g_table(w=5)
    # 使用 baseline 生成公钥，保证正确
    public_key = double_and_add_mul(private_key, (G_X, G_Y), P)
    za = compute_za(user_id, public_key)
    m = za + msg
    e = int.from_bytes(sm3_hash(m), 'big') % N

    while True:
        k = secrets.randbelow(N - 1) + 1
        # 计算 R = kG （用 wNAF）
        R = wnaf_mul(k, (G_X, G_Y), w=5, p_mod=P)
        if R is None:
            continue
        r = (e + R[0]) % N
        if r == 0 or r + k == N:
            continue
        try:
            inv = inverse_mod(1 + private_key, N)
        except ZeroDivisionError:
            continue
        s = (inv * (k - r * private_key)) % N
        if s != 0:
            return (r, s)

def sm2_verify(public_key: Tuple[int, int], msg: bytes, signature: Tuple[int, int], user_id: str = "1234567812345678") -> bool:
    r, s = signature
    if not (1 <= r < N and 1 <= s < N):
        return False
    za = compute_za(user_id, public_key)
    m = za + msg
    e = int.from_bytes(sm3_hash(m), 'big') % N
    t = (r + s) % N
    if t == 0:
        return False
    # sG + tP
    sG = wnaf_mul(s, (G_X, G_Y), w=5, p_mod=P)
    tP = wnaf_mul(t, public_key, w=5, p_mod=P)
    if sG is None or tP is None:
        return False
    R_j = jacobian_point_add(point_to_jacobian(sG), point_to_jacobian(tP), P)
    if R_j is None:
        return False
    R_aff = jacobian_to_point(R_j, P)
    if R_aff is None:
        return False
    return (e + R_aff[0]) % N == r

# ---------------------------- 测试/验证辅助 ----------------------------
def is_on_curve(Pt: Point) -> bool:
    if Pt is None:
        return False
    x, y = Pt
    return (y * y - (x * x * x + A * x + B)) % P == 0

def test_sm2():
    print("=== SM2签名算法测试（优化版） ===")
    private_key, public_key = generate_keypair()
    print(f"私钥: {hex(private_key)}")
    print(f"公钥: ({hex(public_key[0])}, {hex(public_key[1])})")
    print("公钥在曲线上:", is_on_curve(public_key))
    message = b"Hello, SM2!"
    signature = sm2_sign(private_key, message)
    print(f"签名 (r, s): ({hex(signature[0])}, {hex(signature[1])})")
    is_valid = sm2_verify(public_key, message, signature)
    print(f"签名验证: {'成功' if is_valid else '失败'}")
    # 测试错误签名
    wrong_signature = (signature[0], (signature[1] + 1) % N)
    is_valid_wrong = sm2_verify(public_key, message, wrong_signature)
    print(f"错误签名验证: {'成功（危险）' if is_valid_wrong else '失败（正常）'}")

if __name__ == "__main__":
    test_sm2()
