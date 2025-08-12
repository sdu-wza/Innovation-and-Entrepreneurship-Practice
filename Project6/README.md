# Project 6: Google Password Checkup 验证

## 1. 背景

Google Password Checkup 协议用于在不泄露用户明文密码的前提下，检测其凭据是否出现在泄露数据库中。  
本实验参考论文 [《Private Set Membership Checking with Application to Password Breach Alerting》](https://eprint.iacr.org/2019/723.pdf) 第 3.1 节及 Figure 2 协议，使用 **椭圆曲线密码学 (ECC)** 实现了一个简化版的验证流程。

与原论文一致，我们使用了基于**盲化 (Blinding)** 的双边指数交换思路，只不过在本实验中选择了曲线 `secp256r1` (P-256) 进行标量域运算，以演示协议的数学原理。

---

## 2. 协议原理

协议核心思想：
1. 客户端将 `(username:password)` 哈希为一个曲线标量 `s`，对应曲线点 `P = s·G`（`G` 为基点）。
2. 客户端选择随机因子 `a` 对 `P` 进行盲化（`a·P`），发送给服务器。
3. 服务器持有私钥 `b`，对接收到的点进行二次标量乘法（`b·(a·P)`），并将泄露凭据桶内的每个点 `Y` 也进行 `b` 次标量乘法。
4. 客户端对服务器返回的桶元素再次乘以 `a`，得到 `a·b·Y`，若与 `a·b·P` 匹配，则说明密码已泄露。

### 数学性质

利用椭圆曲线群中标量乘法的可交换性：`b·(a·P) = a·(b·P) = (a·b)·P`

因此服务器无法恢复 `P`（不知道 `a`），客户端无法反推出 `b`（不知道 `b`），但双方可以在盲化空间中比较。

---

## 3. 协议流程

以下记：
- `H()` 为 SHA-256 哈希
- `n` 为曲线 P-256 的阶
- `mod n` 表示模 `n` 取余

#### 1. 服务器初始化
- 生成私钥 `b ∈ [1, n-1]`
- 对泄露数据库中每条 `(u, p)`：
  - `h = H(u:p)`
  - `prefix = h[:key_len]`
  - `s = int(h) mod n`
  - 存储 `s` 到对应 `prefix` 桶

#### 2. 客户端查询
- 选择随机 `a ∈ [1, n-1]`
- 计算自己的 `h, prefix, s`
- 计算 `blinded = a·s mod n`
- 向服务器发送 `(prefix, blinded)`

#### 3. 服务器响应
- 查找桶 `bucket = DB[prefix]`
- 计算 `A' = b·blinded mod n`
- 对桶中每个 `y` 计算 `y_b = b·y mod n`
- 返回 `(A', [y_b])`

#### 4. 客户端验证
- 对每个 `y_b` 计算 `y_ba = a·y_b mod n`
- 如果 `A'` 在集合 `{y_ba}` 中，则密码已泄露

---

## 4. 实现细节

- **曲线选择**：`secp256r1` (P-256)，阶 `n = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551`
- **哈希映射到标量**：取 SHA-256 前 `hash_len` 字节转整数并 mod `n`（若结果为 0 则置为 1）
- **分桶策略**：取哈希前 `key_len` 字节作为桶前缀
- **盲化**：直接在标量域做乘法，避免手写曲线点运算，便于教学
- **安全性**：本实现是演示性质，缺少零知识证明、抗主动攻击等防御

---

## 5. 运行结果

测试用户“test”的密码“password”，确实已泄露：

![image](https://github.com/sdu-wza/Innovation-and-Entrepreneurship-Practice/blob/main/Project6/image/result.png)

---

## 6. 安全说明与改进方向

1. Hash-to-Curve：使用简单的 mod n 方法映射哈希到标量，生产系统应使用 RFC 9380 等标准安全映射。

2. 曲线运算：本代码将所有点运算等价转换为标量乘法以便演示，真实系统应使用安全曲线库（OpenSSL, libsodium, WebCrypto）。

3. 协议防御：需防止主动攻击、重放攻击、信息泄露，可通过零知识证明、OT 协议、速率限制等加强。

4. 桶大小：生产环境需保证桶内元素数量足够大（k-anonymity）。

5. 侧信道防护：应使用恒时比较与加密数据传输，避免时序与流量分析。
