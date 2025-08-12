# Project 1：SM4软件实现与优化

## a) 基础实现与优化

## 基础实现

### 加密流程

1. 轮密钥加：明文与轮密钥异或

2. S盒替换：使用固定8bit S盒（示例中sm4_sbox）

3. 线性变换L：`L(x) = x ^ rol(x,2) ^ rol(x,10) ^ rol(x,18) ^ rol(x,24)`

4. 32轮迭代后反序输出

### 运行结果

![image](https://github.com/sdu-wza/Innovation-and-Entrepreneurship-Practice/blob/main/Project1/image/basic.png)

## T-table优化

### 实验原理

1. 将 S-box（τ）与线性变换 L 合并为四张表 T0..T3，每张 256 项，每项为 32-bit。

2. 对于字 a（32-bit big-endian），计算 `T0[a>>24] ^ T1[(a>>16)&0xFF] ^ T2[(a>>8)&0xFF] ^ T3[a&0xFF] 得到 L(τ(a))`。

### 运行结果

![image](https://github.com/sdu-wza/Innovation-and-Entrepreneurship-Practice/blob/main/Project1/image/t-table.png)

优化效果显著。

## AES-NI优化

### 实验原理

SM4 S-box 可以表示为：对输入字节做 GF(2^8) 的逆元计算，然后做仿射变换。AES S-box 也是同样的结构（逆元 + 仿射），只是使用的不可约多项式或 affine 常数不同。

若存在从 SM4 域到 AES 域的线性同构矩阵 M（8×8 over GF(2)）和常数向量，使得：`S_sm4(x) = A_sm4(Inv_sm4(x)) ⊕ c_sm4`。与 AES S-box 满足类似关系：通过 M 把 SM4 的输入映射到 AES 域，调用 AES 的 S-box（用 AES-NI），再把输出映回 SM4 域并做最后的仿射修正。

这样可以把单字节 S-box 计算替换成：两次矩阵乘/仿射 + AES-NI 指令，适合并行向量化处理。


### 运行结果

![image](https://github.com/sdu-wza/Innovation-and-Entrepreneurship-Practice/blob/main/Project1/image/aesni.png)

优化效果更好。

 ---

## b)SM4-GCM优化

### SM4-GCM 工作模式原理
SM4-GCM（Galois/Counter Mode）是一种将分组加密算法（此处为 SM4）与消息认证码结合的加密模式，能够同时提供机密性与完整性。它由两部分组成：

1. 加密部分（CTR 模式）

使用计数器模式（Counter Mode）对明文加密：

· 将初始计数器 IV 与分组序号组合，形成唯一的输入块。

· 用 SM4 对该输入块加密得到密钥流。

· 将密钥流与明文按字节异或得到密文。

CTR 模式的特点是：

· 无需解密函数，解密过程与加密完全相同。

· 各分组之间独立，可并行处理。

2. 认证部分（GHASH 运算）

在 GF(2^128) 有限域上对密文和附加数据（AAD）进行多项式哈希：`GHASH(H, X) = ( ( (0 ⊕ C1)·H ⊕ C2)·H ⊕ ... )·H`

其中 H = E_K(0^128) 是通过 SM4 加密全零块得到的哈希子密钥。GF(2^128) 乘法是无进位乘法（Carry-less Multiplication）。

### SM4-GCM 的优化原理

1. 加密部分优化（CTR 并行化）
   
· 批量计数器生成：在一个循环中一次性生成多个连续的计数器值（如 4 个或 8 个）。

· SIMD 指令并行加密：利用 AES-NI/GFNI/VPROLD 对 SM4 的 SBox 和 L 变换进行向量化，实现一次加密多个 128-bit 分组，充分利用 CPU 的流水线和向量寄存器资源。

2. 认证部分优化（PCLMULQDQ 加速 GHASH）

· PCLMULQDQ 是 Intel 提供的无进位乘法指令，可直接在 GF(2^128) 上做乘法运算。

· 将 128-bit 的分组拆成两个 64-bit 部分，利用 PCLMULQDQ 进行乘法，再用异或组合结果。

· 可通过流水线化的方式，在加密的同时计算 GHASH，减少总延迟。

3. 指令集增强（GFNI / VPROLD）

· GFNI：可在 GF(2^8) 上直接实现 SM4 SBox 所需的仿射变换，减少查表延迟。

· VPROLD（AVX-512 扩展）：支持对向量寄存器的 32-bit 元素进行循环左移，实现 SM4 的 L 变换比传统移位和异或更高效。


 ### 运行结果

 ![image](https://github.com/sdu-wza/Innovation-and-Entrepreneurship-Practice/blob/main/Project1/image/gcm.png)

