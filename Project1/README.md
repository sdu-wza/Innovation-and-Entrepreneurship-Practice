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

 b)SM4-GCM优化

### 实验原理

GHASH 基本运算是多次在 GF(2^128) 上的乘法（H 为 hash key，X_i 为数据块，Z = Σ X_i · H^{n-i}）。

加速点是 GF(2^128) 乘法与矢量化约减。

 ### 运行结果

 ![image](https://github.com/sdu-wza/Innovation-and-Entrepreneurship-Practice/blob/main/Project1/image/gcm.png)

