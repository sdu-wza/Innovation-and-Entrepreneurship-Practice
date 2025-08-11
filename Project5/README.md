# Project 5: SM2椭圆曲线密码算法实现优化与安全性分析

## 项目背景

SM2作为我国商用密码体系的核心算法，在数字签名、密钥交换等领域具有重要应用。本项目围绕SM2实现三个关键目标：

- **a) SM2基础实现与算法优化**  
- **b) 签名算法误用场景的POC验证**  
- **c) 数字签名伪造的原理性演示**

---

## a) SM2基础实现与算法优化

### 算法核心结构
```python
class SM2:
    def __init__(self):
        # 国标参数初始化（256位素数域）
        self.p = 0x8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3
        self.a = 0x787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498
        self.G = (0x421DEBD61B62EAB6..., 0x0680512BCBB42C07...)
        self.n = 0x8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7
```
### 关键优化技术

1. Jacobian坐标加速：点加运算从12M+4S优化至8M+3S，避免模逆运算，采用投影坐标转换

2. 固定点预计算（窗口法）

3. NAF编码优化

### 运行结果

basic：

![image](https://github.com/sdu-wza/Innovation-and-Entrepreneurship-Practice/blob/main/Project5/image/basic.png)

optimized:

![image](https://github.com/sdu-wza/Innovation-and-Entrepreneurship-Practice/blob/main/Project5/image/optimized.png)

---

## b) 签名算法误用POC验证


### 泄露随机数k

SM2签名算法：`s = (1 + d_A)^(-1) · (k - r · d_A) mod n`

其中：`r = e + x_1 mod n，e = Hash(Z_A || M)`

如果随机数k被泄露，攻击者可以通过以下方式计算私钥：

`
s = (1 + d_A)^(-1) · (k - r · d_A) mod n
s · (1 + d_A) = k - r · d_A mod n
s + s · d_A = k - r · d_A mod n
s · d_A + r · d_A = k - s mod n
d_A · (s + r) = k - s mod n
d_A = (s + r)^(-1) · (k - s) mod n
`

运行结果：

![image](https://github.com/sdu-wza/Innovation-and-Entrepreneurship-Practice/blob/main/Project5/image/leak_k.png)

### 重复使用k（同一用户）

如果同一用户对两个不同消息使用相同的k：

消息1：`s1 = (1 + d_A)^(-1) · (k - r1 · d_A) mod n`
消息2：`s2 = (1 + d_A)^(-1) · (k - r2 · d_A) mod n`

推导过程：
`
s1 · (1 + d_A) = k - r1 · d_A mod n
s2 · (1 + d_A) = k - r2 · d_A mod n
`
两式相减：
`
(s1 - s2) · (1 + d_A) = (r2 - r1) · d_A mod n
s1 - s2 + (s1 - s2) · d_A = (r2 - r1) · d_A mod n
s1 - s2 = (r2 - r1 - s1 + s2) · d_A mod n
`
`
d_A = (s2 - s1) / (s1 - s2 + r1 - r2) mod n
`

运行结果：
![image](https://github.com/sdu-wza/Innovation-and-Entrepreneurship-Practice/blob/main/Project5/image/k_reuse.png)

### 不同用户重复使用k

Alice签名：`s1 = (1 + d_A)^(-1) · (k - r1 · d_A) mod n`
Bob签名：`s2 = (1 + d_B)^(-1) · (k - r2 · d_B) mod n`

如果Alice知道k，可以恢复Bob的私钥：
`
s2 · (1 + d_B) = k - r2 · d_B mod n
s2 + s2 · d_B = k - r2 · d_B mod n
d_B · (s2 + r2) = k - s2 mod n
d_B = (k - s2) / (s2 + r2) mod n
`

运行结果：
![image](https://github.com/sdu-wza/Innovation-and-Entrepreneurship-Practice/blob/main/Project5/image/k_reuse_diff.png)


### SM2与ECDSA使用相同d和k

数学推导：

ECDSA签名：`s1 = k^(-1) · (e1 + r1 · d) mod n`
SM2签名：`s2 = (1 + d)^(-1) · (k - r2 · d) mod n`

从ECDSA恢复关系：`d · r1 = k · s1 - e1 mod n`
从SM2恢复关系：`d · (s2 + r2) = k - s2 mod n`

联立求解：
`
d = (s1 · s2 - e1) / (r1 - s1 · s2 - s1 · r2) mod n
`
运行结果：
![image](https://github.com/sdu-wza/Innovation-and-Entrepreneurship-Practice/blob/main/Project5/image/same_d_k.png)

---

## c) 数字签名伪造演示

SM2签名验证机制
`
ZA = SM3(ENTL∥ID∥a∥b∥xG∥yG∥xA∥yA)  
e = SM3(ZA ∥ M)  
验证：sG + (r+s)P ≡ R (mod p)
`

伪造局限性分析:

1. ZA屏障：攻击者无法获取目标公钥的真实ZA值

2. 数学约束：验证方程含曲线参数哈希，无法自由构造有效签名

### 运行结果

![image](https://github.com/sdu-wza/Innovation-and-Entrepreneurship-Practice/blob/main/Project5/image/forgery.png)

---

## 项目总结

安全启示：

1. 随机数安全：k值必须密码学安全随机且不重复

2. 密钥隔离：不同算法需使用独立密钥对

3. 参数校验：验证时严格检查所有输入范围
