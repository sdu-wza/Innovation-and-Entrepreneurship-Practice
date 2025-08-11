# Project 4: 基于SM3的高效实现与Merkle树构建及证明

## 项目背景

随着国产密码标准的推广，SM3作为国家密码杂凑算法被广泛应用于数据完整性与认证场景。Merkle树作为一种树状哈希结构，为大规模数据的完整性校验和归属证明提供了高效的方案。

本项目分三部分：

- **a) SM3软件实现与性能优化**  
- **b) 基于SM3的长度扩展攻击实验**  
- **c) 基于SM3的Merkle树构建及存在性/不存在性证明设计与实现**

---

## a) SM3软件实现与性能优化

### 算法简介

SM3是一个迭代哈希函数，输出256位摘要。采用Merkle–Damgård结构，包含消息填充、消息扩展和64轮压缩。

消息扩展采用：
`
W_j = \begin{cases}
M_j, & 0 \leq j \leq 15 \\
P_1(W_{j-16} \oplus W_{j-9} \oplus (W_{j-3} \lll 15)) \oplus (W_{j-13} \lll 7) \oplus W_{j-6}, & 16 \leq j \leq 67
\end{cases}
`

其中，非线性变换函数定义：

`
P_0(x) = x \oplus (x \lll 9) \oplus (x \lll 17)
`
`
P_1(x) = x \oplus (x \lll 15) \oplus (x \lll 23)
`

压缩函数64轮迭代采用函数FF和GG，不同轮使用不同逻辑。

### 实现思路

- 使用位操作宏（`ROTL32`, `P0`, `P1`等）提升代码可读性与性能。
- 设计`sm3_compress`函数实现核心64轮压缩。
- 支持流式输入，设计`sm3_init`, `sm3_update`, `sm3_final`接口。
- 采用大端转换保证跨平台一致性。

### 优化点

- 循环展开与中间变量复用，减少函数调用和内存访问。
- 采用宏定义实现高效位操作。
- 对数据块处理进行边界优化，避免多余复制。


### 运行结果

基础实现：
![image](https://github.com/sdu-wza/Innovation-and-Entrepreneurship-Practice/blob/main/Project4/image/basic.png)

优化：
![image](https://github.com/sdu-wza/Innovation-and-Entrepreneurship-Practice/blob/main/Project4/image/optimized.png)

## b) SM3长度扩展攻击实验

### 理论基础  
SM3基于**Merkle–Damgård结构**，存在长度扩展攻击漏洞：  
已知消息 `M` 及其摘要 `H(M)`，攻击者可无需密钥推算出 `H(M || padding || M')`，伪造合法摘要。  

### 实验设计  
1. 给定消息 `M` 和 `H(M)`，构造带有填充的消息后缀 `M'`。  
2. 利用 `H(M)` 作为初始状态，继续哈希 `M'`，计算 `H(M || padding || M')`。  
3. 验证伪造哈希和完整哈希一致。

### 运行结果

![image](https://github.com/sdu-wza/Innovation-and-Entrepreneurship-Practice/blob/main/Project4/image/attack.png)



### 实验意义  
通过实际代码验证SM3的长度扩展攻击风险，为密码工程提供安全警示。  


## c) 基于SM3的Merkle树构建及证明设计与实现

### Merkle树概述  
Merkle树是一种**二叉树结构**：  
- **叶子节点**：数据块的SM3哈希值。  
- **内部节点**：子节点哈希拼接后的SM3哈希值。  
- **树根**：全树数据的唯一摘要。  
- **存在性证明**：通过叶子到根的兄弟节点哈希路径验证。  

### 设计实现  
#### 1. 树结构设计  
- **存储方式**：数组存储完全二叉树（索引计算高效，内存连续）。  
- **补全规则**：叶子节点数不足2的幂时，补充零哈希节点。  

#### 2. 哈希计算  
- 内部节点哈希 = `SM3(左子节点哈希 || 右子节点哈希)`  

#### 3. 证明机制  
- **存在性证明**：  
  1. 输入叶子索引 → 获取路径兄弟哈希  
  2. 递归计算哈希 → 对比最终根哈希  
- **不存在性证明**：  
  1. 目标哈希排序后，二分查找其前驱和后继叶子节点  
  2. 提供二者的存在性证明  
  3. 验证 `前驱 < 目标 < 后继` 且二者存在  

### 运行结果

![image](https://github.com/sdu-wza/Innovation-and-Entrepreneurship-Practice/blob/main/Project4/image/merkle.png)

