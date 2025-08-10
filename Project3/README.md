# Project3: Poseidon2 哈希算法 Circom 电路实现与 Groth16 零知识证明

## 1. 项目背景与意义

Poseidon2 是一种面向零知识证明场景优化的哈希函数，旨在提供高效且安全的哈希计算，特别适用于电路复杂度敏感的环境，如 zk-SNARKs、zk-STARKs 等。其设计基于 Sponge 架构，通过设计专门的 S-box 和线性层（MDS矩阵）实现良好的安全性与高效性平衡。

本项目基于 Poseidon2 论文中的参数 `(n,t,d) = (256,3,5)`，使用 Circom 2.2.2 语言实现了对应哈希电路，并通过 snarkjs 完成 Groth16 零知识证明的可信设置、证明生成和验证。

---

## 2. 算法原理及数学推导

### 2.1 Poseidon2 基础

Poseidon2 采用 Sponge 结构进行吸收和挤压。核心状态大小为 \( t \) 个 field 元素，通常选择适应电路设计的参数。

每轮计算包括：

1. **加轮常数**：


`\mathbf{s} \leftarrow \mathbf{s} + \mathbf{c}_r`


其中 \(\mathbf{s}\) 是当前状态向量，\(\mathbf{c}_r\) 是第 \(r\) 轮的轮常数。

2. **S-box 非线性变换**：

对状态中的部分元素应用非线性映射 \(\phi(x) = x^d\)，其中 \(d=5\) 是指数幂。

完整轮对所有元素进行 S-box 计算，部分轮只对部分元素（如第一个元素）应用 S-box。

3. **MDS 矩阵线性变换**：

`
\mathbf{s} \leftarrow M \times \mathbf{s}
`

其中 \(M\) 是满足最大距离可分离性（Maximum Distance Separable）的矩阵，保证良好的扩散性。

### 2.2 参数选取

- \(t = 3\)：状态大小，包含3个元素
- \(d = 5\)：S-box 非线性指数
- 完整轮数：8
- 部分轮数：57

具体轮数和参数来源于论文[Poseidon2](https://eprint.iacr.org/2023/323.pdf)中针对安全级别的设计。

---

## 3. 电路设计思路

### 3.1 输入输出定义

- 私有输入：哈希原象，长度为状态大小 \(t=3\) 的 field 元素数组 `in[3]`
- 公开输出：哈希值，电路最终状态的第一个元素 `out`

### 3.2 轮常数和 MDS 矩阵

为简化实现，采用论文参数的简化版本：

- 轮常数为固定常数数组 `round_constants[65][3]`
- MDS 矩阵为3×3数组，确保良好扩散

> 实际生产环境应使用论文附录中的标准参数。

### 3.3 S-box 实现

利用电路组件 `Pow5` 计算输入的五次方：


`x^5 = x \times x^2 \times x^2`


用中间变量减少约束数。

### 3.4 电路主流程

1. 初始化状态为输入 `in`。
2. 对每一轮（共 65 轮）执行：
   - 加轮常数
   - S-box 变换（完整轮对所有元素，部分轮只对第一个元素）
   - MDS 矩阵乘法实现线性扩散
3. 输出最后一轮状态的第一个元素作为哈希值。

---

## 4. 实现细节

- 使用 `template Poseidon2()` 封装主电路，结构清晰，方便扩展参数。
- S-box 使用单独组件 `Pow5()`，提升复用性。
- 电路约束条数与轮数和状态大小成正比，65轮设计较为折中。
- 采用 Circom 2.2.2 版本，兼容最新语法。

---

## 5. 环境搭建与使用流程

### 5.1 依赖安装

- 安装 Node.js (版本 >= 14)
- 安装 Circom 2.2.2
- 全局安装 snarkjs：

### 5.2 编译电路

```bash
circom poseidon2.circom --r1cs --wasm --sym
```
![image](https://github.com/sdu-wza/Innovation-and-Entrepreneurship-Practice/blob/main/Project3/image/poseidon2.png)

### 5.3 准备输入

进入 poseidon2_js 目录，创建测试输入文件：

```bash
echo '{"in": [1, 2, 3]}' > input.json
```
### 5.4 计算 Witness

```bash
node generate_witness.js poseidon2.wasm input.json witness.wtns
```
### 5.5 可信设置

```bash
snarkjs powersoftau new bn128 12 pot12_0000.ptau -v
snarkjs powersoftau contribute pot12_0000.ptau pot12_0001.ptau --name="First contribution" -v
snarkjs powersoftau prepare phase2 pot12_0001.ptau pot12_final.ptau -v
snarkjs groth16 setup poseidon2.r1cs pot12_final.ptau poseidon2_0000.zkey
snarkjs zkey contribute poseidon2_0000.zkey poseidon2_0001.zkey --name="Second contribution" -v
```
### 5.6 导出验证密钥

```bash
snarkjs zkey export verificationkey poseidon2_0001.zkey verification_key.json
```
### 5.7 生成证明

```bash
snarkjs groth16 prove poseidon2_0001.zkey witness.wtns proof.json public.json
```
### 5.8 验证证明

```bash
snarkjs groth16 verify verification_key.json public.json proof.json
```

![image](https://github.com/sdu-wza/Innovation-and-Entrepreneurship-Practice/blob/main/Project3/image/verify.png)
---

## 6. 实验结果与分析

- 使用输入 [1, 2, 3] 计算出的哈希值符合电路预期。

- Groth16 证明文件正确生成，验证成功。

- 证明大小和验证时间与电路复杂度成正比，符合预期。
