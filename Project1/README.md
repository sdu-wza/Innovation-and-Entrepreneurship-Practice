# Project 1：SM4软件实现与优化

## a) 基础实现与优化
从基本实现出发优化SM4的软件执行效率，优化方案应至少覆盖：
- T-table查找表优化
- AESNI指令集优化
- 最新指令集优化（包括但不限于）：
  * GFNI（Galois Field New Instructions）
  * VPROLD（Variable Rotate Left Doubleword）等SIMD指令

## b) SM4-GCM工作模式实现
基于SM4的实现，完成：
- SM4-GCM认证加密工作模式的软件实现
- 针对GCM模式的特定优化
