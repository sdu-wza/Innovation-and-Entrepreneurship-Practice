# 基于数字水印的图片泄露检测系统

![Python](https://img.shields.io/badge/Python-3.7%2B-blue)
![OpenCV](https://img.shields.io/badge/OpenCV-4.5%2B-green)
![License](https://img.shields.io/badge/License-MIT-orange)

一个基于DCT变换的数字水印系统，支持水印嵌入、提取和鲁棒性测试。

## 项目简介

本项目实现了基于离散余弦变换(DCT)的数字水印技术，主要功能包括：
- 将文本信息作为水印嵌入到图像中
- 从图像中提取隐藏的水印信息
- 测试水印对常见图像处理的鲁棒性

## 技术原理

### 水印嵌入流程
1. 将水印文本转换为二进制串
2. 对原始图像进行8×8分块DCT变换
3. 在中频系数中嵌入水印信息
4. 进行逆DCT变换重建图像

### 水印提取流程
1. 对含水印图像进行DCT变换
2. 比较含水印图像与原始图像的DCT系数差异
3. 提取二进制水印信息
4. 将二进制串转换为文本

## 安装与使用

### 依赖安装
```bash
pip install opencv-python numpy pillow scikit-image matplotlib
