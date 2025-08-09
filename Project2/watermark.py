import cv2
import numpy as np
from matplotlib import pyplot as plt
import os

def embed_watermark(original_img_path, watermark_text, output_path, alpha=0.1):
    # 读取原始图像
    img = cv2.imread(original_img_path, cv2.IMREAD_GRAYSCALE)
    
    # 对图像进行DCT变换
    dct = cv2.dct(np.float32(img)/255.0)
    
    # 将水印文本转换为二进制
    watermark_binary = ''.join(format(ord(c), '08b') for c in watermark_text)
    watermark_len = len(watermark_binary)
    
    # 在DCT系数中嵌入水印
    rows, cols = dct.shape
    pos = 0
    
    for i in range(rows):
        for j in range(cols):
            if pos < watermark_len:
                # 修改中频系数嵌入水印
                if 10 < i < 50 and 10 < j < 50:
                    if watermark_binary[pos] == '1':
                        dct[i,j] += alpha * abs(dct[i,j])
                    else:
                        dct[i,j] -= alpha * abs(dct[i,j])
                    pos += 1
    
    # 逆DCT变换
    watermarked_img = cv2.idct(dct) * 255.0
    watermarked_img = np.uint8(np.clip(watermarked_img, 0, 255))
    
    # 保存水印图像
    cv2.imwrite(output_path, watermarked_img)
    
    return watermarked_img

def extract_watermark(watermarked_img_path, original_img_path, watermark_length, alpha=0.1):
    # 读取原始图像和水印图像
    original_img = cv2.imread(original_img_path, cv2.IMREAD_GRAYSCALE)
    watermarked_img = cv2.imread(watermarked_img_path, cv2.IMREAD_GRAYSCALE)
    
    # 对两幅图像进行DCT变换
    original_dct = cv2.dct(np.float32(original_img)/255.0)
    watermarked_dct = cv2.dct(np.float32(watermarked_img)/255.0)
    
    # 提取水印
    extracted_binary = ''
    pos = 0
    rows, cols = original_dct.shape
    
    for i in range(rows):
        for j in range(cols):
            if pos < watermark_length * 8:  # 每个字符8位
                # 在中频系数中提取水印
                if 10 < i < 50 and 10 < j < 50:
                    if watermarked_dct[i,j] > original_dct[i,j]:
                        extracted_binary += '1'
                    else:
                        extracted_binary += '0'
                    pos += 1
    
    # 将二进制转换为字符串
    watermark = ''
    for i in range(0, len(extracted_binary), 8):
        byte = extracted_binary[i:i+8]
        watermark += chr(int(byte, 2))
    
    return watermark[:watermark_length]  # 返回指定长度的水印

def robustness_tests(image_path, watermark_text):
    # 嵌入水印
    watermarked_img = embed_watermark(image_path, watermark_text, "/Users/apple/sdu-practice/Project2/watermarked.png")
    
    # 1. 旋转测试
    rotated = cv2.rotate(watermarked_img, cv2.ROTATE_90_CLOCKWISE)
    cv2.imwrite("/Users/apple/sdu-practice/Project2/rotated.png", rotated)
    
    # 2. 裁剪测试
    h, w = watermarked_img.shape
    cropped = watermarked_img[h//4:3*h//4, w//4:3*w//4]
    cv2.imwrite("/Users/apple/sdu-practice/Project2/cropped.png", cropped)
    
    # 3. 对比度调整
    contrast = np.clip(watermarked_img * 1.5, 0, 255).astype(np.uint8)
    cv2.imwrite("/Users/apple/sdu-practice/Project2/contrast.png", contrast)
    
    # 4. 亮度调整
    brightness = np.clip(watermarked_img + 50, 0, 255).astype(np.uint8)
    cv2.imwrite("/Users/apple/sdu-practice/Project2/brightness.png", brightness)
    
    # 5. 添加噪声
    noise = np.random.normal(0, 25, watermarked_img.shape)
    noisy = np.clip(watermarked_img + noise, 0, 255).astype(np.uint8)
    cv2.imwrite("/Users/apple/sdu-practice/Project2/noisy.png", noisy)
    
    # 提取各测试图像中的水印
    original_path = image_path
    wm_length = len(watermark_text)
    
    results = {
        "original": extract_watermark("/Users/apple/sdu-practice/Project2/watermarked.png", original_path, wm_length),
        "rotated": extract_watermark("/Users/apple/sdu-practice/Project2/rotated.png", original_path, wm_length),
        "cropped": extract_watermark("/Users/apple/sdu-practice/Project2/cropped.png", original_path, wm_length),
        "contrast": extract_watermark("/Users/apple/sdu-practice/Project2/contrast.png", original_path, wm_length),
        "brightness": extract_watermark("/Users/apple/sdu-practice/Project2/brightness.png", original_path, wm_length),
        "noisy": extract_watermark("/Users/apple/sdu-practice/Project2/noisy.png", original_path, wm_length)
    }
    
    return results

if __name__ == "__main__":
    # 测试图像和水印文本
    image_path = "/Users/apple/sdu-practice/Project2/1.png"  # 测试图像
    print(f"文件存在: {os.path.exists(image_path)}")
    print(f"绝对路径: {os.path.abspath(image_path)}")
    watermark_text = "SECRET2025"  # 10字符水印
    
    # 嵌入和提取演示
    watermarked_img = embed_watermark(image_path, watermark_text, "/Users/apple/sdu-practice/Project2/watermarked.png")
    extracted = extract_watermark("/Users/apple/sdu-practice/Project2/watermarked.png", image_path, len(watermark_text))
    print(f"提取的水印: {extracted}")
    
    # 鲁棒性测试
    test_results = robustness_tests(image_path, watermark_text)
    
    print("\n鲁棒性测试结果:")
    for test, result in test_results.items():
        print(f"{test}: {result} (正确率: {sum(1 for a, b in zip(watermark_text, result) if a == b)/len(watermark_text)*100:.1f}%)")
