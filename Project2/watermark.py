import numpy as np
import cv2
from PIL import Image
import matplotlib.pyplot as plt
from skimage.util import random_noise
from skimage import transform as tf

class DCTWatermark:
    def __init__(self, alpha=0.2):
        self.alpha = alpha  # 水印强度
    
    def _text_to_bits(self, text):
        """将文本转换为二进制串"""
        return ''.join(format(ord(c), '08b') for c in text)
    
    def _bits_to_text(self, bits):
        """将二进制串转换为文本"""
        return ''.join(chr(int(bits[i:i+8], 2)) for i in range(0, len(bits), 8))
    
    def embed(self, original_img, watermark_text):
        """嵌入文本水印"""
        # 转换为灰度图
        if len(original_img.shape) > 2:
            original_img = cv2.cvtColor(original_img, cv2.COLOR_BGR2GRAY)
        
        # 将水印文本转换为二进制
        watermark = self._text_to_bits(watermark_text)
        
        # 嵌入水印
        watermarked_img = embed_watermark(original_img, watermark, self.alpha)
        return watermarked_img
    
    def extract(self, watermarked_img, original_img, watermark_length=None):
        """提取水印文本"""
        # 转换为灰度图
        if len(watermarked_img.shape) > 2:
            watermarked_img = cv2.cvtColor(watermarked_img, cv2.COLOR_BGR2GRAY)
        if len(original_img.shape) > 2:
            original_img = cv2.cvtColor(original_img, cv2.COLOR_BGR2GRAY)
        
        # 如果未提供水印长度，则尝试提取最大可能长度
        if watermark_length is None:
            watermark_length = (watermarked_img.shape[0] // 8) * (watermarked_img.shape[1] // 8)
        
        # 提取水印二进制串
        extracted_bits = extract_watermark(watermarked_img, original_img, watermark_length, self.alpha)
        
        # 将二进制转换为文本
        return self._bits_to_text(extracted_bits)
    
    def test_robustness(self, original_img, watermarked_img, watermark_text):
        """测试水印鲁棒性"""
        watermark = self._text_to_bits(watermark_text)
        results = robustness_test(original_img, watermarked_img, watermark, test_cases)
        
        # 打印测试结果
        print("\n鲁棒性测试结果:")
        print("="*40)
        for test_name, result in results.items():
            print(f"{test_name}:")
            print(f"  提取水印: {self._bits_to_text(result['extracted_watermark'])}")
            print(f"  误码率(BER): {result['ber']:.2f}")
            print(f"  检测结果: {'成功' if result['is_detected'] else '失败'}")
            print("-"*30)
        
        return results

# 使用示例
if __name__ == "__main__":
    # 1. 加载原始图像
    original_img = cv2.imread('lena.jpg', cv2.IMREAD_GRAYSCALE)
    
    # 2. 创建水印器
    watermarker = DCTWatermark(alpha=0.15)
    
    # 3. 嵌入水印
    watermark_text = "Copyright2023"
    watermarked_img = watermarker.embed(original_img, watermark_text)
    
    # 4. 保存含水印图像
    cv2.imwrite('watermarked_lena.jpg', watermarked_img)
    
    # 5. 提取水印(未受攻击)
    extracted_text = watermarker.extract(watermarked_img, original_img, len(watermark_text)*8)
    print(f"提取的水印文本: {extracted_text}")
    
    # 6. 鲁棒性测试
    results = watermarker.test_robustness(original_img, watermarked_img, watermark_text)
    
    # 7. 可视化结果
    plt.figure(figsize=(15, 10))
    
    plt.subplot(3, 3, 1)
    plt.imshow(original_img, cmap='gray')
    plt.title('Original Image')
    
    plt.subplot(3, 3, 2)
    plt.imshow(watermarked_img, cmap='gray')
    plt.title('Watermarked Image')
    
    for i, (test_name, result) in enumerate(results.items()):
        plt.subplot(3, 3, i+3)
        plt.imshow(result['attacked_img'], cmap='gray')
        plt.title(f"{test_name}\nBER: {result['ber']:.2f}")
    
    plt.tight_layout()
    plt.show()