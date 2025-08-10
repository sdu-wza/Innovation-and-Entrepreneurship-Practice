import cv2
import numpy as np

# ====== 盲水印嵌入 ======
def embed_watermark_blind(image_path, watermark_text, output_path):
    img = cv2.imread(image_path, cv2.IMREAD_GRAYSCALE)
    img = np.float32(img)
    h, w = img.shape

    # 水印转成二进制
    watermark_bin = ''.join(format(ord(c), '08b') for c in watermark_text)
    wm_len = len(watermark_bin)
    block_size = 8
    wm_idx = 0

    for i in range(0, h, block_size):
        for j in range(0, w, block_size):
            if wm_idx >= wm_len:
                break
            block = img[i:i+block_size, j:j+block_size]
            if block.shape[0] < block_size or block.shape[1] < block_size:
                continue
            dct_block = cv2.dct(block)

            # 选两个中频系数
            p1 = (4, 3)
            p2 = (3, 4)

            bit = int(watermark_bin[wm_idx])
            if bit == 1:
                if dct_block[p1] < dct_block[p2]:
                    dct_block[p1], dct_block[p2] = dct_block[p2], dct_block[p1]
            else:
                if dct_block[p1] > dct_block[p2]:
                    dct_block[p1], dct_block[p2] = dct_block[p2], dct_block[p1]

            img[i:i+block_size, j:j+block_size] = cv2.idct(dct_block)
            wm_idx += 1

    watermarked_img = np.uint8(np.clip(img, 0, 255))
    cv2.imwrite(output_path, watermarked_img)
    print(f"水印已嵌入，输出文件: {output_path}")


# ====== 盲水印提取 ======
def extract_watermark_blind(image_path, watermark_length):
    img = cv2.imread(image_path, cv2.IMREAD_GRAYSCALE)
    img = np.float32(img)
    h, w = img.shape
    block_size = 8
    bits = ''
    wm_idx = 0

    for i in range(0, h, block_size):
        for j in range(0, w, block_size):
            if wm_idx >= watermark_length * 8:
                break
            block = img[i:i+block_size, j:j+block_size]
            if block.shape[0] < block_size or block.shape[1] < block_size:
                continue
            dct_block = cv2.dct(block)

            p1 = (4, 3)
            p2 = (3, 4)

            if dct_block[p1] > dct_block[p2]:
                bits += '1'
            else:
                bits += '0'
            wm_idx += 1

    watermark_text = ''.join(chr(int(bits[i:i+8], 2)) for i in range(0, len(bits), 8))
    return watermark_text


# ====== 鲁棒性测试 ======
def robustness_tests(wm_path, wm_text):
    wm_len = len(wm_text)

    # 原图提取
    original = extract_watermark_blind(wm_path, wm_len)
    print(f"original: {original} (正确率: {calc_accuracy(wm_text, original)}%)")

    # 旋转
    img = cv2.imread(wm_path)
    M = cv2.getRotationMatrix2D((img.shape[1]//2, img.shape[0]//2), 15, 1)
    rotated = cv2.warpAffine(img, M, (img.shape[1], img.shape[0]))
    cv2.imwrite("/Users/apple/sdu-practice/Project2/IMG/rotated.png", rotated)
    rot_text = extract_watermark_blind("/Users/apple/sdu-practice/Project2/IMG/rotated.png", wm_len)
    print(f"rotated: {rot_text} (正确率: {calc_accuracy(wm_text, rot_text)}%)")

    # 裁剪
    cropped = img[50:-50, 50:-50]
    cv2.imwrite("/Users/apple/sdu-practice/Project2/IMG/cropped.png", cropped)
    crop_text = extract_watermark_blind("/Users/apple/sdu-practice/Project2/IMG/cropped.png", wm_len)
    print(f"cropped: {crop_text} (正确率: {calc_accuracy(wm_text, crop_text)}%)")

    # 调对比度
    contrast = cv2.convertScaleAbs(img, alpha=1.5, beta=0)
    cv2.imwrite("/Users/apple/sdu-practice/Project2/IMG/contrast.png", contrast)
    cont_text = extract_watermark_blind("/Users/apple/sdu-practice/Project2/IMG/contrast.png", wm_len)
    print(f"contrast: {cont_text} (正确率: {calc_accuracy(wm_text, cont_text)}%)")

    # 调亮度
    brightness = cv2.convertScaleAbs(img, alpha=1, beta=50)
    cv2.imwrite("/Users/apple/sdu-practice/Project2/IMG/brightness.png", brightness)
    bright_text = extract_watermark_blind("/Users/apple/sdu-practice/Project2/IMG/brightness.png", wm_len)
    print(f"brightness: {bright_text} (正确率: {calc_accuracy(wm_text, bright_text)}%)")

    # 加噪声
    noisy = np.array(img, dtype=np.float32)
    noise = np.random.normal(0, 10, noisy.shape)
    noisy = np.uint8(np.clip(noisy + noise, 0, 255))
    cv2.imwrite("/Users/apple/sdu-practice/Project2/IMG/noisy.png", noisy)
    noisy_text = extract_watermark_blind("/Users/apple/sdu-practice/Project2/IMG/noisy.png", wm_len)
    print(f"noisy: {noisy_text} (正确率: {calc_accuracy(wm_text, noisy_text)}%)")


def calc_accuracy(expected, actual):
    correct = sum(1 for e, a in zip(expected, actual) if e == a)
    return round(correct / len(expected) * 100, 1)


# ====== 主程序 ======
if __name__ == "__main__":
    input_image = "/Users/apple/sdu-practice/Project2/IMG/1.png"   # 原始图片
    watermarked_image = "/Users/apple/sdu-practice/Project2/IMG/watermarked.png"
    watermark_text = "SECRET2025"

    embed_watermark_blind(input_image, watermark_text, watermarked_image)
    robustness_tests(watermarked_image, watermark_text)
