#include <stdio.h>
#include <stdint.h>
#include <immintrin.h>
#include <wmmintrin.h>
#include <string.h>
#include <time.h>
// SM4测试向量
typedef struct {
    uint32_t key[4];
    uint32_t plaintext[4];
    uint32_t ciphertext[4];
} sm4_test_vector;

// 标准测试向量
const sm4_test_vector test_vec = {
    .key = {0x01234567, 0x89ABCDEF, 0xFEDCBA98, 0x76543210},
    .plaintext = {0x01234567, 0x89ABCDEF, 0xFEDCBA98, 0x76543210},
    .ciphertext = {0x681EDF34, 0xD206965E, 0x86B3E94F, 0x536E4246}
};

// SM4 SBox查表（必须放在函数外部）
static const uint8_t sm4_sbox[256] = {
    0xD6, 0x90, 0xE9, 0xFE, 0xCC, 0xE1, 0x3D, 0xB7, 0x16, 0xB6, 0x14, 0xC2, 0x28, 0xFB, 0x2C, 0x05,
    0x2B, 0x67, 0x9A, 0x76, 0x2A, 0xBE, 0x04, 0xC3, 0xAA, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
    0x9C, 0x42, 0x50, 0xF4, 0x91, 0xEF, 0x98, 0x7A, 0x33, 0x54, 0x0B, 0x43, 0xED, 0xCF, 0xAC, 0x62,
    0xE4, 0xB3, 0x1C, 0xA9, 0xC9, 0x08, 0xE8, 0x95, 0x80, 0xDF, 0x94, 0xFA, 0x75, 0x8F, 0x3F, 0xA6,
    0x47, 0x07, 0xA7, 0xFC, 0xF3, 0x73, 0x17, 0xBA, 0x83, 0x59, 0x3C, 0x19, 0xE6, 0x85, 0x4F, 0xA8,
    0x68, 0x6B, 0x81, 0xB2, 0x71, 0x64, 0xDA, 0x8B, 0xF8, 0xEB, 0x0F, 0x4B, 0x70, 0x56, 0x9D, 0x35,
    0x1E, 0x24, 0x0E, 0x5E, 0x63, 0x58, 0xD1, 0xA2, 0x25, 0x22, 0x7C, 0x3B, 0x01, 0x21, 0x78, 0x87,
    0xD4, 0x00, 0x46, 0x57, 0x9F, 0xD3, 0x27, 0x52, 0x4C, 0x36, 0x02, 0xE7, 0xA0, 0xC4, 0xC8, 0x9E,
    0xEA, 0xBF, 0x8A, 0xD2, 0x40, 0xC7, 0x38, 0xB5, 0xA3, 0xF7, 0xF2, 0xCE, 0xF9, 0x61, 0x15, 0xA1,
    0xE0, 0xAE, 0x5D, 0xA4, 0x9B, 0x34, 0x1A, 0x55, 0xAD, 0x93, 0x32, 0x30, 0xF5, 0x8C, 0xB1, 0xE3,
    0x1D, 0xF6, 0xE2, 0x2E, 0x82, 0x66, 0xCA, 0x60, 0xC0, 0x29, 0x23, 0xAB, 0x0D, 0x53, 0x4E, 0x6F,
    0xD5, 0xDB, 0x37, 0x45, 0xDE, 0xFD, 0x8E, 0x2F, 0x03, 0xFF, 0x6A, 0x72, 0x6D, 0x6C, 0x5B, 0x51,
    0x8D, 0x1B, 0xAF, 0x92, 0xBB, 0xDD, 0xBC, 0x7F, 0x11, 0xD9, 0x5C, 0x41, 0x1F, 0x10, 0x5A, 0xD8,
    0x0A, 0xC1, 0x31, 0x88, 0xA5, 0xCD, 0x7B, 0xBD, 0x2D, 0x74, 0xD0, 0x12, 0xB8, 0xE5, 0xB4, 0xB0,
    0x89, 0x69, 0x97, 0x4A, 0x0C, 0x96, 0x77, 0x7E, 0x65, 0xB9, 0xF1, 0x09, 0xC5, 0x6E, 0xC6, 0x84,
    0x18, 0xF0, 0x7D, 0xEC, 0x3A, 0xDC, 0x4D, 0x20, 0x79, 0xEE, 0x5F, 0x3E, 0xD7, 0xCB, 0x39, 0x48
};

// 全局常量定义（使用函数初始化）
static __m128i M, M_inv, SM4_AFFINE;

void init_constants() {
    // 修正后的同构映射矩阵
    M = _mm_setr_epi8(
        0x65, 0x4C, 0x6A, 0x42, 0x4B, 0x63, 0x43, 0x6B,
        0x55, 0x75, 0x5A, 0x7A, 0x53, 0x73, 0x5B, 0x7B
    );
    M_inv = _mm_setr_epi8(
        0xA4, 0x0D, 0xE0, 0x45, 0x8B, 0x2E, 0x4F, 0xD1,
        0xFE, 0x5D, 0x97, 0x3C, 0xFB, 0x58, 0x94, 0x37
    );
    // SM4仿射变换常数（修正版）
    SM4_AFFINE = _mm_setr_epi8(
        0x8E, 0x9F, 0xAB, 0xBC, 0xCD, 0xDE, 0xEA, 0xFB,
        0x43, 0x51, 0x65, 0x76, 0x87, 0x98, 0xA4, 0xB5
    );
}

void print_hex(const char* label, const uint32_t* data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%08X ", data[i]);
    }
    printf("\n");
}

// SM4密钥扩展
void sm4_key_expansion(const uint32_t* key, uint32_t* rk) {
    const uint32_t FK[4] = {0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC};
    const uint32_t CK[32] = {
        0x00070E15, 0x1C232A31, 0x383F464D, 0x545B6269,
        0x70777E85, 0x8C939AA1, 0xA8AFB6BD, 0xC4CBD2D9,
        0xE0E7EEF5, 0xFC030A11, 0x181F262D, 0x343B4249,
        0x50575E65, 0x6C737A81, 0x888F969D, 0xA4ABB2B9,
        0xC0C7CED5, 0xDCE3EAF1, 0xF8FF060D, 0x141B2229,
        0x30373E45, 0x4C535A61, 0x686F767D, 0x848B9299,
        0xA0A7AEB5, 0xBCC3CAD1, 0xD8DFE6ED, 0xF4FB0209,
        0x10171E25, 0x2C333A41, 0x484F565D, 0x646B7279
    };
    
    uint32_t K[36];
    for (int i = 0; i < 4; i++) {
        K[i] = key[i] ^ FK[i];
    }
    
    for (int i = 0; i < 32; i++) {
        uint32_t tmp = K[i+1] ^ K[i+2] ^ K[i+3] ^ CK[i];
        
        // 应用SBox
        uint8_t *p = (uint8_t*)&tmp;
        uint8_t b0 = p[3], b1 = p[2], b2 = p[1], b3 = p[0];
        p[3] = sm4_sbox[b0];
        p[2] = sm4_sbox[b1];
        p[1] = sm4_sbox[b2];
        p[0] = sm4_sbox[b3];
        
        // L'变换
        tmp = tmp ^ ((tmp << 13) | (tmp >> (32-13)));
        tmp = tmp ^ ((tmp << 23) | (tmp >> (32-23)));
        
        K[i+4] = K[i] ^ tmp;
        rk[i] = K[i+4];
    }
}

// SM4 SBox（AES-NI加速版）
__m128i sm4_sbox_aesni(__m128i x) {
    // 1. 映射到AES域
    __m128i x_aes = _mm_shuffle_epi8(M, x);
    
    // 2. 使用AESENCLAST计算x⁻¹
    __m128i inv_aes = _mm_aesenclast_si128(x_aes, _mm_setzero_si128());
    
    // 3. 映射回SM4域
    __m128i result = _mm_shuffle_epi8(M_inv, inv_aes);
    
    // 4. 应用SM4的仿射变换调整
    __m128i linear_part = _mm_and_si128(x, _mm_set1_epi32(0xFEFEFEFE));
    return _mm_xor_si128(result, _mm_xor_si128(SM4_AFFINE, linear_part));
}

// SM4轮函数
void sm4_round_aesni(__m128i* state, uint32_t rk) {
    __m128i tmp = _mm_xor_si128(state[1], state[2]);
    tmp = _mm_xor_si128(tmp, state[3]);
    tmp = _mm_xor_si128(tmp, _mm_set1_epi32(rk));
    
    // 使用AES-NI加速SBox
    __m128i sboxed = sm4_sbox_aesni(tmp);
    
    // 线性变换
    __m128i rot2 = _mm_or_si128(_mm_slli_epi32(sboxed, 2), _mm_srli_epi32(sboxed, 30));
    __m128i rot10 = _mm_or_si128(_mm_slli_epi32(sboxed, 10), _mm_srli_epi32(sboxed, 22));
    __m128i rot18 = _mm_or_si128(_mm_slli_epi32(sboxed, 18), _mm_srli_epi32(sboxed, 14));
    __m128i rot24 = _mm_or_si128(_mm_slli_epi32(sboxed, 24), _mm_srli_epi32(sboxed, 8));
    
    __m128i L = _mm_xor_si128(sboxed, rot2);
    L = _mm_xor_si128(L, rot10);
    L = _mm_xor_si128(L, rot18);
    L = _mm_xor_si128(L, rot24);
    
    state[0] = _mm_xor_si128(state[0], L);
    
    // 轮换状态字
    __m128i tmp_state = state[0];
    state[0] = state[1];
    state[1] = state[2];
    state[2] = state[3];
    state[3] = tmp_state;
}

// SM4加密
void sm4_encrypt_aesni(uint32_t* output, const uint32_t* input, const uint32_t* rk) {
    __m128i state[4];
    for (int i = 0; i < 4; i++) {
        state[i] = _mm_set1_epi32(input[i]);
    }
    
    for (int round = 0; round < 32; round++) {
        sm4_round_aesni(state, rk[round]);
    }
    
    // 最终反序
    uint32_t tmp = _mm_cvtsi128_si32(state[0]);
    state[0] = state[3];
    state[3] = _mm_set1_epi32(tmp);
    tmp = _mm_cvtsi128_si32(state[1]);
    state[1] = state[2];
    state[2] = _mm_set1_epi32(tmp);
    
    for (int i = 0; i < 4; i++) {
        output[i] = _mm_cvtsi128_si32(state[i]);
    }
}

int main() {
    init_constants(); // 初始化全局常量
    
    printf("=== SM4 AES-NI加速测试 ===\n");
    
    uint32_t rk[32];
    uint32_t output[4];
    
    // 密钥扩展
    sm4_key_expansion(test_vec.key, rk);
    
    // 加密
    clock_t start=clock();
    sm4_encrypt_aesni(output, test_vec.plaintext, rk);
    clock_t end=clock();
    // 打印结果
    print_hex("密钥      ", test_vec.key, 4);
    print_hex("明文      ", test_vec.plaintext, 4);
    print_hex("预期密文  ", test_vec.ciphertext, 4);
    print_hex("实际密文  ", output, 4);

    double ttable_time = (double)(end - start) / CLOCKS_PER_SEC;
    printf("AES-NI version time: %.6f seconds\n", ttable_time);

    // 验证
   
    if (memcmp(output, test_vec.ciphertext, 16) == 0) {
        printf("测试通过\n");
        return 0;
    } else {
        printf("测试失败\n");
        return 1;
    }
    
    

    
}
