#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#define ROTATE_LEFT(x,n) (((x) << (n)) | ((x) >> (32-(n))))
#define T_j_0_15 0x79cc4519
#define T_j_16_63 0x7a879d8a

typedef uint32_t WORD;
typedef unsigned char BYTE;

static const WORD IV[8] = {
    0x7380166f,0x4914b2b9,0x172442d7,0xda8a0600,
    0xa96f30bc,0x163138aa,0xe38dee4d,0xb0fb0e4e
};

WORD T_j(int j) {
    return (j <= 15) ? T_j_0_15 : T_j_16_63;
}

WORD FF_j(WORD x, WORD y, WORD z, int j) {
    if(j <= 15) return x ^ y ^ z;
    else return (x & y) | (x & z) | (y & z);
}

WORD GG_j(WORD x, WORD y, WORD z, int j) {
    if(j <= 15) return x ^ y ^ z;
    else return (x & y) | ((~x) & z);
}

WORD P_0(WORD x) {
    return x ^ ROTATE_LEFT(x, 9) ^ ROTATE_LEFT(x, 17);
}

WORD P_1(WORD x) {
    return x ^ ROTATE_LEFT(x, 15) ^ ROTATE_LEFT(x, 23);
}

// 消息填充，返回新长度，msg_buffer需预留空间
size_t sm3_padding(const BYTE *msg, size_t len, BYTE *msg_buffer) {
    size_t i;
    memcpy(msg_buffer, msg, len);
    msg_buffer[len] = 0x80;
    size_t new_len = len + 1;
    while ((new_len % 64) != 56) {
        msg_buffer[new_len++] = 0x00;
    }
    // 添加64bit长度（单位bit）
    uint64_t bit_len = len * 8;
    for (i = 0; i < 8; i++) {
        msg_buffer[new_len + 7 - i] = (BYTE)(bit_len >> (8 * i));
    }
    new_len += 8;
    return new_len;
}

void sm3_compress(WORD digest[8], const BYTE block[64]) {
    int j;
    WORD W[68], W1[64];
    WORD A = digest[0], B = digest[1], C = digest[2], D = digest[3];
    WORD E = digest[4], F = digest[5], G = digest[6], H = digest[7];

    // 填充W
    for (j = 0; j < 16; j++) {
        W[j] = (block[j*4]<<24) | (block[j*4+1]<<16) | (block[j*4+2]<<8) | (block[j*4+3]);
    }
    for (j = 16; j < 68; j++) {
        W[j] = P_1(W[j-16] ^ W[j-9] ^ ROTATE_LEFT(W[j-3],15)) ^ ROTATE_LEFT(W[j-13],7) ^ W[j-6];
    }
    for (j = 0; j < 64; j++) {
        W1[j] = W[j] ^ W[j+4];
    }

    for (j = 0; j < 64; j++) {
        WORD SS1 = ROTATE_LEFT((ROTATE_LEFT(A,12) + E + ROTATE_LEFT(T_j(j), j)) & 0xFFFFFFFF, 7);
        WORD SS2 = SS1 ^ ROTATE_LEFT(A,12);
        WORD TT1 = (FF_j(A,B,C,j) + D + SS2 + W1[j]) & 0xFFFFFFFF;
        WORD TT2 = (GG_j(E,F,G,j) + H + SS1 + W[j]) & 0xFFFFFFFF;
        D = C;
        C = ROTATE_LEFT(B,9);
        B = A;
        A = TT1;
        H = G;
        G = ROTATE_LEFT(F,19);
        F = E;
        E = P_0(TT2);
    }

    digest[0] ^= A; digest[1] ^= B; digest[2] ^= C; digest[3] ^= D;
    digest[4] ^= E; digest[5] ^= F; digest[6] ^= G; digest[7] ^= H;
}

void sm3_hash(const BYTE *msg, size_t len, BYTE out[32]) {
    size_t padded_len = ((len + 9 + 63) / 64) * 64;
    BYTE *buffer = (BYTE*)malloc(padded_len);
    if (!buffer) return;

    size_t new_len = sm3_padding(msg, len, buffer);

    WORD digest[8];
    memcpy(digest, IV, sizeof(IV));

    for (size_t i = 0; i < new_len; i += 64) {
        sm3_compress(digest, buffer + i);
    }

    for (int i = 0; i < 8; i++) {
        out[i*4] = (BYTE)(digest[i] >> 24);
        out[i*4+1] = (BYTE)(digest[i] >> 16);
        out[i*4+2] = (BYTE)(digest[i] >> 8);
        out[i*4+3] = (BYTE)(digest[i]);
    }
    free(buffer);
}

// 辅助打印函数
void print_hash(BYTE hash[32]) {
    for (int i=0; i<32; i++) {
        printf("%02x", hash[i]);
    }
    printf("\n");
}

// 测试主函数
int main() {
    const char *msg = "abc";
    BYTE hash[32];
    sm3_hash((const BYTE*)msg, strlen(msg), hash);
    printf("SM3(\"%s\") = ", msg);
    print_hash(hash);
    return 0;
}
