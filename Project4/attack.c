#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define SM3_DIGEST_SIZE 32
#define SM3_BLOCK_SIZE 64

// --- SM3基础数据与函数，和你的优化代码基本一致 ---

static const uint32_t SM3_IV[8] = {
    0x7380166F,0x4914B2B9,0x172442D7,0xDA8A0600,
    0xA96F30BC,0x163138AA,0xE38DEE4D,0xB0FB0E4E
};

static const uint32_t T[64] = {
    0x79CC4519,0x79CC4519,0x79CC4519,0x79CC4519,0x79CC4519,0x79CC4519,
    0x79CC4519,0x79CC4519,0x79CC4519,0x79CC4519,0x79CC4519,0x79CC4519,
    0x79CC4519,0x79CC4519,0x79CC4519,0x79CC4519,0x7A879D8A,0x7A879D8A,
    0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,
    0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,
    0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,
    0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,
    0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,
    0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,
    0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,
    0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A
};

#define ROTL32(x,n) (((x) << (n)) | ((x) >> (32 - (n))))
#define P0(x) ((x) ^ ROTL32((x),9) ^ ROTL32((x),17))
#define P1(x) ((x) ^ ROTL32((x),15) ^ ROTL32((x),23))
#define FF(x,y,z,j) ((j)<16 ? ((x)^(y)^(z)) : (((x)&(y))|((x)&(z))|((y)&(z))))
#define GG(x,y,z,j) ((j)<16 ? ((x)^(y)^(z)) : (((x)&(y))|((~(x))&(z))))

static uint32_t be32_to_cpu(const uint8_t *p) {
    return (p[0]<<24) | (p[1]<<16) | (p[2]<<8) | p[3];
}
static void cpu_to_be32(uint32_t val, uint8_t *p) {
    p[0] = val >> 24; p[1] = val >> 16; p[2] = val >> 8; p[3] = val;
}

typedef struct {
    uint64_t total_len;    // 总字节数
    uint32_t state[8];
    uint8_t buffer[SM3_BLOCK_SIZE];
    int buffer_len;
} SM3_CTX;

// 你给的优化1压缩函数（这里用你原版压缩函数即可）
void sm3_compress(uint32_t state[8], const uint8_t block[64]) {
    uint32_t W[68], W1[64];
    uint32_t A,B,C,D,E,F,G,H,SS1,SS2,TT1,TT2;
    int j;

    for (j=0;j<16;j++) W[j] = be32_to_cpu(block+j*4);
    for (j=16;j<68;j++) {
        W[j] = P1(W[j-16]^W[j-9]^ROTL32(W[j-3],15)) ^ ROTL32(W[j-13],7) ^ W[j-6];
    }
    for (j=0;j<64;j++) {
        W1[j] = W[j]^W[j+4];
    }

    A=state[0]; B=state[1]; C=state[2]; D=state[3];
    E=state[4]; F=state[5]; G=state[6]; H=state[7];

    for (j=0;j<64;j++) {
        SS1 = ROTL32(ROTL32(A,12) + E + ROTL32(T[j],j),7);
        SS2 = SS1 ^ ROTL32(A,12);
        TT1 = FF(A,B,C,j) + D + SS2 + W1[j];
        TT2 = GG(E,F,G,j) + H + SS1 + W[j];
        D = C; C = ROTL32(B,9); B = A; A = TT1;
        H = G; G = ROTL32(F,19); F = E; E = P0(TT2);
    }

    state[0] ^= A; state[1] ^= B; state[2] ^= C; state[3] ^= D;
    state[4] ^= E; state[5] ^= F; state[6] ^= G; state[7] ^= H;
}

void sm3_init(SM3_CTX *ctx) {
    ctx->total_len = 0;
    ctx->buffer_len = 0;
    memcpy(ctx->state, SM3_IV, sizeof(SM3_IV));
}

void sm3_update(SM3_CTX *ctx, const uint8_t *data, size_t len) {
    size_t fill = SM3_BLOCK_SIZE - ctx->buffer_len;
    ctx->total_len += len;

    if (ctx->buffer_len && len >= fill) {
        memcpy(ctx->buffer + ctx->buffer_len, data, fill);
        sm3_compress(ctx->state, ctx->buffer);
        data += fill; len -= fill;
        ctx->buffer_len = 0;
    }

    while (len >= SM3_BLOCK_SIZE) {
        sm3_compress(ctx->state, data);
        data += SM3_BLOCK_SIZE; len -= SM3_BLOCK_SIZE;
    }

    if (len > 0) {
        memcpy(ctx->buffer + ctx->buffer_len, data, len);
        ctx->buffer_len += len;
    }
}

void sm3_final(SM3_CTX *ctx, uint8_t digest[SM3_DIGEST_SIZE]) {
    uint64_t total_bits = ctx->total_len * 8;
    int padding_len = (ctx->buffer_len < 56) ? (56 - ctx->buffer_len) : (120 - ctx->buffer_len);
    uint8_t padding[128] = {0};
    padding[0] = 0x80;

    for (int i=0; i<8; i++) {
        padding[padding_len + i] = (total_bits >> (56 - 8*i)) & 0xFF;
    }

    sm3_update(ctx, padding, padding_len + 8);

    for (int i=0; i<8; i++) {
        cpu_to_be32(ctx->state[i], digest + i*4);
    }
}

void sm3_hash(const uint8_t *data, size_t len, uint8_t digest[SM3_DIGEST_SIZE]) {
    SM3_CTX ctx;
    sm3_init(&ctx);
    sm3_update(&ctx, data, len);
    sm3_final(&ctx, digest);
}

// ---- b) length extension attack ----

// 构造padding（对给定消息长度做SM3填充）
// 返回padding长度，padding写到buf
size_t sm3_padding(uint64_t msg_len, uint8_t *buf) {
    // msg_len是字节长度
    uint64_t bits = msg_len * 8;
    size_t pad_len = ((msg_len % 64) < 56) ? (56 - (msg_len % 64)) : (64 + 56 - (msg_len % 64));
    buf[0] = 0x80;
    memset(buf+1, 0, pad_len-1);
    for (int i=0; i<8; i++) {
        buf[pad_len + i] = (bits >> (56 - i*8)) & 0xFF;
    }
    return pad_len + 8;
}

// 直接用压缩函数执行一次分块
// 用于手动更新中间状态，执行扩展分块
void sm3_compress_with_state(uint32_t state[8], const uint8_t block[64]) {
    sm3_compress(state, block);
}

// length extension attack demo
void length_extension_attack_demo() {
    printf("\n--- Length Extension Attack Demo ---\n");

    const char *orig_msg = "comment=hello"; // 原消息
    const char *ext_msg = "&admin=true";    // 想追加的消息

    uint8_t orig_digest[SM3_DIGEST_SIZE];
    sm3_hash((const uint8_t*)orig_msg, strlen(orig_msg), orig_digest);

    printf("Original message: \"%s\"\n", orig_msg);
    printf("Original hash: ");
    for(int i=0;i<SM3_DIGEST_SIZE;i++) printf("%02x", orig_digest[i]);
    printf("\n");

    // 构造padding
    uint8_t padding[128];
    size_t pad_len = sm3_padding(strlen(orig_msg), padding);

    // 计算消息长度：原消息+padding长度
    uint64_t new_msg_len = strlen(orig_msg) + pad_len;

    // 构造扩展消息（padding后的消息 + ext_msg）
    // 这里只是示意，实际攻击者只知道orig_digest和orig_msg长度，不能得知orig_msg内容
    uint8_t forged_msg[256];
    memcpy(forged_msg, orig_msg, strlen(orig_msg));
    memcpy(forged_msg + strlen(orig_msg), padding, pad_len);
    memcpy(forged_msg + strlen(orig_msg) + pad_len, ext_msg, strlen(ext_msg));
    size_t forged_msg_len = strlen(orig_msg) + pad_len + strlen(ext_msg);

    // 模拟攻击：使用orig_digest作为中间状态，继续用扩展消息做压缩
    SM3_CTX ctx;
    // 把orig_digest转为state（大端转uint32_t）
    for(int i=0;i<8;i++) {
        ctx.state[i] = (orig_digest[4*i]<<24)|(orig_digest[4*i+1]<<16)|(orig_digest[4*i+2]<<8)|(orig_digest[4*i+3]);
    }
    ctx.total_len = new_msg_len; // 注意这一步，要用padding后的长度，保证位数统计正确
    ctx.buffer_len = 0;

    // 扩展消息长度
    sm3_update(&ctx, (const uint8_t*)ext_msg, strlen(ext_msg));

    uint8_t final_digest[SM3_DIGEST_SIZE];
    sm3_final(&ctx, final_digest);

    printf("Forged message (hex): ");
    for(size_t i=0;i<forged_msg_len;i++) printf("%02x", forged_msg[i]);
    printf("\n");

    printf("Forged hash: ");
    for(int i=0;i<SM3_DIGEST_SIZE;i++) printf("%02x", final_digest[i]);
    printf("\n");

    // 验证：直接计算完整消息
    uint8_t verify_digest[SM3_DIGEST_SIZE];
    sm3_hash(forged_msg, forged_msg_len, verify_digest);

    printf("Verify hash: ");
    for(int i=0;i<SM3_DIGEST_SIZE;i++) printf("%02x", verify_digest[i]);
    printf("\n");

    if(memcmp(final_digest, verify_digest, SM3_DIGEST_SIZE)==0) {
        printf("Length extension attack success!\n");
    } else {
        printf("Length extension attack failed!\n");
    }
}

int main() {
    length_extension_attack_demo();

    return 0;
}
