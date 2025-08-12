#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

#define SM3_DIGEST_SIZE 32
#define SM3_BLOCK_SIZE 64

// IV
static const uint32_t SM3_IV[8] = {
    0x7380166fU, 0x4914b2b9U, 0x172442d7U, 0xda8a0600U,
    0xa96f30bcU, 0x163138aaU, 0xe38dee4dU, 0xb0fb0e4eU
};

#define ROTL32(x,n) ( ( (x) << (n) ) | ( (x) >> (32 - (n)) ) )
#define SM3_T1 0x79cc4519U
#define SM3_T2 0x7a879d8aU
static inline uint32_t T_rot(int j) { return ROTL32((j < 16) ? SM3_T1 : SM3_T2, j & 31); }

#define P0(x) ((x) ^ ROTL32((x),9) ^ ROTL32((x),17))
#define P1(x) ((x) ^ ROTL32((x),15) ^ ROTL32((x),23))
#define FF(j,x,y,z) (((j) < 16) ? ((x) ^ (y) ^ (z)) : (((x) & (y)) | ((x) & (z)) | ((y) & (z))))
#define GG(j,x,y,z) (((j) < 16) ? ((x) ^ (y) ^ (z)) : (((x) & (y)) | ((~(x)) & (z))))

// endian helpers (explicit)
static inline uint32_t be32_to_cpu(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | ((uint32_t)p[3]);
}
static inline void cpu_to_be32(uint32_t v, uint8_t *p) {
    p[0] = (uint8_t)((v >> 24) & 0xFF);
    p[1] = (uint8_t)((v >> 16) & 0xFF);
    p[2] = (uint8_t)((v >> 8) & 0xFF);
    p[3] = (uint8_t)(v & 0xFF);
}

typedef struct {
    uint64_t total_len; // bytes
    uint32_t state[8];
    uint8_t buffer[SM3_BLOCK_SIZE];
    size_t buffer_len;
} SM3_CTX;

// ------------------ Corrected compress (opt1) ------------------
void sm3_compress_opt1(uint32_t state[8], const uint8_t block[SM3_BLOCK_SIZE]) {
    uint32_t W[68], Wp[64];
    int j;
    // load big-endian words
    for (j = 0; j < 16; ++j) W[j] = be32_to_cpu(block + j*4);
    // message expansion
    for (j = 16; j < 68; ++j) {
        uint32_t tmp = W[j-16] ^ W[j-9] ^ ROTL32(W[j-3], 15);
        W[j] = P1(tmp) ^ ROTL32(W[j-13], 7) ^ W[j-6];
    }
    for (j = 0; j < 64; ++j) Wp[j] = W[j] ^ W[j+4];

    uint32_t A = state[0], B = state[1], C = state[2], D = state[3];
    uint32_t E = state[4], F = state[5], G = state[6], H = state[7];

    for (j = 0; j < 64; ++j) {
        uint32_t Tj = T_rot(j);
        uint32_t SS1 = ROTL32(ROTL32(A,12) + E + Tj, 7);
        uint32_t SS2 = SS1 ^ ROTL32(A,12);
        uint32_t TT1 = (uint32_t)(FF(j, A, B, C) + D + SS2 + Wp[j]);
        uint32_t TT2 = (uint32_t)(GG(j, E, F, G) + H + SS1 + W[j]);
        D = C;
        C = ROTL32(B,9);
        B = A;
        A = TT1;
        H = G;
        G = ROTL32(F,19);
        F = E;
        E = P0(TT2);
    }

    state[0] ^= A; state[1] ^= B; state[2] ^= C; state[3] ^= D;
    state[4] ^= E; state[5] ^= F; state[6] ^= G; state[7] ^= H;
}

// ------------------ Corrected compress (opt2) ------------------
// For correctness-first, compute full W/Wp as well (safe). Later we can implement a true,
// correct on-the-fly expansion, but it's tricky and must be carefully tested.
void sm3_compress_opt2(uint32_t state[8], const uint8_t block[SM3_BLOCK_SIZE]) {
    // identical to opt1 for correctness baseline
    sm3_compress_opt1(state, block);
}

// ------------------ High level functions ------------------
void sm3_init(SM3_CTX *ctx) {
    ctx->total_len = 0;
    ctx->buffer_len = 0;
    memcpy(ctx->state, SM3_IV, sizeof(SM3_IV));
}

void sm3_update_with(SM3_CTX *ctx, const uint8_t *data, size_t len,
                     void (*compress)(uint32_t*, const uint8_t*)) {
    size_t left = ctx->buffer_len;
    if (len == 0) return;
    ctx->total_len += len;
    size_t fill = SM3_BLOCK_SIZE - left;

    if (left && len >= fill) {
        memcpy(ctx->buffer + left, data, fill);
        compress(ctx->state, ctx->buffer);
        data += fill; len -= fill; left = 0;
    }
    while (len >= SM3_BLOCK_SIZE) {
        compress(ctx->state, data);
        data += SM3_BLOCK_SIZE; len -= SM3_BLOCK_SIZE;
    }
    if (len > 0) {
        memcpy(ctx->buffer + left, data, len);
        left += len;
    }
    ctx->buffer_len = left;
}

void sm3_final_with(SM3_CTX *ctx, uint8_t out[SM3_DIGEST_SIZE],
                   void (*compress)(uint32_t*, const uint8_t*)) {
    uint64_t bits = ctx->total_len * 8ULL;
    size_t idx = ctx->buffer_len;

    uint8_t tmp[SM3_BLOCK_SIZE * 2];
    memset(tmp, 0, sizeof(tmp));
    tmp[0] = 0x80;
    size_t pad_len = (idx < 56) ? (56 - idx) : (56 + 64 - idx);

    sm3_update_with(ctx, tmp, pad_len, compress);

    // append 64-bit big-endian length
    uint8_t len64[8];
    for (int i = 0; i < 8; ++i) len64[7 - i] = (uint8_t)((bits >> (8 * i)) & 0xFF);
    sm3_update_with(ctx, len64, 8, compress);

    // output state in big-endian bytes
    for (int i = 0; i < 8; ++i) cpu_to_be32(ctx->state[i], out + i*4);
}

void sm3_hash_with(const uint8_t *data, size_t len, uint8_t out[SM3_DIGEST_SIZE],
                   void (*compress)(uint32_t*, const uint8_t*)) {
    SM3_CTX ctx;
    sm3_init(&ctx);
    sm3_update_with(&ctx, data, len, compress);
    sm3_final_with(&ctx, out, compress);
}

// ------------------ helpers, tests & benchmark ------------------
static void print_hex(const uint8_t *d, size_t n) {
    for (size_t i = 0; i < n; ++i) printf("%02x", d[i]);
    printf("\n");
}

void test_and_benchmark() {
    const char *msg = "abc";
    uint8_t out[SM3_DIGEST_SIZE];
    const uint8_t expected[SM3_DIGEST_SIZE] = {
        0x66,0xc7,0xf0,0xf4,0x62,0xee,0xed,0xd9,
        0xd1,0xf2,0xd4,0x6b,0xdc,0x10,0xe4,0xe2,
        0x41,0x67,0xc4,0x87,0x5c,0xf2,0xf7,0xa2,
        0x29,0x7d,0xa0,0x2b,0x8f,0x4b,0xa8,0xe0
    };

    printf("Test vectors:\n");

    sm3_hash_with((const uint8_t *)"", 0, out, sm3_compress_opt1);
    printf("opt1 empty: "); print_hex(out, SM3_DIGEST_SIZE);

    sm3_hash_with((const uint8_t *)"abc", 3, out, sm3_compress_opt1);
    printf("opt1  abc : "); print_hex(out, SM3_DIGEST_SIZE);

    sm3_hash_with((const uint8_t *)"abc", 3, out, sm3_compress_opt2);
    printf("opt2  abc : "); print_hex(out, SM3_DIGEST_SIZE);

    printf("expected  : "); print_hex(expected, SM3_DIGEST_SIZE);

    uint8_t out1[SM3_DIGEST_SIZE], out2[SM3_DIGEST_SIZE];
    sm3_hash_with((const uint8_t *)"abc", 3, out1, sm3_compress_opt1);
    sm3_hash_with((const uint8_t *)"abc", 3, out2, sm3_compress_opt2);
    printf("opt1 ok: %s\n", (memcmp(out1, expected, SM3_DIGEST_SIZE)==0) ? "YES" : "NO");
    printf("opt2 ok: %s\n", (memcmp(out2, expected, SM3_DIGEST_SIZE)==0) ? "YES" : "NO");

    // benchmark (1MB)
    const size_t test_size = 1024 * 1024;
    uint8_t *data = malloc(test_size);
    for (size_t i = 0; i < test_size; ++i) data[i] = (uint8_t)(i & 0xFF);

    const int rounds = 8;
    clock_t t0 = clock();
    for (int i = 0; i < rounds; ++i) sm3_hash_with(data, test_size, out, sm3_compress_opt1);
    clock_t t1 = clock();
    double sec1 = (double)(t1 - t0) / CLOCKS_PER_SEC / (double)rounds;
    printf("opt1: %.3f sec per 1MB, %.2f MB/s\n", sec1, 1.0 / sec1);

    t0 = clock();
    for (int i = 0; i < rounds; ++i) sm3_hash_with(data, test_size, out, sm3_compress_opt2);
    t1 = clock();
    double sec2 = (double)(t1 - t0) / CLOCKS_PER_SEC / (double)rounds;
    printf("opt2: %.3f sec per 1MB, %.2f MB/s\n", sec2, 1.0 / sec2);

    free(data);
}

int main(void) {
    test_and_benchmark();
    return 0;
}
