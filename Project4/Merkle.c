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
// --- c) Merkle树实现 ---
// 简化版本，二叉树叶子节点哈希构造

typedef struct {
    uint8_t hash[SM3_DIGEST_SIZE];
} MerkleNode;

typedef struct {
    MerkleNode *nodes;  // 节点数组
    size_t leaf_count;  // 叶子节点数
    size_t node_count;  // 节点总数
} MerkleTree;

// 计算两哈希拼接哈希
void hash_concat(const uint8_t *a, const uint8_t *b, uint8_t out[SM3_DIGEST_SIZE]) {
    uint8_t buf[SM3_DIGEST_SIZE*2];
    memcpy(buf, a, SM3_DIGEST_SIZE);
    memcpy(buf+SM3_DIGEST_SIZE, b, SM3_DIGEST_SIZE);
    sm3_hash(buf, SM3_DIGEST_SIZE*2, out);
}

// 计算Merkle树大小，向上取整2的次幂
size_t next_power_of_two(size_t n) {
    size_t p = 1;
    while(p < n) p <<= 1;
    return p;
}

// 创建Merkle树，叶子哈希由输入数据生成
MerkleTree* merkle_create(const uint8_t **leaf_datas, size_t leaf_count) {
    size_t tree_size = next_power_of_two(leaf_count);
    size_t total_nodes = tree_size * 2 - 1;
    MerkleTree *tree = (MerkleTree*)malloc(sizeof(MerkleTree));
    tree->leaf_count = leaf_count;
    tree->node_count = total_nodes;
    tree->nodes = (MerkleNode*)malloc(sizeof(MerkleNode)*total_nodes);

    // 先计算叶子节点哈希，放在后面 leaf_count 个位置
    for(size_t i=0;i<tree_size;i++) {
        if(i < leaf_count) {
            sm3_hash(leaf_datas[i], strlen((const char*)leaf_datas[i]), tree->nodes[total_nodes - tree_size + i].hash);
        } else {
            // 补全空节点，全部置为0哈希
            memset(tree->nodes[total_nodes - tree_size + i].hash, 0, SM3_DIGEST_SIZE);
        }
    }

    // 向上计算内部节点哈希
    for(ssize_t i = total_nodes - tree_size - 1; i >= 0; i--) {
        hash_concat(tree->nodes[i*2 + 1].hash, tree->nodes[i*2 + 2].hash, tree->nodes[i].hash);
    }

    return tree;
}

// 获取Merkle树根哈希
void merkle_root(MerkleTree *tree, uint8_t root[SM3_DIGEST_SIZE]) {
    memcpy(root, tree->nodes[0].hash, SM3_DIGEST_SIZE);
}

// 生成存在性证明路径（从叶子到根的兄弟节点哈希）
size_t merkle_proof(MerkleTree *tree, size_t leaf_index, uint8_t proof[][SM3_DIGEST_SIZE], size_t max_proof_len) {
    size_t tree_size = next_power_of_two(tree->leaf_count);
    size_t total_nodes = tree_size * 2 - 1;
    size_t idx = total_nodes - tree_size + leaf_index;
    size_t proof_len = 0;

    while(idx > 0 && proof_len < max_proof_len) {
        size_t sibling = (idx % 2) ? (idx + 1) : (idx - 1);
        memcpy(proof[proof_len++], tree->nodes[sibling].hash, SM3_DIGEST_SIZE);
        idx = (idx - 1) / 2;
    }
    return proof_len;
}

// 验证存在性证明
int merkle_verify(const uint8_t *leaf_hash, size_t leaf_index, 
                  const uint8_t proof[][SM3_DIGEST_SIZE], size_t proof_len,
                  const uint8_t root[SM3_DIGEST_SIZE]) {
    size_t tree_size = 1 << proof_len; // 证明深度对应的树大小
    uint8_t computed_hash[SM3_DIGEST_SIZE];
    memcpy(computed_hash, leaf_hash, SM3_DIGEST_SIZE);

    size_t idx = leaf_index;
    for(size_t i=0;i<proof_len;i++) {
        uint8_t buf[SM3_DIGEST_SIZE*2];
        if(idx % 2 == 0) {
            memcpy(buf, computed_hash, SM3_DIGEST_SIZE);
            memcpy(buf + SM3_DIGEST_SIZE, proof[i], SM3_DIGEST_SIZE);
        } else {
            memcpy(buf, proof[i], SM3_DIGEST_SIZE);
            memcpy(buf + SM3_DIGEST_SIZE, computed_hash, SM3_DIGEST_SIZE);
        }
        sm3_hash(buf, SM3_DIGEST_SIZE*2, computed_hash);
        idx /= 2;
    }

    return (memcmp(computed_hash, root, SM3_DIGEST_SIZE) == 0);
}

void print_hex(const uint8_t *buf, size_t len) {
    for(size_t i=0;i<len;i++) printf("%02x", buf[i]);
}

// 测试Merkle树构建和证明
void merkle_test() {
    printf("\n--- Merkle Tree Test ---\n");

    // 10万个叶子节点数据，为了测试这里用简单字符串表示
    size_t leaf_count = 100000;
    const uint8_t **leaves = malloc(sizeof(uint8_t*) * leaf_count);
    char **data_buf = malloc(sizeof(char*) * leaf_count);
    for(size_t i=0;i<leaf_count;i++) {
        data_buf[i] = malloc(32);
        snprintf(data_buf[i], 32, "leaf #%zu data", i);
        leaves[i] = (const uint8_t*)data_buf[i];
    }

    MerkleTree *tree = merkle_create(leaves, leaf_count);

    uint8_t root[SM3_DIGEST_SIZE];
    merkle_root(tree, root);

    printf("Merkle root: ");
    print_hex(root, SM3_DIGEST_SIZE);
    printf("\n");

    // 测试存在性证明
    size_t leaf_to_prove = 12345;  // 测试第12345个叶子
    uint8_t leaf_hash[SM3_DIGEST_SIZE];
    sm3_hash(leaves[leaf_to_prove], strlen((const char*)leaves[leaf_to_prove]), leaf_hash);

    uint8_t proof[64][SM3_DIGEST_SIZE];
    size_t proof_len = merkle_proof(tree, leaf_to_prove, proof, 64);

    printf("Proof length: %zu\n", proof_len);
    printf("Verifying proof for leaf %zu... ", leaf_to_prove);

    int verified = merkle_verify(leaf_hash, leaf_to_prove, proof, proof_len, root);
    if(verified) {
        printf("Success!\n");
    } else {
        printf("Failed!\n");
    }

    // 释放内存
    for(size_t i=0;i<leaf_count;i++) free(data_buf[i]);
    free(data_buf);
    free(leaves);
    free(tree->nodes);
    free(tree);
}

// 比较两个哈希值的大小（用于排序）
int hash_compare(const uint8_t *a, const uint8_t *b) {
    return memcmp(a, b, SM3_DIGEST_SIZE);
}

// 对叶子节点进行排序（按哈希值）
void sort_leaves(MerkleNode *leaves, size_t leaf_count) {
    qsort(leaves, leaf_count, sizeof(MerkleNode), 
        (int (*)(const void *, const void *))hash_compare);
}

// 创建排序的Merkle树
MerkleTree* merkle_create_sorted(const uint8_t **leaf_datas, size_t leaf_count) {
    size_t tree_size = next_power_of_two(leaf_count);
    size_t total_nodes = tree_size * 2 - 1;
    MerkleTree *tree = (MerkleTree*)malloc(sizeof(MerkleTree));
    tree->leaf_count = leaf_count;
    tree->node_count = total_nodes;
    tree->nodes = (MerkleNode*)malloc(sizeof(MerkleNode)*total_nodes);

    // 先计算叶子节点哈希
    for(size_t i=0;i<leaf_count;i++) {
        sm3_hash(leaf_datas[i], strlen((const char*)leaf_datas[i]), 
                tree->nodes[total_nodes - tree_size + i].hash);
    }
    
    // 对叶子节点进行排序
    sort_leaves(tree->nodes + (total_nodes - tree_size), leaf_count);
    
    // 补全空节点（全部置为0哈希）
    for(size_t i=leaf_count;i<tree_size;i++) {
        memset(tree->nodes[total_nodes - tree_size + i].hash, 0, SM3_DIGEST_SIZE);
    }

    // 向上计算内部节点哈希
    for(ssize_t i = total_nodes - tree_size - 1; i >= 0; i--) {
        hash_concat(tree->nodes[i*2 + 1].hash, tree->nodes[i*2 + 2].hash, tree->nodes[i].hash);
    }

    return tree;
}

// 查找叶子节点的位置（二分查找）
ssize_t find_leaf_index(MerkleTree *tree, const uint8_t *target_hash) {
    size_t tree_size = next_power_of_two(tree->leaf_count);
    size_t start = tree->node_count - tree_size;
    
    // 二分查找
    ssize_t low = 0, high = tree->leaf_count - 1;
    while(low <= high) {
        ssize_t mid = low + (high - low)/2;
        int cmp = hash_compare(target_hash, tree->nodes[start + mid].hash);
        
        if(cmp == 0) return mid; // 找到
        else if(cmp < 0) high = mid - 1;
        else low = mid + 1;
    }
    
    return -1; // 未找到
}

// 生成不存在性证明
// 返回前驱和后继的证明路径长度，proofs数组需要足够大
void merkle_non_inclusion_proof(MerkleTree *tree, const uint8_t *target_hash,
                              uint8_t proofs[2][64][SM3_DIGEST_SIZE],
                              size_t proof_lens[2],
                              size_t *predecessor_idx,
                              size_t *successor_idx) {
    size_t tree_size = next_power_of_two(tree->leaf_count);
    size_t start = tree->node_count - tree_size;
    
    // 初始化
    *predecessor_idx = -1;
    *successor_idx = -1;
    proof_lens[0] = 0;
    proof_lens[1] = 0;
    
    // 查找前驱和后继
    ssize_t low = 0, high = tree->leaf_count - 1;
    while(low <= high) {
        ssize_t mid = low + (high - low)/2;
        int cmp = hash_compare(target_hash, tree->nodes[start + mid].hash);
        
        if(cmp == 0) {
            // 不应该发生，因为是不存在性证明
            return;
        } else if(cmp < 0) {
            *successor_idx = mid;
            high = mid - 1;
        } else {
            *predecessor_idx = mid;
            low = mid + 1;
        }
    }
    
    // 生成前驱和后继的证明路径
    if(*predecessor_idx != -1) {
        proof_lens[0] = merkle_proof(tree, *predecessor_idx, proofs[0], 64);
    }
    if(*successor_idx != -1) {
        proof_lens[1] = merkle_proof(tree, *successor_idx, proofs[1], 64);
    }
}

// 验证不存在性证明
int merkle_verify_non_inclusion(const uint8_t *target_hash,
                               const uint8_t *predecessor_hash, size_t predecessor_idx,
                               const uint8_t predecessor_proof[][SM3_DIGEST_SIZE], size_t predecessor_proof_len,
                               const uint8_t *successor_hash, size_t successor_idx,
                               const uint8_t successor_proof[][SM3_DIGEST_SIZE], size_t successor_proof_len,
                               const uint8_t root[SM3_DIGEST_SIZE]) {
    // 1. 验证前驱和后继的存在性
    int pred_valid = 1, succ_valid = 1;
    
    if(predecessor_hash) {
        pred_valid = merkle_verify(predecessor_hash, predecessor_idx, 
                                 predecessor_proof, predecessor_proof_len, root);
    }
    
    if(successor_hash) {
        succ_valid = merkle_verify(successor_hash, successor_idx, 
                                 successor_proof, successor_proof_len, root);
    }
    
    if(!pred_valid || !succ_valid) {
        return 0; // 前驱或后继验证失败
    }
    
    // 2. 验证前驱 < 目标 < 后继
    int order_valid = 1;
    if(predecessor_hash && successor_hash) {
        order_valid = (hash_compare(predecessor_hash, target_hash) < 0) && 
                      (hash_compare(target_hash, successor_hash) < 0);
    } else if(predecessor_hash) {
        order_valid = (hash_compare(predecessor_hash, target_hash) < 0);
    } else if(successor_hash) {
        order_valid = (hash_compare(target_hash, successor_hash) < 0);
    }
    
    return order_valid;
}

// 测试不存在性证明
void merkle_non_inclusion_test() {
    printf("\n--- Merkle Tree Non-Inclusion Proof Test ---\n");

    // 创建测试数据
    size_t leaf_count = 100000;
    const uint8_t **leaves = malloc(sizeof(uint8_t*) * leaf_count);
    char **data_buf = malloc(sizeof(char*) * leaf_count);
    for(size_t i=0;i<leaf_count;i++) {
        data_buf[i] = malloc(32);
        snprintf(data_buf[i], 32, "leaf #%zu data", i);
        leaves[i] = (const uint8_t*)data_buf[i];
    }

    // 创建排序的Merkle树
    MerkleTree *tree = merkle_create_sorted(leaves, leaf_count);
    uint8_t root[SM3_DIGEST_SIZE];
    merkle_root(tree, root);

    // 选择一个不存在于树中的目标哈希
    uint8_t target_hash[SM3_DIGEST_SIZE];
    const char *non_existent_data = "this data is not in the tree";
    sm3_hash((const uint8_t*)non_existent_data, strlen(non_existent_data), target_hash);
    
    // 确保这个哈希确实不存在于树中
    while(find_leaf_index(tree, target_hash) != -1) {
        // 如果意外存在，修改数据重新哈希
        non_existent_data = "modified non-existent data";
        sm3_hash((const uint8_t*)non_existent_data, strlen(non_existent_data), target_hash);
    }

    printf("Target hash (not in tree): ");
    print_hex(target_hash, SM3_DIGEST_SIZE);
    printf("\n");

    // 生成不存在性证明
    uint8_t proofs[2][64][SM3_DIGEST_SIZE];
    size_t proof_lens[2];
    size_t pred_idx, succ_idx;
    
    merkle_non_inclusion_proof(tree, target_hash, proofs, proof_lens, &pred_idx, &succ_idx);
    
    printf("Predecessor index: %zu, proof length: %zu\n", pred_idx, proof_lens[0]);
    printf("Successor index: %zu, proof length: %zu\n", succ_idx, proof_lens[1]);

    // 获取前驱和后继的哈希
    uint8_t *pred_hash = NULL, *succ_hash = NULL;
    size_t tree_size = next_power_of_two(tree->leaf_count);
    
    if(pred_idx != -1) {
        pred_hash = tree->nodes[tree->node_count - tree_size + pred_idx].hash;
        printf("Predecessor hash: ");
        print_hex(pred_hash, SM3_DIGEST_SIZE);
        printf("\n");
    }
    
    if(succ_idx != -1) {
        succ_hash = tree->nodes[tree->node_count - tree_size + succ_idx].hash;
        printf("Successor hash: ");
        print_hex(succ_hash, SM3_DIGEST_SIZE);
        printf("\n");
    }

    // 验证不存在性证明
    printf("Verifying non-inclusion proof... ");
    int verified = merkle_verify_non_inclusion(
        target_hash,
        pred_hash, pred_idx, proofs[0], proof_lens[0],
        succ_hash, succ_idx, proofs[1], proof_lens[1],
        root
    );
    
    if(verified) {
        printf("Success!\n");
    } else {
        printf("Failed!\n");
    }

    // 释放内存
    for(size_t i=0;i<leaf_count;i++) free(data_buf[i]);
    free(data_buf);
    free(leaves);
    free(tree->nodes);
    free(tree);
}

int main() {
    merkle_test();
    merkle_non_inclusion_test();
    return 0;
}