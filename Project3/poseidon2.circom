pragma circom 2.2.2;

// 修正版本的 Poseidon2 实现
// 基于论文参数 (n,t,d) = (256,3,5)
template Poseidon2() {
    // t = 3 状态大小，d=5 非线性指数  
    signal input in[3];    // 私有输入，3个field元素
    signal output out;     // 公开输出哈希值
    
    // 基于论文Table 1的参数设置
    var rounds_full = 8;    // 完整轮数
    var rounds_partial = 57; // 部分轮数，基于论文安全参数
    var t = 3;
    var d = 5;
    
    // 注意：这里使用简化的轮常数，生产环境需要使用论文附录的官方参数
    var round_constants[65][3] = [
        [1, 2, 3], [4, 5, 6], [7, 8, 9], [10, 11, 12],
        [13, 14, 15], [16, 17, 18], [19, 20, 21], [22, 23, 24],
        [25, 26, 27], [28, 29, 30], [31, 32, 33], [34, 35, 36],
        [37, 38, 39], [40, 41, 42], [43, 44, 45], [46, 47, 48],
        [49, 50, 51], [52, 53, 54], [55, 56, 57], [58, 59, 60],
        [61, 62, 63], [64, 65, 66], [67, 68, 69], [70, 71, 72],
        [73, 74, 75], [76, 77, 78], [79, 80, 81], [82, 83, 84],
        [85, 86, 87], [88, 89, 90], [91, 92, 93], [94, 95, 96],
        [97, 98, 99], [100, 101, 102], [103, 104, 105], [106, 107, 108],
        [109, 110, 111], [112, 113, 114], [115, 116, 117], [118, 119, 120],
        [121, 122, 123], [124, 125, 126], [127, 128, 129], [130, 131, 132],
        [133, 134, 135], [136, 137, 138], [139, 140, 141], [142, 143, 144],
        [145, 146, 147], [148, 149, 150], [151, 152, 153], [154, 155, 156],
        [157, 158, 159], [160, 161, 162], [163, 164, 165], [166, 167, 168],
        [169, 170, 171], [172, 173, 174], [175, 176, 177], [178, 179, 180],
        [181, 182, 183], [184, 185, 186], [187, 188, 189], [190, 191, 192],
        [193, 194, 195]
    ];
    
    // MDS矩阵 (Maximum Distance Separable)
    // 这里使用简化版本，生产环境需要使用论文中的官方MDS矩阵
    var MDS[3][3] = [
        [2, 3, 1],
        [1, 2, 3], 
        [3, 1, 2]
    ];
    
    // S-box计算组件：计算 x^5
    component sbox[rounds_full * t + rounds_partial];
    var sbox_index = 0;
    
    // 状态变量和中间信号
    signal state[66][3]; // 每轮后的状态 (65轮 + 初始状态)
    signal after_constants[65][3]; // 加轮常数后的状态
    signal after_sbox[65][3]; // S-box后的状态
    
    // 初始化状态
    for (var i = 0; i < 3; i++) {
        state[0][i] <== in[i];
    }
    
    // 主循环：完整轮 + 部分轮
    for (var r = 0; r < rounds_full + rounds_partial; r++) {
        // 步骤1：加轮常数
        for (var i = 0; i < t; i++) {
            after_constants[r][i] <== state[r][i] + round_constants[r][i];
        }
        
        // 步骤2：S-box变换
        if (r < rounds_full) {
            // 完整轮：对所有元素应用S-box
            for (var i = 0; i < t; i++) {
                sbox[sbox_index] = Pow5();
                sbox[sbox_index].in <== after_constants[r][i];
                after_sbox[r][i] <== sbox[sbox_index].out;
                sbox_index++;
            }
        } else {
            // 部分轮：只对第一个元素应用S-box
            sbox[sbox_index] = Pow5();
            sbox[sbox_index].in <== after_constants[r][0];
            after_sbox[r][0] <== sbox[sbox_index].out;
            sbox_index++;
            
            // 其他元素保持不变
            for (var i = 1; i < t; i++) {
                after_sbox[r][i] <== after_constants[r][i];
            }
        }
        
        // 步骤3：MDS矩阵乘法（线性混合）
        for (var i = 0; i < t; i++) {
            var sum = 0;
            for (var j = 0; j < t; j++) {
                sum += MDS[i][j] * after_sbox[r][j];
            }
            state[r+1][i] <== sum;
        }
    }
    
    // 输出第一个状态元素作为哈希值
    out <== state[rounds_full + rounds_partial][0];
}

// S-box组件：计算 x^5
template Pow5() {
    signal input in;
    signal output out;
    
    signal x2;
    signal x4;
    
    x2 <== in * in;
    x4 <== x2 * x2;
    out <== in * x4;
}

// 主电路组件
component main = Poseidon2();
