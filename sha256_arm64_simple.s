// SHA-256 implementation in ARM64 assembly
// Simplified version with proper calling convention

.section __DATA,__data
.align 3

// SHA-256 constants (first 32 bits of fractional parts of cube roots of first 64 primes)
K:
    .word 0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5
    .word 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5
    .word 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3
    .word 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174
    .word 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc
    .word 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da
    .word 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7
    .word 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967
    .word 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13
    .word 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85
    .word 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3
    .word 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070
    .word 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5
    .word 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3
    .word 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208
    .word 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2

// Initial hash values (first 32 bits of fractional parts of square roots of first 8 primes)
H0:
    .word 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a
    .word 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19

.section __TEXT,__text
.global _sha256_asm
.align 2

// SHA-256 assembly function
// x0 = input message pointer
// x1 = message length
// x2 = output hash pointer (32 bytes)
_sha256_asm:
    // Save callee-saved registers
    stp x29, x30, [sp, #-96]!
    stp x19, x20, [sp, #16]
    stp x21, x22, [sp, #32]
    stp x23, x24, [sp, #48]
    stp x25, x26, [sp, #64]
    stp x27, x28, [sp, #80]
    mov x29, sp
    
    // Allocate space on stack for working variables
    sub sp, sp, #416    // 64*4 (W array) + 32 (hash) + 64 (msg block) + padding
    
    // Save parameters
    mov x19, x0         // Message pointer
    mov x20, x1         // Message length
    mov x21, x2         // Output pointer
    
    // Initialize hash values from H0
    adrp x0, H0@PAGE
    add x0, x0, H0@PAGEOFF
    mov x1, sp          // Hash values at sp
    ldp w2, w3, [x0]
    stp w2, w3, [x1]
    ldp w2, w3, [x0, #8]
    stp w2, w3, [x1, #8]
    ldp w2, w3, [x0, #16]
    stp w2, w3, [x1, #16]
    ldp w2, w3, [x0, #24]
    stp w2, w3, [x1, #24]
    
    // Process complete 64-byte blocks
    mov x22, #0         // Block offset
process_blocks:
    mov x0, x20
    sub x0, x0, x22
    cmp x0, #64
    b.lt final_block
    
    // Copy block to working area (sp + 32)
    add x0, x19, x22
    add x1, sp, #32
    mov x2, #64
copy_block:
    ldrb w3, [x0], #1
    strb w3, [x1], #1
    subs x2, x2, #1
    b.ne copy_block
    
    // Process this block
    bl process_block
    
    add x22, x22, #64
    b process_blocks

final_block:
    // Handle final block with padding
    mov x0, x20
    sub x0, x0, x22     // Remaining bytes
    mov x23, x0         // Save remaining count
    
    // Clear block buffer
    add x1, sp, #32
    mov x2, #64
    mov w3, #0
clear_block:
    strb w3, [x1], #1
    subs x2, x2, #1
    b.ne clear_block
    
    // Copy remaining bytes
    cbz x23, add_padding
    add x0, x19, x22
    add x1, sp, #32
    mov x2, x23
copy_remaining:
    ldrb w3, [x0], #1
    strb w3, [x1], #1
    subs x2, x2, #1
    b.ne copy_remaining

add_padding:
    // Add padding byte
    add x1, sp, #32
    mov w2, #0x80
    strb w2, [x1, x23]
    
    // Check if we need an extra block
    cmp x23, #56
    b.lt add_length
    
    // Process current block
    bl process_block
    
    // Clear block for length
    add x1, sp, #32
    mov x2, #64
    mov w3, #0
clear_block2:
    strb w3, [x1], #1
    subs x2, x2, #1
    b.ne clear_block2

add_length:
    // Add message length in bits (big-endian)
    lsl x0, x20, #3     // Convert to bits
    add x1, sp, #32
    
    // Store as big-endian 64-bit value at offset 56
    // SHA-256 uses a 64-bit length field at the end
    rev x0, x0          // Convert to big-endian
    str x0, [x1, #56]
    
    // Process final block
    bl process_block
    
    // Copy hash to output
    mov x0, sp          // Hash values
    mov x1, x21         // Output pointer
    mov x2, #8          // 8 words
copy_output:
    ldr w3, [x0], #4
    rev w3, w3          // Convert to big-endian
    str w3, [x1], #4
    subs x2, x2, #1
    b.ne copy_output
    
    // Restore stack and return
    mov sp, x29
    ldp x27, x28, [sp, #80]
    ldp x25, x26, [sp, #64]
    ldp x23, x24, [sp, #48]
    ldp x21, x22, [sp, #32]
    ldp x19, x20, [sp, #16]
    ldp x29, x30, [sp], #96
    ret

// Process a single 512-bit block
// Uses stack layout:
// sp+0:   hash[8] (32 bytes)
// sp+32:  message block (64 bytes)
// sp+96:  W array (256 bytes)
process_block:
    stp x29, x30, [sp, #-16]!
    
    // Prepare message schedule W
    add x0, sp, #48     // Message block (adjusted for frame)
    add x1, sp, #112    // W array
    
    // Copy and byte-swap first 16 words
    mov x2, #0
copy_w:
    ldr w3, [x0, x2, lsl #2]
    rev w3, w3
    str w3, [x1, x2, lsl #2]
    add x2, x2, #1
    cmp x2, #16
    b.ne copy_w
    
    // Extend W[16..63]
    mov x2, #16
extend_w:
    // W[i] = W[i-16] + s0 + W[i-7] + s1
    // s0 = (W[i-15] ror 7) ^ (W[i-15] ror 18) ^ (W[i-15] >> 3)
    sub x3, x2, #15
    ldr w4, [x1, x3, lsl #2]
    ror w5, w4, #7
    ror w6, w4, #18
    eor w5, w5, w6
    lsr w6, w4, #3
    eor w5, w5, w6      // s0
    
    // s1 = (W[i-2] ror 17) ^ (W[i-2] ror 19) ^ (W[i-2] >> 10)
    sub x3, x2, #2
    ldr w4, [x1, x3, lsl #2]
    ror w6, w4, #17
    ror w7, w4, #19
    eor w6, w6, w7
    lsr w7, w4, #10
    eor w6, w6, w7      // s1
    
    // W[i] = W[i-16] + s0 + W[i-7] + s1
    sub x3, x2, #16
    ldr w7, [x1, x3, lsl #2]
    add w5, w5, w7
    sub x3, x2, #7
    ldr w7, [x1, x3, lsl #2]
    add w5, w5, w7
    add w5, w5, w6
    str w5, [x1, x2, lsl #2]
    
    add x2, x2, #1
    cmp x2, #64
    b.ne extend_w
    
    // Load working variables
    add x0, sp, #16     // Hash values (adjusted)
    ldp w8, w9, [x0]    // a, b
    ldp w10, w11, [x0, #8]  // c, d
    ldp w12, w13, [x0, #16] // e, f
    ldp w14, w15, [x0, #24] // g, h
    
    // Main compression loop
    adrp x3, K@PAGE
    add x3, x3, K@PAGEOFF
    mov x2, #0
compress:
    // T1 = h + S1 + ch + K[i] + W[i]
    // S1 = (e ror 6) ^ (e ror 11) ^ (e ror 25)
    ror w4, w12, #6
    ror w5, w12, #11
    eor w4, w4, w5
    ror w5, w12, #25
    eor w4, w4, w5      // S1
    
    // ch = (e & f) ^ (~e & g)
    and w5, w12, w13
    mvn w6, w12
    and w6, w6, w14
    eor w5, w5, w6      // ch
    
    add w6, w15, w4     // h + S1
    add w6, w6, w5      // + ch
    ldr w4, [x3, x2, lsl #2]    // K[i]
    add w6, w6, w4
    ldr w4, [x1, x2, lsl #2]    // W[i]
    add w6, w6, w4      // T1
    
    // T2 = S0 + maj
    // S0 = (a ror 2) ^ (a ror 13) ^ (a ror 22)
    ror w4, w8, #2
    ror w5, w8, #13
    eor w4, w4, w5
    ror w5, w8, #22
    eor w4, w4, w5      // S0
    
    // maj = (a & b) ^ (a & c) ^ (b & c)
    and w5, w8, w9
    and w7, w8, w10
    eor w5, w5, w7
    and w7, w9, w10
    eor w5, w5, w7      // maj
    
    add w4, w4, w5      // T2
    
    // Update working variables
    mov w15, w14        // h = g
    mov w14, w13        // g = f
    mov w13, w12        // f = e
    add w12, w11, w6    // e = d + T1
    mov w11, w10        // d = c
    mov w10, w9         // c = b
    mov w9, w8          // b = a
    add w8, w6, w4      // a = T1 + T2
    
    add x2, x2, #1
    cmp x2, #64
    b.ne compress
    
    // Add compressed chunk to hash
    add x0, sp, #16     // Hash values (adjusted)
    ldp w2, w3, [x0]
    add w2, w2, w8
    add w3, w3, w9
    stp w2, w3, [x0]
    ldp w2, w3, [x0, #8]
    add w2, w2, w10
    add w3, w3, w11
    stp w2, w3, [x0, #8]
    ldp w2, w3, [x0, #16]
    add w2, w2, w12
    add w3, w3, w13
    stp w2, w3, [x0, #16]
    ldp w2, w3, [x0, #24]
    add w2, w2, w14
    add w3, w3, w15
    stp w2, w3, [x0, #24]
    
    ldp x29, x30, [sp], #16
    ret