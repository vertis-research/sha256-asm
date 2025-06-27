; SHA-256 implementation in ARM64 assembly (GNU assembler syntax)
; For macOS/Linux ARM64

.section __DATA,__data
.align 4
K:      ; SHA-256 constants
    .long 0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5
    .long 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5
    .long 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3
    .long 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174
    .long 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc
    .long 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da
    .long 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7
    .long 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967
    .long 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13
    .long 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85
    .long 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3
    .long 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070
    .long 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5
    .long 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3
    .long 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208
    .long 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2

H0:     ; Initial hash values
    .long 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a
    .long 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19

hex_table:
    .ascii "0123456789abcdef"
newline:
    .byte 10

.section __BSS,__bss
.align 4
W:          .skip 256       ; Message schedule array (64 * 4)
hash:       .skip 32        ; Working hash values (8 * 4)
msg_buffer: .skip 64        ; Message block buffer
output:     .skip 65        ; Output buffer for hex string

.section __TEXT,__text
.global _main
.align 2

_main:
    ; Save frame pointer and link register
    stp x29, x30, [sp, #-16]!
    mov x29, sp
    
    ; x0 contains argc, x1 contains argv
    cmp w0, #2
    b.lt usage_error
    
    ; Get argv[1]
    ldr x0, [x1, #8]        ; argv[1]
    
    ; Calculate string length
    mov x2, x0              ; Save string pointer
    mov x3, #0              ; Length counter
strlen_loop:
    ldrb w4, [x0, x3]
    cbz w4, strlen_done
    add x3, x3, #1
    b strlen_loop
    
strlen_done:
    ; x2 = string pointer, x3 = length
    mov x19, x3             ; Save total length
    
    ; Initialize hash
    bl init_hash
    
    ; Process message
    mov x0, x2              ; String pointer
    mov x1, x3              ; Length
    bl sha256_update
    
    ; Finalize
    mov x0, x19             ; Total length
    bl sha256_final
    
    ; Convert to hex
    bl hash_to_hex
    
    ; Print result
    mov x0, #1              ; stdout
    adrp x1, output@PAGE
    add x1, x1, output@PAGEOFF
    mov x2, #64             ; 64 hex chars
    mov x16, #4             ; sys_write
    svc #0x80
    
    ; Print newline
    mov x0, #1
    adrp x1, newline@PAGE
    add x1, x1, newline@PAGEOFF
    mov x2, #1
    mov x16, #4
    svc #0x80
    
    ; Exit success
    mov x0, #0
    ldp x29, x30, [sp], #16
    ret

usage_error:
    mov x0, #1
    ldp x29, x30, [sp], #16
    ret

; Initialize hash values
init_hash:
    adrp x0, H0@PAGE
    add x0, x0, H0@PAGEOFF
    adrp x1, hash@PAGE
    add x1, x1, hash@PAGEOFF
    mov x2, #32             ; 8 words * 4 bytes
copy_init:
    ldr w3, [x0], #4
    str w3, [x1], #4
    subs x2, x2, #4
    b.ne copy_init
    ret

; SHA-256 update - process complete blocks
; x0 = message pointer, x1 = length
sha256_update:
    stp x29, x30, [sp, #-48]!
    stp x19, x20, [sp, #16]
    stp x21, x22, [sp, #32]
    
    mov x19, x0             ; Message pointer
    mov x20, x1             ; Length
    mov x21, #0             ; Offset
    
process_blocks:
    sub x22, x20, x21       ; Remaining length
    cmp x22, #64
    b.lt update_done
    
    ; Copy block to buffer
    add x0, x19, x21
    adrp x1, msg_buffer@PAGE
    add x1, x1, msg_buffer@PAGEOFF
    mov x2, #64
    bl memcpy
    
    ; Process block
    bl sha256_transform
    
    add x21, x21, #64
    b process_blocks
    
update_done:
    ; Return remaining data pointer and length
    add x0, x19, x21        ; Remaining data pointer
    sub x1, x20, x21        ; Remaining length
    
    ldp x21, x22, [sp, #32]
    ldp x19, x20, [sp, #16]
    ldp x29, x30, [sp], #48
    ret

; SHA-256 finalize with padding
; x0 = total length
sha256_final:
    stp x29, x30, [sp, #-32]!
    stp x19, x20, [sp, #16]
    
    mov x19, x0             ; Total length
    and x20, x19, #63       ; Remaining bytes
    
    ; Clear buffer
    adrp x0, msg_buffer@PAGE
    add x0, x0, msg_buffer@PAGEOFF
    mov x1, #0
    mov x2, #64
    bl memset
    
    ; Add padding byte
    adrp x0, msg_buffer@PAGE
    add x0, x0, msg_buffer@PAGEOFF
    mov w1, #0x80
    strb w1, [x0, x20]
    
    ; Check if we need extra block
    cmp x20, #56
    b.lt add_length
    
    ; Process current block
    bl sha256_transform
    
    ; Clear buffer
    adrp x0, msg_buffer@PAGE
    add x0, x0, msg_buffer@PAGEOFF
    mov x1, #0
    mov x2, #64
    bl memset
    
add_length:
    ; Add length in bits (big-endian)
    lsl x0, x19, #3         ; Convert to bits
    rev x0, x0              ; Byte swap to big-endian
    adrp x1, msg_buffer@PAGE
    add x1, x1, msg_buffer@PAGEOFF
    str x0, [x1, #56]
    
    ; Process final block
    bl sha256_transform
    
    ldp x19, x20, [sp, #16]
    ldp x29, x30, [sp], #32
    ret

; SHA-256 compression function
sha256_transform:
    stp x29, x30, [sp, #-16]!
    sub sp, sp, #256        ; Space for working variables
    
    ; Prepare message schedule
    adrp x0, msg_buffer@PAGE
    add x0, x0, msg_buffer@PAGEOFF
    adrp x1, W@PAGE
    add x1, x1, W@PAGEOFF
    
    ; Copy and byte-swap first 16 words
    mov x2, #0
copy_w:
    ldr w3, [x0, x2, lsl #2]
    rev w3, w3              ; Byte swap
    str w3, [x1, x2, lsl #2]
    add x2, x2, #1
    cmp x2, #16
    b.ne copy_w
    
    ; Extend message schedule
    mov x2, #16
extend_w:
    ; s0 = (w[i-15] ror 7) ^ (w[i-15] ror 18) ^ (w[i-15] >> 3)
    sub x3, x2, #15
    ldr w4, [x1, x3, lsl #2]
    ror w5, w4, #7
    ror w6, w4, #18
    eor w5, w5, w6
    lsr w6, w4, #3
    eor w5, w5, w6         ; s0
    
    ; s1 = (w[i-2] ror 17) ^ (w[i-2] ror 19) ^ (w[i-2] >> 10)
    sub x3, x2, #2
    ldr w4, [x1, x3, lsl #2]
    ror w6, w4, #17
    ror w7, w4, #19
    eor w6, w6, w7
    lsr w7, w4, #10
    eor w6, w6, w7         ; s1
    
    ; w[i] = w[i-16] + s0 + w[i-7] + s1
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
    
    ; Load working variables
    adrp x0, hash@PAGE
    add x0, x0, hash@PAGEOFF
    ldp w8, w9, [x0]        ; a, b
    ldp w10, w11, [x0, #8]  ; c, d
    ldp w12, w13, [x0, #16] ; e, f
    ldp w14, w15, [x0, #24] ; g, h
    
    ; Main compression loop
    mov x2, #0
compress_loop:
    ; S1 = (e ror 6) ^ (e ror 11) ^ (e ror 25)
    ror w3, w12, #6
    ror w4, w12, #11
    eor w3, w3, w4
    ror w4, w12, #25
    eor w3, w3, w4         ; S1
    
    ; ch = (e & f) ^ (~e & g)
    and w4, w12, w13
    mvn w5, w12
    and w5, w5, w14
    eor w4, w4, w5         ; ch
    
    ; temp1 = h + S1 + ch + k[i] + w[i]
    add w5, w15, w3
    add w5, w5, w4
    adrp x0, K@PAGE
    add x0, x0, K@PAGEOFF
    ldr w3, [x0, x2, lsl #2]
    add w5, w5, w3
    adrp x0, W@PAGE
    add x0, x0, W@PAGEOFF
    ldr w3, [x0, x2, lsl #2]
    add w5, w5, w3         ; temp1
    
    ; S0 = (a ror 2) ^ (a ror 13) ^ (a ror 22)
    ror w3, w8, #2
    ror w4, w8, #13
    eor w3, w3, w4
    ror w4, w8, #22
    eor w3, w3, w4         ; S0
    
    ; maj = (a & b) ^ (a & c) ^ (b & c)
    and w4, w8, w9
    and w6, w8, w10
    eor w4, w4, w6
    and w6, w9, w10
    eor w4, w4, w6         ; maj
    
    ; temp2 = S0 + maj
    add w3, w3, w4
    
    ; Update working variables
    mov w15, w14           ; h = g
    mov w14, w13           ; g = f
    mov w13, w12           ; f = e
    add w12, w11, w5       ; e = d + temp1
    mov w11, w10           ; d = c
    mov w10, w9            ; c = b
    mov w9, w8             ; b = a
    add w8, w5, w3         ; a = temp1 + temp2
    
    add x2, x2, #1
    cmp x2, #64
    b.ne compress_loop
    
    ; Add to hash values
    adrp x0, hash@PAGE
    add x0, x0, hash@PAGEOFF
    ldp w3, w4, [x0]
    add w3, w3, w8
    add w4, w4, w9
    stp w3, w4, [x0]
    ldp w3, w4, [x0, #8]
    add w3, w3, w10
    add w4, w4, w11
    stp w3, w4, [x0, #8]
    ldp w3, w4, [x0, #16]
    add w3, w3, w12
    add w4, w4, w13
    stp w3, w4, [x0, #16]
    ldp w3, w4, [x0, #24]
    add w3, w3, w14
    add w4, w4, w15
    stp w3, w4, [x0, #24]
    
    add sp, sp, #256
    ldp x29, x30, [sp], #16
    ret

; Convert hash to hex string
hash_to_hex:
    adrp x0, hash@PAGE
    add x0, x0, hash@PAGEOFF
    adrp x1, output@PAGE
    add x1, x1, output@PAGEOFF
    adrp x2, hex_table@PAGE
    add x2, x2, hex_table@PAGEOFF
    
    mov x3, #8              ; 8 words
convert_word:
    ldr w4, [x0], #4
    rev w4, w4              ; Byte swap to big-endian
    
    ; Convert each nibble
    mov x5, #8              ; 8 nibbles per word
convert_nibble:
    lsr w6, w4, #28         ; Get top nibble
    ldrb w6, [x2, x6]       ; Look up hex char
    strb w6, [x1], #1       ; Store char
    lsl w4, w4, #4          ; Shift to next nibble
    subs x5, x5, #1
    b.ne convert_nibble
    
    subs x3, x3, #1
    b.ne convert_word
    
    mov w4, #0
    strb w4, [x1]           ; Null terminate
    ret

; Helper functions
memcpy:
    cbz x2, memcpy_done
memcpy_loop:
    ldrb w3, [x0], #1
    strb w3, [x1], #1
    subs x2, x2, #1
    b.ne memcpy_loop
memcpy_done:
    ret

memset:
    cbz x2, memset_done
memset_loop:
    strb w1, [x0], #1
    subs x2, x2, #1
    b.ne memset_loop
memset_done:
    ret