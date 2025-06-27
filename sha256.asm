; SHA-256 implementation in x86-64 assembly (NASM syntax)
; For macOS/Linux x86-64

section .data
    ; SHA-256 constants (first 32 bits of fractional parts of cube roots of first 64 primes)
    K: dd 0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5
       dd 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5
       dd 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3
       dd 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174
       dd 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc
       dd 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da
       dd 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7
       dd 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967
       dd 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13
       dd 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85
       dd 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3
       dd 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070
       dd 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5
       dd 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3
       dd 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208
       dd 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2

    ; Initial hash values (first 32 bits of fractional parts of square roots of first 8 primes)
    H0: dd 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a
        dd 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19

    hex_table: db "0123456789abcdef"
    newline: db 10

section .bss
    W: resd 64          ; Message schedule array
    hash: resd 8        ; Working hash values
    msg_buffer: resb 64 ; Message block buffer
    output: resb 65     ; Output buffer for hex string (64 chars + null)

section .text
global _main

_main:
    ; Check if we have command line argument
    mov rax, [rsp]      ; argc
    cmp rax, 2
    jl .usage

    ; Get the input string
    mov rsi, [rsp + 16] ; argv[1]
    
    ; Calculate string length
    xor rcx, rcx
.strlen_loop:
    cmp byte [rsi + rcx], 0
    je .strlen_done
    inc rcx
    jmp .strlen_loop

.strlen_done:
    ; rcx now contains the length
    mov rdx, rcx        ; Save original length
    mov r15, rcx        ; Save total length for final
    
    ; Initialize hash values
    call init_hash
    
    ; Process the message
    call sha256_update
    ; rsi and rdx are now updated to point to remaining bytes
    
    ; Finalize the hash
    push r15            ; Pass total length
    call sha256_final
    pop r15
    
    ; Convert hash to hex string
    call hash_to_hex
    
    ; Print the result
    mov rax, 1          ; sys_write
    mov rdi, 1          ; stdout
    lea rsi, [rel output]
    mov rdx, 64         ; 64 hex characters
    syscall
    
    ; Print newline
    mov rax, 1
    mov rdi, 1
    lea rsi, [rel newline]
    mov rdx, 1
    syscall
    
    ; Exit
    mov rax, 60         ; sys_exit
    xor rdi, rdi        ; exit code 0
    syscall

.usage:
    ; Exit with error
    mov rax, 60
    mov rdi, 1
    syscall

; Initialize hash values
init_hash:
    lea rsi, [rel H0]
    lea rdi, [rel hash]
    mov rcx, 8
    rep movsd
    ret

; Process message blocks
; rsi = message pointer, rdx = length
sha256_update:
    push rbx
    push r12
    push r13
    push r14
    push r15
    
    mov r12, rsi        ; Message pointer
    mov r13, rdx        ; Length
    xor r14, r14        ; Offset

.process_blocks:
    ; Check if we have a full block
    mov rax, r13
    sub rax, r14
    cmp rax, 64
    jl .done
    
    ; Copy block to buffer
    lea rsi, [r12 + r14]
    lea rdi, [rel msg_buffer]
    mov rcx, 64
    rep movsb
    
    ; Process this block
    call sha256_transform
    
    ; Move to next block
    add r14, 64
    jmp .process_blocks

.done:
    ; Save remaining bytes info
    mov rsi, r12
    add rsi, r14        ; Point to remaining bytes
    mov rdx, r13
    sub rdx, r14        ; Remaining length
    
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; Finalize the hash with padding
; rsi = pointer to remaining bytes, rdx = remaining length, [rsp+48] = total length
sha256_final:
    push rbx
    push r12
    push r13
    push r14
    push r15
    
    mov r14, rsi        ; Save pointer to remaining bytes
    mov r12, rdx        ; Save remaining length
    mov r13, rdx        ; Also save for padding calculation
    mov r15, [rsp + 48] ; Get total length from stack
    
    ; Clear the buffer
    lea rdi, [rel msg_buffer]
    xor rax, rax
    mov rcx, 64
    rep stosb
    
    ; Copy remaining bytes if any
    test r12, r12
    jz .padding
    
    mov rsi, r14
    lea rdi, [rel msg_buffer]
    mov rcx, r12
    rep movsb

.padding:
    ; Add padding byte
    lea rdi, [rel msg_buffer]
    mov byte [rdi + r13], 0x80
    
    ; Check if we need an extra block
    cmp r13, 56
    jl .add_length
    
    ; Process current block and prepare new one
    call sha256_transform
    
    ; Clear buffer for next block
    lea rdi, [rel msg_buffer]
    xor rax, rax
    mov rcx, 64
    rep stosb

.add_length:
    ; Add message length in bits (big-endian)
    mov rax, r15        ; Use total length
    shl rax, 3          ; Convert to bits
    bswap rax
    lea rdi, [rel msg_buffer]
    mov [rdi + 56], rax
    
    ; Process final block
    call sha256_transform
    
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; SHA-256 compression function
sha256_transform:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    
    ; Prepare message schedule
    ; Copy first 16 words from message buffer
    lea rsi, [rel msg_buffer]
    lea rdi, [rel W]
    mov rcx, 16
.copy_loop:
    lodsd
    bswap eax
    stosd
    loop .copy_loop
    
    ; Extend message schedule for words 16-63
    mov rcx, 48
    lea rdi, [rel W]
    add rdi, 64     ; Start at W[16]
.extend_loop:
    ; s0 = (w[i-15] rightrotate 7) xor (w[i-15] rightrotate 18) xor (w[i-15] rightshift 3)
    mov eax, [rdi - 60] ; W[i-15]
    mov ebx, eax
    ror eax, 7
    ror ebx, 18
    xor eax, ebx
    mov ebx, [rdi - 60]
    shr ebx, 3
    xor eax, ebx
    mov r8d, eax        ; s0
    
    ; s1 = (w[i-2] rightrotate 17) xor (w[i-2] rightrotate 19) xor (w[i-2] rightshift 10)
    mov eax, [rdi - 8]  ; W[i-2]
    mov ebx, eax
    ror eax, 17
    ror ebx, 19
    xor eax, ebx
    mov ebx, [rdi - 8]
    shr ebx, 10
    xor eax, ebx        ; s1
    
    ; w[i] = w[i-16] + s0 + w[i-7] + s1
    add eax, r8d
    add eax, [rdi - 64] ; W[i-16]
    add eax, [rdi - 28] ; W[i-7]
    stosd
    
    loop .extend_loop
    
    ; Initialize working variables
    lea rsi, [rel hash]
    mov eax, [rsi]
    mov ebx, [rsi + 4]
    mov ecx, [rsi + 8]
    mov edx, [rsi + 12]
    mov r8d, [rsi + 16]
    mov r9d, [rsi + 20]
    mov r10d, [rsi + 24]
    mov r11d, [rsi + 28]
    
    ; Main compression loop
    xor r15, r15        ; i = 0
.compress_loop:
    ; S1 = (e rightrotate 6) xor (e rightrotate 11) xor (e rightrotate 25)
    mov r12d, r8d
    ror r12d, 6
    mov r13d, r8d
    ror r13d, 11
    xor r12d, r13d
    mov r13d, r8d
    ror r13d, 25
    xor r12d, r13d      ; S1
    
    ; ch = (e and f) xor ((not e) and g)
    mov r13d, r8d
    and r13d, r9d
    mov r14d, r8d
    not r14d
    and r14d, r10d
    xor r13d, r14d      ; ch
    
    ; temp1 = h + S1 + ch + k[i] + w[i]
    mov r14d, r11d      ; h
    add r14d, r12d      ; + S1
    add r14d, r13d      ; + ch
    lea rsi, [rel K]
    add r14d, [rsi + r15*4] ; + K[i]
    lea rsi, [rel W]
    add r14d, [rsi + r15*4] ; + W[i]
    
    ; S0 = (a rightrotate 2) xor (a rightrotate 13) xor (a rightrotate 22)
    mov r12d, eax
    ror r12d, 2
    mov r13d, eax
    ror r13d, 13
    xor r12d, r13d
    mov r13d, eax
    ror r13d, 22
    xor r12d, r13d      ; S0
    
    ; maj = (a and b) xor (a and c) xor (b and c)
    mov r13d, eax
    and r13d, ebx
    mov rbp, rax
    and ebp, ecx
    xor r13d, ebp
    mov rbp, rbx
    and ebp, ecx
    xor r13d, ebp       ; maj
    
    ; temp2 = S0 + maj
    add r12d, r13d
    
    ; Update working variables
    mov r11d, r10d      ; h = g
    mov r10d, r9d       ; g = f
    mov r9d, r8d        ; f = e
    mov r8d, edx        ; e = d
    add r8d, r14d       ; e = d + temp1
    mov edx, ecx        ; d = c
    mov ecx, ebx        ; c = b
    mov ebx, eax        ; b = a
    mov eax, r14d       ; a = temp1
    add eax, r12d       ; a = temp1 + temp2
    
    inc r15
    cmp r15, 64
    jl near .compress_loop
    
    ; Add compressed chunk to current hash value
    lea rsi, [rel hash]
    add [rsi], eax
    add [rsi + 4], ebx
    add [rsi + 8], ecx
    add [rsi + 12], edx
    add [rsi + 16], r8d
    add [rsi + 20], r9d
    add [rsi + 24], r10d
    add [rsi + 28], r11d
    
    pop rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; Convert hash to hex string
hash_to_hex:
    lea rsi, [rel hash]
    lea rdi, [rel output]
    mov rcx, 8
.convert_loop:
    lodsd
    bswap eax           ; Convert to big-endian
    
    ; Convert each byte to hex
    push rbx
    lea rbx, [rel hex_table]
    
    mov r8d, eax
    shr r8d, 28
    movzx r8d, byte [rbx + r8]
    mov [rdi], r8b
    inc rdi
    
    mov r8d, eax
    shr r8d, 24
    and r8d, 0xf
    movzx r8d, byte [rbx + r8]
    mov [rdi], r8b
    inc rdi
    
    mov r8d, eax
    shr r8d, 20
    and r8d, 0xf
    movzx r8d, byte [rbx + r8]
    mov [rdi], r8b
    inc rdi
    
    mov r8d, eax
    shr r8d, 16
    and r8d, 0xf
    movzx r8d, byte [rbx + r8]
    mov [rdi], r8b
    inc rdi
    
    mov r8d, eax
    shr r8d, 12
    and r8d, 0xf
    movzx r8d, byte [rbx + r8]
    mov [rdi], r8b
    inc rdi
    
    mov r8d, eax
    shr r8d, 8
    and r8d, 0xf
    movzx r8d, byte [rbx + r8]
    mov [rdi], r8b
    inc rdi
    
    mov r8d, eax
    shr r8d, 4
    and r8d, 0xf
    movzx r8d, byte [rbx + r8]
    mov [rdi], r8b
    inc rdi
    
    mov r8d, eax
    and r8d, 0xf
    movzx r8d, byte [rbx + r8]
    mov [rdi], r8b
    inc rdi
    
    pop rbx
    
    dec rcx
    jnz .convert_loop
    
    mov byte [rdi], 0   ; Null terminate
    ret