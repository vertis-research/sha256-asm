#include <stdio.h>
#include <string.h>
#include <stdint.h>

// SHA-256 implementation in assembly
extern void sha256_asm(const char *input, size_t length, uint8_t output[32]);

// Convert binary hash to hex string
void hash_to_hex(const uint8_t hash[32], char output[65]) {
    const char *hex = "0123456789abcdef";
    for (int i = 0; i < 32; i++) {
        output[i * 2] = hex[hash[i] >> 4];
        output[i * 2 + 1] = hex[hash[i] & 0xf];
    }
    output[64] = '\0';
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <string>\n", argv[0]);
        return 1;
    }
    
    const char *input = argv[1];
    size_t length = strlen(input);
    uint8_t hash[32];
    char hex_output[65];
    
    // Call assembly SHA-256 implementation
    sha256_asm(input, length, hash);
    
    // Convert to hex and print
    hash_to_hex(hash, hex_output);
    printf("%s\n", hex_output);
    
    return 0;
}