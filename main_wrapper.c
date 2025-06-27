#include <stdio.h>
#include <string.h>
#include <stdint.h>

// External assembly function
extern void sha256_asm(const uint8_t *input, size_t length, uint8_t output[32]);

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <string>\n", argv[0]);
        return 1;
    }
    
    const char *input = argv[1];
    size_t length = strlen(input);
    uint8_t hash[32];
    
    // Call assembly implementation
    sha256_asm((const uint8_t *)input, length, hash);
    
    // Print hex output
    for (int i = 0; i < 32; i++) {
        printf("%02x", hash[i]);
    }
    printf("\n");
    
    return 0;
}