# Makefile for SHA-256 assembly implementation

# Detect operating system and architecture
UNAME_S := $(shell uname -s)
UNAME_M := $(shell uname -m)

# Compiler and assembler
CC = cc
AS = as

# Target executables
TARGET = sha256
TARGET_PURE = sha256_pure

# Source files
C_SRC = main_wrapper.c
ASM_SRC = sha256_arm64_simple.s
C_OBJ = main_wrapper.o
ASM_OBJ = sha256_arm64_simple.o

# Pure assembly version
PURE_ASM_SRC = sha256_pure_arm64.s
PURE_ASM_OBJ = sha256_pure_arm64.o

all: $(TARGET) $(TARGET_PURE)

$(TARGET): $(C_OBJ) $(ASM_OBJ)
	$(CC) -o $@ $^

$(C_OBJ): $(C_SRC)
	$(CC) -c -o $@ $<

$(ASM_OBJ): $(ASM_SRC)
	$(AS) -o $@ $<

$(TARGET_PURE): $(PURE_ASM_OBJ)
	$(CC) -o $@ $^

$(PURE_ASM_OBJ): $(PURE_ASM_SRC)
	$(AS) -o $@ $<

clean:
	rm -f $(C_OBJ) $(ASM_OBJ) $(PURE_ASM_OBJ) $(TARGET) $(TARGET_PURE)

test: $(TARGET) $(TARGET_PURE)
	@echo "Testing SHA-256 implementation (with C wrapper)..."
	@printf "Test 1 (empty string): "
	@./$(TARGET) "" | grep -q "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" && echo "PASS" || echo "FAIL"
	@printf "Test 2 ('abc'): "
	@./$(TARGET) "abc" | grep -q "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" && echo "PASS" || echo "FAIL"
	@printf "Test 3 ('hello world'): "
	@./$(TARGET) "hello world" | grep -q "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9" && echo "PASS" || echo "FAIL"
	@printf "Test 4 ('The quick brown fox jumps over the lazy dog'): "
	@./$(TARGET) "The quick brown fox jumps over the lazy dog" | grep -q "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592" && echo "PASS" || echo "FAIL"
	@echo "\nTesting pure assembly SHA-256 implementation..."
	@printf "Test 1 (empty string): "
	@./$(TARGET_PURE) "" | grep -q "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" && echo "PASS" || echo "FAIL"
	@printf "Test 2 ('abc'): "
	@./$(TARGET_PURE) "abc" | grep -q "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" && echo "PASS" || echo "FAIL"
	@printf "Test 3 ('hello world'): "
	@./$(TARGET_PURE) "hello world" | grep -q "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9" && echo "PASS" || echo "FAIL"
	@printf "Test 4 ('The quick brown fox jumps over the lazy dog'): "
	@./$(TARGET_PURE) "The quick brown fox jumps over the lazy dog" | grep -q "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592" && echo "PASS" || echo "FAIL"

.PHONY: all clean test