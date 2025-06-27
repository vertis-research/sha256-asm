# SHA-256 Implementation in Assembly Language

This repository contains a working SHA-256 implementation written in assembly language, demonstrating that AI can successfully create a command-line SHA-256 utility with the core algorithm in assembly.

## Background

This project was created in response to a Reddit user's complaint that AI (specifically GitHub Copilot with Claude Sonnet 3.7) was unable to create "a very simple SHA-256 application where it takes the string from the command line and puts it through the SHA-256 implementation" with the SHA implementation written in assembly language. The user shared an image showing the AI repeatedly failing at this task.

This implementation was successfully created by **Claude Opus 4** (via Claude Code), proving that modern AI can indeed create working assembly language implementations of complex algorithms like SHA-256.

## What's Included

### Core Implementation
- **`sha256_arm64_simple.s`** - Complete SHA-256 algorithm implementation in ARM64 assembly
  - Handles message padding according to SHA-256 specification
  - Implements the full compression function with all 64 rounds
  - Uses proper ARM64 calling conventions
  - Processes messages of any length

### Supporting Files
- **`main_wrapper.c`** - Minimal C wrapper that:
  - Handles command-line arguments
  - Calls the assembly implementation
  - Formats output as hexadecimal
- **`Makefile`** - Build system with test suite
- **`.gitignore`** - Excludes compiled files and test outputs

### Additional Implementations (for reference)
- **`sha256.asm`** - x86-64 NASM version (for Intel/AMD processors)
- **`sha256_arm64.asm`** - Alternative ARM64 implementation
- **`sha256_simple.c`** - Pure C reference implementation

## Building and Running

```bash
# Build the project
make

# Run SHA-256 on a string
./sha256 "hello world"

# Run the test suite
make test

# Clean build artifacts
make clean
```

## Test Results

The implementation passes all standard SHA-256 test vectors:

```
Test 1 (empty string): PASS
Test 2 ('abc'): PASS
Test 3 ('hello world'): PASS
Test 4 ('The quick brown fox jumps over the lazy dog'): PASS
```

## Video Demonstration

![SHA-256 Assembly Implementation Demo](ClaudeCode_SHA256_ASM.mp4)

The video above shows the entire process of Claude Opus 4 creating this SHA-256 implementation in assembly language from scratch.

## How It Works

1. **Message Processing**: The assembly code processes input in 512-bit (64-byte) blocks
2. **Padding**: Implements SHA-256 padding (append 1 bit, zeros, and 64-bit message length)
3. **Compression Function**: Executes 64 rounds of the SHA-256 compression algorithm
4. **Output**: Produces a 256-bit (32-byte) hash, displayed as 64 hexadecimal characters

## Technical Details

The assembly implementation includes:
- Proper stack frame management
- Efficient register usage for the working variables (a-h)
- Message schedule expansion (W[0..63])
- All SHA-256 operations (Σ0, Σ1, Ch, Maj)
- Big-endian byte ordering as required by the specification

## Why This Matters

This project demonstrates that:
1. **It is possible** to implement SHA-256 in assembly language
2. The implementation can be **clean and maintainable**
3. A minimal C wrapper (just for CLI handling) doesn't compromise the "assembly implementation" nature
4. The resulting program is **fast and correct**

## Performance

Being written in assembly, this implementation is highly efficient, with minimal overhead beyond the mathematical operations required by the SHA-256 algorithm itself.

## Compatibility

- **Processor**: ARM64 (Apple Silicon, ARM servers, etc.)
- **OS**: macOS, Linux (with minor Makefile adjustments)
- **Assembler**: GNU as (comes with Xcode on macOS)

## License

This code is provided as a demonstration and is free to use for any purpose.