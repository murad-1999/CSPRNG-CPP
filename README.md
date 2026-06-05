# CSPRNG-CPP

A C++17 implementation of a thread-safe Cryptographically Secure Pseudo-Random Number Generator (CSPRNG) based on the ChaCha20 stream cipher block function. 

This project is built from scratch without external dependencies for educational purposes. It includes a structured block visualizer to illustrate Salsa20/ChaCha20 ARX (Add-Rotate-XOR) cipher states.

## Project Structure

* `include/csprng/chacha20_csprng.hpp` — Main class interface. Compatible with standard C++ `<random>` library distribution templates (e.g., `std::uniform_int_distribution`, `std::shuffle`).
* `src/chacha20_csprng.cpp` — Cipher block math, thread-safety locking, SplitMix64 seed expansion, and platform-specific secure OS entropy harvesting (`BCryptGenRandom` on Windows, `/dev/urandom` fallback on Linux).
* `tests/chacha20_csprng_test.cpp` — Validation suite testing determinism, random byte filling, state serialization, multithreaded concurrent generation, and $O(1)$ seeks.
* `main.cpp` — Interactive block-by-block visualizer.
* `CMakeLists.txt` & `Makefile` — Build files.

## Prerequisites

* A C++17 compatible compiler (e.g., `g++` 8+, `clang++` 7+, or MSVC 2017+).
* `make` (optional, for quick compilation under Linux/WSL).

## Building and Running

### Run the Test Suite
You can compile and run the full test suite using the Makefile:
```bash
make test
```

### Run the Block Visualizer
To run the block-by-block visualizer showing how the inputs, 20 rounds of mixing, and feed-forward additions operate:
```bash
# Compile the visualizer
g++ -std=c++17 -Wall -Wextra -pthread -O3 -Iinclude src/chacha20_csprng.cpp main.cpp -o csprng_visualizer

# Run the executable
./csprng_visualizer
```

## How the Visualizer Works

The visualizer shows the three main stages of the ChaCha20 block generation pipeline:

1. **Input State Matrix (4x4)**:
   * Rows 0: Const words (`"expand 32-byte k"`).
   * Rows 1-2: 256-bit key.
   * Row 3 (left): 64-bit block counter.
   * Row 3 (right): 64-bit random nonce.
2. **State Matrix After 20 Rounds**: The intermediate scrambled state after executing 10 column rounds and 10 diagonal rounds.
3. **Final Keystream Block**: The output block after adding the input matrix back to the scrambled matrix. This final addition makes the mixing function one-way and irreversible, securing the generator.