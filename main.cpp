#include <iostream>
#include <array>
#include <iomanip>
#include <cstdint>

// Left rotation helper for ChaCha20 Quarter Round
inline uint32_t rotl(uint32_t x, int shift) {
    return (x << shift) | (x >> (32 - shift));
}

// ChaCha20 Quarter Round
inline void qr(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d) {
    a += b; d ^= a; d = rotl(d, 16);
    c += d; b ^= c; b = rotl(b, 12);
    a += b; d ^= a; d = rotl(d, 8);
    c += d; b ^= c; b = rotl(b, 7);
}

// Helper to print a 4x4 matrix with labels
void print_matrix(const std::array<uint32_t, 16>& mat, const std::string& title) {
    std::cout << "\n" << std::string(80, '=') << "\n";
    std::cout << " " << title << "\n";
    std::cout << std::string(80, '=') << "\n";

    for (int row = 0; row < 4; ++row) {
        for (int col = 0; col < 4; ++col) {
            int idx = row * 4 + col;
            std::string type;
            if (idx < 4) type = "Const";
            else if (idx < 12) type = "Key  ";
            else if (idx < 14) type = "Ctr  ";
            else type = "Nonce";

            std::cout << "[" << std::setw(2) << idx << "] " 
                      << type << ": " 
                      << std::hex << std::setw(8) << std::setfill('0') << mat[idx] 
                      << "   ";
        }
        std::cout << "\n";
    }
    std::cout << std::string(80, '-') << std::dec << "\n";
}

int main() {
    std::cout << "ChaCha20 CSPRNG Block Generation & Mixing Visualisation\n";

    // Setup input state matrix
    std::array<uint32_t, 16> initial_state{};

    // 1. Set constant words: "expand 32-byte k"
    initial_state[0] = 0x61707865; // "expa"
    initial_state[1] = 0x3320646e; // "nd 3"
    initial_state[2] = 0x79622d32; // "2-by"
    initial_state[3] = 0x6b206574; // "te k"

    // 2. Set key words (simulating a 256-bit key from seed = 12345)
    // We populate this with a deterministic key sequence
    initial_state[4] = 0x11223344;
    initial_state[5] = 0x55667788;
    initial_state[6] = 0x99aabbcc;
    initial_state[7] = 0xddeeff00;
    initial_state[8] = 0x00ffeedd;
    initial_state[9] = 0xccbbaa99;
    initial_state[10] = 0x88776655;
    initial_state[11] = 0x44332211;

    // 3. Set counter words (simulating block counter = 1)
    initial_state[12] = 0x00000001;
    initial_state[13] = 0x00000000;

    // 4. Set nonce words
    initial_state[14] = 0xdeadbeef;
    initial_state[15] = 0xcafebabe;

    // Print initial input state
    print_matrix(initial_state, "INPUT STATE MATRIX (Seed + Configuration)");

    // Run 20 rounds on a copy of the state
    std::array<uint32_t, 16> mixed_state = initial_state;
    for (int i = 0; i < 10; ++i) {
        // Column rounds
        qr(mixed_state[0], mixed_state[4], mixed_state[8], mixed_state[12]);
        qr(mixed_state[1], mixed_state[5], mixed_state[9], mixed_state[13]);
        qr(mixed_state[2], mixed_state[6], mixed_state[10], mixed_state[14]);
        qr(mixed_state[3], mixed_state[7], mixed_state[11], mixed_state[15]);
        
        // Diagonal rounds
        qr(mixed_state[0], mixed_state[5], mixed_state[10], mixed_state[15]);
        qr(mixed_state[1], mixed_state[6], mixed_state[11], mixed_state[12]);
        qr(mixed_state[2], mixed_state[7], mixed_state[8], mixed_state[13]);
        qr(mixed_state[3], mixed_state[4], mixed_state[9], mixed_state[14]);
    }

    // Print state after 20 rounds of mixing
    print_matrix(mixed_state, "STATE MATRIX AFTER 20 ROUNDS (Post-mixing, Pre-addition)");

    // Mix (add) initial state back into post-round state
    std::array<uint32_t, 16> final_keystream{};
    for (int i = 0; i < 16; ++i) {
        final_keystream[i] = mixed_state[i] + initial_state[i];
    }

    // Print final mixed keystream block
    print_matrix(final_keystream, "FINAL KEYSTREAM BLOCK (Post-addition: Mixed + Input)");

    // Print Keystream Block as Hexadecimal Bytes
    std::cout << "Generated 64 Keystream Bytes (Hexadecimal representation):\n";
    const uint8_t* bytes = reinterpret_cast<const uint8_t*>(final_keystream.data());
    for (int i = 0; i < 64; ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(bytes[i]) << " ";
        if ((i + 1) % 16 == 0) {
            std::cout << "\n";
        }
    }
    std::cout << "\n";

    return 0;
}
