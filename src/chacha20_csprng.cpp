#include "csprng/chacha20_csprng.hpp"
#include <algorithm>
#include <stdexcept>
#include <random>

#if defined(_WIN32) || defined(_WIN64)
#include <windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")
#else
#include <fstream>
#endif

namespace csprng {

namespace {

// Platform-independent secure entropy harvester
void get_os_entropy(uint8_t* buffer, size_t size) {
#if defined(_WIN32) || defined(_WIN64)
    NTSTATUS status = BCryptGenRandom(
        nullptr,
        buffer,
        static_cast<ULONG>(size),
        BCRYPT_USE_SYSTEM_PREFERRED_RNG
    );
    if (status != 0) {
        throw std::runtime_error("BCryptGenRandom failed to harvest secure entropy");
    }
#else
    std::ifstream urandom("/dev/urandom", std::ios::binary);
    if (urandom) {
        urandom.read(reinterpret_cast<char*>(buffer), size);
        if (urandom.gcount() == static_cast<std::streamsize>(size)) {
            return;
        }
    }
    throw std::runtime_error("/dev/urandom is unavailable or failed to harvest secure entropy");
#endif
}

// SplitMix64 generator to expand a 32-bit seed into key/nonce states
uint32_t next_splitmix64(uint64_t& x) {
    x += 0x9e3779b97f4a7c15ULL;
    uint64_t z = x;
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
    return static_cast<uint32_t>((z ^ (z >> 31)) & 0xFFFFFFFF);
}

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

} // namespace

// Constructors
ChaCha20CSPRNG::ChaCha20CSPRNG() {
    reseed();
}

ChaCha20CSPRNG::ChaCha20CSPRNG(result_type value) {
    seed(value);
}

// Custom Destructor
ChaCha20CSPRNG::~ChaCha20CSPRNG() {
    std::lock_guard<std::mutex> lock(mutex_);
    std::fill(state_.begin(), state_.end(), 0);
    std::fill(buffer_.begin(), buffer_.end(), 0);
}

// Custom Copy Constructor
ChaCha20CSPRNG::ChaCha20CSPRNG(const ChaCha20CSPRNG& other) {
    std::lock_guard<std::mutex> lock(other.mutex_);
    state_ = other.state_;
    buffer_ = other.buffer_;
    word_counter_ = other.word_counter_;
    cached_block_index_ = other.cached_block_index_;
}

// Custom Move Constructor
ChaCha20CSPRNG::ChaCha20CSPRNG(ChaCha20CSPRNG&& other) noexcept {
    std::lock_guard<std::mutex> lock(other.mutex_);
    state_ = other.state_;
    buffer_ = other.buffer_;
    word_counter_ = other.word_counter_;
    cached_block_index_ = other.cached_block_index_;

    // Securely clear the moved-from instance
    std::fill(other.state_.begin(), other.state_.end(), 0);
    std::fill(other.buffer_.begin(), other.buffer_.end(), 0);
    other.word_counter_ = 0;
    other.cached_block_index_ = std::numeric_limits<uint64_t>::max();
}

// Custom Copy Assignment
ChaCha20CSPRNG& ChaCha20CSPRNG::operator=(const ChaCha20CSPRNG& other) {
    if (this != &other) {
        std::unique_lock<std::mutex> lock_this(mutex_, std::defer_lock);
        std::unique_lock<std::mutex> lock_other(other.mutex_, std::defer_lock);
        std::lock(lock_this, lock_other);
        state_ = other.state_;
        buffer_ = other.buffer_;
        word_counter_ = other.word_counter_;
        cached_block_index_ = other.cached_block_index_;
    }
    return *this;
}

// Custom Move Assignment
ChaCha20CSPRNG& ChaCha20CSPRNG::operator=(ChaCha20CSPRNG&& other) noexcept {
    if (this != &other) {
        std::unique_lock<std::mutex> lock_this(mutex_, std::defer_lock);
        std::unique_lock<std::mutex> lock_other(other.mutex_, std::defer_lock);
        std::lock(lock_this, lock_other);
        state_ = other.state_;
        buffer_ = other.buffer_;
        word_counter_ = other.word_counter_;
        cached_block_index_ = other.cached_block_index_;

        // Securely clear the moved-from instance
        std::fill(other.state_.begin(), other.state_.end(), 0);
        std::fill(other.buffer_.begin(), other.buffer_.end(), 0);
        other.word_counter_ = 0;
        other.cached_block_index_ = std::numeric_limits<uint64_t>::max();
    }
    return *this;
}

// Seeding methods
void ChaCha20CSPRNG::reseed() {
    std::array<uint8_t, 40> seed_bytes{};
    get_os_entropy(seed_bytes.data(), seed_bytes.size());

    std::lock_guard<std::mutex> lock(mutex_);
    init_state_constants();

    // Fill 256-bit key (8 words) starting at index 4
    for (int i = 0; i < 8; ++i) {
        state_[i + 4] = (static_cast<uint32_t>(seed_bytes[i * 4]) << 0) |
                        (static_cast<uint32_t>(seed_bytes[i * 4 + 1]) << 8) |
                        (static_cast<uint32_t>(seed_bytes[i * 4 + 2]) << 16) |
                        (static_cast<uint32_t>(seed_bytes[i * 4 + 3]) << 24);
    }

    // Reset 64-bit block counter to 0
    state_[12] = 0;
    state_[13] = 0;

    // Fill 64-bit nonce (2 words) starting at index 14
    for (int i = 0; i < 2; ++i) {
        int offset = 32 + i * 4;
        state_[i + 14] = (static_cast<uint32_t>(seed_bytes[offset]) << 0) |
                         (static_cast<uint32_t>(seed_bytes[offset + 1]) << 8) |
                         (static_cast<uint32_t>(seed_bytes[offset + 2]) << 16) |
                         (static_cast<uint32_t>(seed_bytes[offset + 3]) << 24);
    }

    word_counter_ = 0;
    cached_block_index_ = std::numeric_limits<uint64_t>::max();
}

void ChaCha20CSPRNG::seed(result_type value) {
    uint64_t x = value;

    std::lock_guard<std::mutex> lock(mutex_);
    init_state_constants();

    // Expand seed into key
    for (int i = 4; i < 12; ++i) {
        state_[i] = next_splitmix64(x);
    }

    // Reset block counter
    state_[12] = 0;
    state_[13] = 0;

    // Set nonce
    state_[14] = next_splitmix64(x);
    state_[15] = next_splitmix64(x);

    word_counter_ = 0;
    cached_block_index_ = std::numeric_limits<uint64_t>::max();
}

// Keystream Block Generation
void ChaCha20CSPRNG::init_state_constants() {
    state_[0] = 0x61707865; // "expa"
    state_[1] = 0x3320646e; // "nd 3"
    state_[2] = 0x79622d32; // "2-by"
    state_[3] = 0x6b206574; // "te k"
}

void ChaCha20CSPRNG::generate_block_for_index(uint64_t block_idx) {
    // Write target block counter to state matrix (words 12 and 13)
    state_[12] = static_cast<uint32_t>(block_idx & 0xFFFFFFFF);
    state_[13] = static_cast<uint32_t>(block_idx >> 32);

    std::array<uint32_t, 16> x = state_;

    // 20 rounds of ChaCha
    for (int i = 0; i < 10; ++i) {
        // Column rounds
        qr(x[0], x[4], x[8], x[12]);
        qr(x[1], x[5], x[9], x[13]);
        qr(x[2], x[6], x[10], x[14]);
        qr(x[3], x[7], x[11], x[15]);
        // Diagonal rounds
        qr(x[0], x[5], x[10], x[15]);
        qr(x[1], x[6], x[11], x[12]);
        qr(x[2], x[7], x[8], x[13]);
        qr(x[3], x[4], x[9], x[14]);
    }

    // Mix state back into input state
    for (int i = 0; i < 16; ++i) {
        buffer_[i] = x[i] + state_[i];
    }

    cached_block_index_ = block_idx;
}

// Output Generation
ChaCha20CSPRNG::result_type ChaCha20CSPRNG::operator()() {
    std::lock_guard<std::mutex> lock(mutex_);
    uint64_t block_idx = word_counter_ / 16;
    size_t word_idx = word_counter_ % 16;

    if (block_idx != cached_block_index_) {
        generate_block_for_index(block_idx);
    }

    word_counter_++;
    return buffer_[word_idx];
}

void ChaCha20CSPRNG::fill_bytes(uint8_t* dest, size_t size) {
    std::lock_guard<std::mutex> lock(mutex_);
    size_t offset = 0;
    while (offset < size) {
        uint64_t block_idx = word_counter_ / 16;
        size_t word_idx = word_counter_ % 16;

        if (block_idx != cached_block_index_) {
            generate_block_for_index(block_idx);
        }

        size_t bytes_available = 64 - (word_idx * 4);
        size_t bytes_to_copy = std::min(size - offset, bytes_available);

        const uint8_t* src = reinterpret_cast<const uint8_t*>(buffer_.data()) + (word_idx * 4);
        std::copy(src, src + bytes_to_copy, dest + offset);

        offset += bytes_to_copy;
        word_counter_ += (bytes_to_copy + 3) / 4;
    }
}

// Navigation (O(1) seek/discard)
void ChaCha20CSPRNG::discard(unsigned long long z) {
    std::lock_guard<std::mutex> lock(mutex_);
    word_counter_ += z;
}

bool operator==(const ChaCha20CSPRNG& lhs, const ChaCha20CSPRNG& rhs) {
    if (&lhs == &rhs) return true;
    
    std::unique_lock<std::mutex> lock_lhs(lhs.mutex_, std::defer_lock);
    std::unique_lock<std::mutex> lock_rhs(rhs.mutex_, std::defer_lock);
    std::lock(lock_lhs, lock_rhs);

    // Compare constants (0..3), key (4..11), nonce (14..15), and current stream word_counter_
    return std::equal(lhs.state_.begin(), lhs.state_.begin() + 12, rhs.state_.begin()) &&
           lhs.state_[14] == rhs.state_[14] &&
           lhs.state_[15] == rhs.state_[15] &&
           lhs.word_counter_ == rhs.word_counter_;
}

bool operator!=(const ChaCha20CSPRNG& lhs, const ChaCha20CSPRNG& rhs) {
    return !(lhs == rhs);
}

// Serialization
std::ostream& operator<<(std::ostream& os, const ChaCha20CSPRNG& rng) {
    std::lock_guard<std::mutex> lock(rng.mutex_);
    for (int i = 0; i < 16; ++i) {
        os << rng.state_[i] << " ";
    }
    for (int i = 0; i < 16; ++i) {
        os << rng.buffer_[i] << " ";
    }
    os << rng.word_counter_ << " " << rng.cached_block_index_;
    return os;
}

std::istream& operator>>(std::istream& is, ChaCha20CSPRNG& rng) {
    std::array<uint32_t, 16> temp_state{};
    std::array<uint32_t, 16> temp_buffer{};
    uint64_t temp_word_counter = 0;
    uint64_t temp_cached_block_index = 0;

    for (int i = 0; i < 16; ++i) {
        is >> temp_state[i];
    }
    for (int i = 0; i < 16; ++i) {
        is >> temp_buffer[i];
    }
    is >> temp_word_counter >> temp_cached_block_index;

    if (is) {
        std::lock_guard<std::mutex> lock(rng.mutex_);
        rng.state_ = temp_state;
        rng.buffer_ = temp_buffer;
        rng.word_counter_ = temp_word_counter;
        rng.cached_block_index_ = temp_cached_block_index;
    }
    return is;
}

} // namespace csprng
