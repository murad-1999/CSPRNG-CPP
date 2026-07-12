#ifndef CSPRNG_CHACHA20_CSPRNG_HPP
#define CSPRNG_CHACHA20_CSPRNG_HPP

#include <array>
#include <vector>
#include <mutex>
#include <cstdint>
#include <ostream>
#include <istream>
#include <limits>
#include <type_traits>

namespace csprng {

class ChaCha20CSPRNG {
public:
    // Standard library requirements for UniformRandomBitGenerator
    using result_type = uint32_t;

    static constexpr result_type min() { return 0; }
    static constexpr result_type max() { return std::numeric_limits<result_type>::max(); }

    static constexpr result_type default_seed = 5489U;

    // Constructors
    // 1. Default constructor: auto-seeds from secure OS-native entropy source
    ChaCha20CSPRNG();

    // 2. Deterministic constructor with a single result_type seed
    explicit ChaCha20CSPRNG(result_type value);

    // 3. Deterministic constructor with a seed sequence (templated)
    template <typename SeedSeq,
              typename = std::enable_if_t<
                  !std::is_same_v<std::decay_t<SeedSeq>, ChaCha20CSPRNG> &&
                  !std::is_convertible_v<SeedSeq, result_type>
              >>
    explicit ChaCha20CSPRNG(SeedSeq& seq) {
        seed(seq);
    }

    // Custom Copy/Move Constructors (required due to std::mutex)
    ChaCha20CSPRNG(const ChaCha20CSPRNG& other);
    ChaCha20CSPRNG(ChaCha20CSPRNG&& other) noexcept;

    // Custom Copy/Move Assignment Operators (required due to std::mutex)
    ChaCha20CSPRNG& operator=(const ChaCha20CSPRNG& other);
    ChaCha20CSPRNG& operator=(ChaCha20CSPRNG&& other) noexcept;

    // Destructor
    ~ChaCha20CSPRNG();

    // Seeding methods
    // 1. Reseed from secure OS-native entropy source
    void reseed();

    // 2. Reseed with a single result_type seed
    void seed(result_type value = default_seed);

    // 3. Reseed with a seed sequence
    template <typename SeedSeq>
    void seed(SeedSeq& seq) {
        std::array<uint32_t, 10> seed_data{};
        seq.generate(seed_data.begin(), seed_data.end());

        std::lock_guard<std::mutex> lock(mutex_);
        init_state_constants();

        // Copy 256-bit key from seed sequence
        for (int i = 0; i < 8; ++i) {
            state_[i + 4] = seed_data[i];
        }

        // Reset 64-bit counter to 0
        state_[12] = 0;
        state_[13] = 0;

        // Copy 64-bit nonce from seed sequence
        state_[14] = seed_data[8];
        state_[15] = seed_data[9];

        // Reset stream position
        word_counter_ = 0;
        cached_block_index_ = std::numeric_limits<uint64_t>::max();
    }

    // Output Generation
    // 1. Generate next 32-bit pseudo-random value
    result_type operator()();

    // 2. Fill a memory buffer with arbitrary bytes
    void fill_bytes(uint8_t* dest, size_t size);

    // Navigation (O(1) seek/discard)
    void discard(unsigned long long z);

    // Equality operators
    friend bool operator==(const ChaCha20CSPRNG& lhs, const ChaCha20CSPRNG& rhs);
    friend bool operator!=(const ChaCha20CSPRNG& lhs, const ChaCha20CSPRNG& rhs);

    // Stream serialization operators
    friend std::ostream& operator<<(std::ostream& os, const ChaCha20CSPRNG& rng);
    friend std::istream& operator>>(std::istream& is, ChaCha20CSPRNG& rng);

private:
    std::array<uint32_t, 16> state_{};         // ChaCha20 state matrix (16 words)
    std::array<uint32_t, 16> buffer_{};        // Buffered keystream block (16 words = 64 bytes)
    uint64_t word_counter_ = 0;                // Keystream offset in 32-bit words
    uint64_t cached_block_index_ = std::numeric_limits<uint64_t>::max(); // Cached block index
    mutable std::mutex mutex_;                 // Mutex for thread-safety

    // Private helper methods
    void init_state_constants();
    void generate_block_for_index(uint64_t block_idx); // Assumes mutex_ is already locked
};

} // namespace csprng

#endif // CSPRNG_CHACHA20_CSPRNG_HPP
