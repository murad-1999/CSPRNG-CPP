#include "csprng/chacha20_csprng.hpp"
#include <iostream>
#include <cassert>
#include <vector>
#include <thread>
#include <sstream>
#include <algorithm>
#include <random>
#include <future>

// Simple test framework helper
#define TEST_ASSERT(cond) \
    do { \
        if (!(cond)) { \
            std::cerr << "Assertion failed: " << #cond << " at " << __FILE__ << ":" << __LINE__ << std::endl; \
            std::exit(1); \
        } \
    } while (0)

void test_determinism() {
    std::cout << "Running test_determinism..." << std::endl;
    
    // Two generators with the same seed must produce the same sequence
    csprng::ChaCha20CSPRNG rng1(42);
    csprng::ChaCha20CSPRNG rng2(42);
    
    TEST_ASSERT(rng1 == rng2);
    
    for (int i = 0; i < 1000; ++i) {
        TEST_ASSERT(rng1() == rng2());
    }
    
    TEST_ASSERT(rng1 == rng2);
    
    // Two generators with different seeds must produce different sequences
    csprng::ChaCha20CSPRNG rng3(42);
    csprng::ChaCha20CSPRNG rng4(43);
    
    bool different = false;
    for (int i = 0; i < 100; ++i) {
        if (rng3() != rng4()) {
            different = true;
            break;
        }
    }
    TEST_ASSERT(different);
    std::cout << "test_determinism PASSED." << std::endl;
}

void test_fill_bytes() {
    std::cout << "Running test_fill_bytes..." << std::endl;
    
    csprng::ChaCha20CSPRNG rng(12345);
    
    std::vector<uint8_t> buffer1(128);
    std::vector<uint8_t> buffer2(128);
    
    rng.fill_bytes(buffer1.data(), buffer1.size());
    rng.fill_bytes(buffer2.data(), buffer2.size());
    
    // Ensure they are filled with random-looking data (not all 0s)
    size_t zero_count = 0;
    for (uint8_t b : buffer1) {
        if (b == 0) zero_count++;
    }
    TEST_ASSERT(zero_count < buffer1.size() / 2); // Extremely unlikely to have > 50% zeros
    
    // Ensure buffers are different
    TEST_ASSERT(buffer1 != buffer2);
    
    // Test fill_bytes with odd size
    std::vector<uint8_t> buffer3(7);
    rng.fill_bytes(buffer3.data(), buffer3.size());
    
    std::cout << "test_fill_bytes PASSED." << std::endl;
}

void test_discard() {
    std::cout << "Running test_discard..." << std::endl;
    
    // Discard 0 steps
    {
        csprng::ChaCha20CSPRNG rng1(777);
        csprng::ChaCha20CSPRNG rng2(777);
        rng1.discard(0);
        TEST_ASSERT(rng1 == rng2);
    }
    
    // Discard smaller than block (e.g. 5 words)
    {
        csprng::ChaCha20CSPRNG rng1(777);
        csprng::ChaCha20CSPRNG rng2(777);
        for (int i = 0; i < 5; ++i) rng1();
        rng2.discard(5);
        TEST_ASSERT(rng1 == rng2);
    }
    
    // Discard exact block size (16 words)
    {
        csprng::ChaCha20CSPRNG rng1(777);
        csprng::ChaCha20CSPRNG rng2(777);
        for (int i = 0; i < 16; ++i) rng1();
        rng2.discard(16);
        TEST_ASSERT(rng1 == rng2);
    }
    
    // Discard across multiple blocks (e.g. 100 words)
    {
        csprng::ChaCha20CSPRNG rng1(777);
        csprng::ChaCha20CSPRNG rng2(777);
        for (int i = 0; i < 100; ++i) rng1();
        rng2.discard(100);
        TEST_ASSERT(rng1 == rng2);
    }

    // Discard a very large amount (e.g. 1,000,000 words)
    {
        csprng::ChaCha20CSPRNG rng1(777);
        csprng::ChaCha20CSPRNG rng2(777);
        rng1.discard(1000000);
        rng2.discard(1000000);
        TEST_ASSERT(rng1 == rng2);
        
        // Ensure both can still produce valid, identical output
        for (int i = 0; i < 100; ++i) {
            TEST_ASSERT(rng1() == rng2());
        }
    }
    
    std::cout << "test_discard PASSED." << std::endl;
}

void test_standard_compatibility() {
    std::cout << "Running test_standard_compatibility..." << std::endl;
    
    csprng::ChaCha20CSPRNG rng(999);
    
    // Compatibility with std::uniform_int_distribution
    std::uniform_int_distribution<int> dist(1, 6);
    std::vector<int> counts(7, 0);
    for (int i = 0; i < 6000; ++i) {
        int val = dist(rng);
        TEST_ASSERT(val >= 1 && val <= 6);
        counts[val]++;
    }
    
    // Check distribution uniformity roughly (each number should occur around 1000 times)
    for (int i = 1; i <= 6; ++i) {
        TEST_ASSERT(counts[i] > 800 && counts[i] < 1200);
    }
    
    // Compatibility with std::shuffle
    std::vector<int> vec = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
    std::vector<int> original = vec;
    std::shuffle(vec.begin(), vec.end(), rng);
    
    // Should have shuffled elements
    TEST_ASSERT(vec != original);
    std::sort(vec.begin(), vec.end());
    TEST_ASSERT(vec == original); // but elements are still the same
    
    std::cout << "test_standard_compatibility PASSED." << std::endl;
}

void test_serialization() {
    std::cout << "Running test_serialization..." << std::endl;
    
    csprng::ChaCha20CSPRNG rng1(8888);
    // Generate some numbers to change internal state
    for (int i = 0; i < 25; ++i) rng1();
    
    std::stringstream ss;
    ss << rng1;
    
    csprng::ChaCha20CSPRNG rng2;
    ss >> rng2;
    
    TEST_ASSERT(rng1 == rng2);
    
    // Ensure they continue to generate identical streams
    for (int i = 0; i < 100; ++i) {
        TEST_ASSERT(rng1() == rng2());
    }
    
    std::cout << "test_serialization PASSED." << std::endl;
}

void test_thread_safety() {
    std::cout << "Running test_thread_safety..." << std::endl;
    
    csprng::ChaCha20CSPRNG shared_rng; // Auto-seeded
    
    const int num_threads = 8;
    const int iterations_per_thread = 10000;
    
    std::vector<std::future<std::vector<uint32_t>>> futures;
    
    // Spawn threads that concurrently read from the shared generator
    for (int t = 0; t < num_threads; ++t) {
        futures.push_back(std::async(std::launch::async, [&shared_rng]() {
            std::vector<uint32_t> results;
            results.reserve(iterations_per_thread);
            
            for (int i = 0; i < iterations_per_thread; ++i) {
                results.push_back(shared_rng());
                if (i % 100 == 0) {
                    uint8_t dummy[10];
                    shared_rng.fill_bytes(dummy, sizeof(dummy));
                }
            }
            return results;
        }));
    }
    
    // Collect all results
    std::vector<std::vector<uint32_t>> thread_results;
    for (auto& f : futures) {
        thread_results.push_back(f.get());
    }
    
    // If the generator was NOT thread safe, concurrent modifications of the buffer/state
    // would result in data corruption, duplicate arrays of values, or crashes.
    // Let's assert that the results from different threads do not look corrupted (e.g. all threads didn't get identical arrays)
    for (int i = 0; i < num_threads; ++i) {
        for (int j = i + 1; j < num_threads; ++j) {
            TEST_ASSERT(thread_results[i] != thread_results[j]);
        }
    }
    
    std::cout << "test_thread_safety PASSED." << std::endl;
}

void test_security_fixes() {
    std::cout << "Running test_security_fixes..." << std::endl;

    // Test move constructor zeroing/clearing
    {
        csprng::ChaCha20CSPRNG rng1(12345);
        rng1();
        
        csprng::ChaCha20CSPRNG rng2(std::move(rng1));
        
        std::stringstream ss;
        ss << rng1;
        
        bool all_zeros = true;
        for (int i = 0; i < 16; ++i) {
            uint32_t val;
            ss >> val;
            if (val != 0) {
                all_zeros = false;
            }
        }
        TEST_ASSERT(all_zeros);
    }

    // Test move assignment zeroing/clearing
    {
        csprng::ChaCha20CSPRNG rng1(12345);
        rng1();
        csprng::ChaCha20CSPRNG rng2;
        rng2 = std::move(rng1);
        
        std::stringstream ss;
        ss << rng1;
        bool all_zeros = true;
        for (int i = 0; i < 16; ++i) {
            uint32_t val;
            ss >> val;
            if (val != 0) {
                all_zeros = false;
            }
        }
        TEST_ASSERT(all_zeros);
    }

    // Test failed deserialization handling
    {
        csprng::ChaCha20CSPRNG rng1(999);
        csprng::ChaCha20CSPRNG rng2(999);
        
        std::stringstream ss("corrupted data");
        ss >> rng1; // Should fail, and not modify rng1
        
        TEST_ASSERT(rng1 == rng2);
    }

    std::cout << "test_security_fixes PASSED." << std::endl;
}

void test_memory_security_and_edge_cases() {
    std::cout << "Running test_memory_security_and_edge_cases..." << std::endl;

    csprng::ChaCha20CSPRNG rng(12345);

    // 1. Test fill_bytes with nullptr and size > 0 (must throw std::invalid_argument)
    bool threw_exception = false;
    try {
        rng.fill_bytes(nullptr, 32);
    } catch (const std::invalid_argument&) {
        threw_exception = true;
    }
    TEST_ASSERT(threw_exception);

    // 2. Test fill_bytes with nullptr and size == 0 (must not throw or crash)
    try {
        rng.fill_bytes(nullptr, 0);
    } catch (...) {
        TEST_ASSERT(false);
    }

    // 3. Test fill_bytes with valid buffer and size == 0
    uint8_t buffer[10] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    rng.fill_bytes(buffer, 0);
    for (int i = 0; i < 10; ++i) {
        TEST_ASSERT(buffer[i] == 0xFF);
    }

    // 4. Test constant-time equality check across identical and different states
    csprng::ChaCha20CSPRNG rng1(555);
    csprng::ChaCha20CSPRNG rng2(555);
    csprng::ChaCha20CSPRNG rng3(556);

    TEST_ASSERT(rng1 == rng2);
    TEST_ASSERT(rng1 != rng3);

    std::cout << "test_memory_security_and_edge_cases PASSED." << std::endl;
}

int main() {
    std::cout << "============================================" << std::endl;
    std::cout << "Starting CSPRNG-CPP Test Suite" << std::endl;
    std::cout << "============================================" << std::endl;
    
    test_determinism();
    test_fill_bytes();
    test_discard();
    test_standard_compatibility();
    test_serialization();
    test_thread_safety();
    test_security_fixes();
    test_memory_security_and_edge_cases();
    
    std::cout << "============================================" << std::endl;
    std::cout << "All CSPRNG tests PASSED successfully!" << std::endl;
    std::cout << "============================================" << std::endl;
    
    return 0;
}

