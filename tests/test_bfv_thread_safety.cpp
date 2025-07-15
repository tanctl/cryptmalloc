#include <atomic>
#include <catch2/catch_test_macros.hpp>
#include <future>
#include <random>
#include <thread>
#include <vector>
#include "cryptmalloc/bfv_context.hpp"

using namespace cryptmalloc;

TEST_CASE("bfv context thread safety", "[bfv][thread_safety]") {
    auto params = BFVParameters::for_security_level(SecurityLevel::SECURITY_128);
    params.polynomial_degree = 16384;
    BFVContext context(params);
    context.generate_keys();

    SECTION("concurrent encryption operations") {
        const int num_threads = 4;
        const int operations_per_thread = 10;
        std::vector<std::future<bool>> futures;

        for (int t = 0; t < num_threads; ++t) {
            futures.emplace_back(
                std::async(std::launch::async, [&context, operations_per_thread, t]() {
                    try {
                        std::random_device rd;
                        std::mt19937 gen(rd());
                        std::uniform_int_distribution<int64_t> dis(1, 10000);

                        for (int i = 0; i < operations_per_thread; ++i) {
                            int64_t value = dis(gen) + t * 1000;  // unique values per thread
                            auto ciphertext = context.encrypt(value);
                            auto decrypted = context.decrypt_single(ciphertext);

                            if (decrypted != value) {
                                return false;
                            }
                        }
                        return true;
                    } catch (...) {
                        return false;
                    }
                }));
        }

        // wait for all threads and check results
        for (auto& future : futures) {
            REQUIRE(future.get());
        }
    }

    SECTION("concurrent homomorphic operations") {
        const int num_threads = 3;
        const int operations_per_thread = 5;
        std::vector<std::future<bool>> futures;

        for (int t = 0; t < num_threads; ++t) {
            futures.emplace_back(
                std::async(std::launch::async, [&context, operations_per_thread, t]() {
                    try {
                        for (int i = 0; i < operations_per_thread; ++i) {
                            int64_t a = (t + 1) * 10 + i;
                            int64_t b = (t + 1) * 20 + i;

                            auto ct_a = context.encrypt(a);
                            auto ct_b = context.encrypt(b);

                            // test addition
                            auto ct_sum = context.add(ct_a, ct_b);
                            auto sum_result = context.decrypt_single(ct_sum);
                            if (sum_result != a + b) {
                                return false;
                            }

                            // test multiplication
                            auto ct_mult = context.multiply(ct_a, ct_b);
                            auto mult_result = context.decrypt_single(ct_mult);
                            if (mult_result != a * b) {
                                return false;
                            }
                        }
                        return true;
                    } catch (...) {
                        return false;
                    }
                }));
        }

        for (auto& future : futures) {
            REQUIRE(future.get());
        }
    }

    SECTION("concurrent context access") {
        const int num_threads = 4;
        std::atomic<int> successful_operations{0};
        std::vector<std::thread> threads;

        for (int t = 0; t < num_threads; ++t) {
            threads.emplace_back([&context, &successful_operations, t]() {
                try {
                    // each thread performs different operations
                    switch (t % 4) {
                        case 0: {
                            // encryption/decryption
                            auto ct = context.encrypt(100 + t);
                            auto result = context.decrypt_single(ct);
                            if (result == 100 + t) {
                                successful_operations.fetch_add(1);
                            }
                            break;
                        }
                        case 1: {
                            // get context info
                            auto crypto_context = context.get_crypto_context();
                            auto params = context.get_parameters();
                            if (crypto_context &&
                                params.security_level == SecurityLevel::SECURITY_128) {
                                successful_operations.fetch_add(1);
                            }
                            break;
                        }
                        case 2: {
                            // performance metrics
                            auto metrics = context.get_performance_metrics();
                            if (metrics.context_creation_time_ms > 0) {
                                successful_operations.fetch_add(1);
                            }
                            break;
                        }
                        case 3: {
                            // state checks
                            bool initialized = context.is_initialized();
                            bool keys_generated = context.is_key_generated();
                            if (initialized && keys_generated) {
                                successful_operations.fetch_add(1);
                            }
                            break;
                        }
                    }
                } catch (...) {
                    // thread failed
                }
            });
        }

        for (auto& thread : threads) {
            thread.join();
        }

        REQUIRE(successful_operations.load() == num_threads);
    }
}

TEST_CASE("bfv key management thread safety", "[bfv][thread_safety]") {
    auto params = BFVParameters::for_security_level(SecurityLevel::SECURITY_128);
    params.polynomial_degree = 16384;

    SECTION("concurrent key generation attempts") {
        BFVContext context(params);
        const int num_threads = 3;
        std::vector<std::future<bool>> futures;
        std::atomic<int> successful_generations{0};

        for (int t = 0; t < num_threads; ++t) {
            futures.emplace_back(
                std::async(std::launch::async, [&context, &successful_generations]() {
                    try {
                        context.generate_keys();
                        successful_generations.fetch_add(1);
                        return true;
                    } catch (...) {
                        return false;
                    }
                }));
        }

        for (auto& future : futures) {
            future.get();  // wait for completion
        }

        // only one thread should succeed in generating keys
        REQUIRE(successful_generations.load() >= 1);
        REQUIRE(context.is_key_generated());
    }

    SECTION("key clearing during operations") {
        BFVContext context(params);
        context.generate_keys();

        std::atomic<bool> stop_flag{false};
        std::atomic<int> encryption_successes{0};
        std::atomic<int> encryption_failures{0};

        // thread doing encryptions
        std::thread encryption_thread([&]() {
            int64_t value = 42;
            while (!stop_flag.load()) {
                try {
                    auto ct = context.encrypt(value);
                    auto result = context.decrypt_single(ct);
                    if (result == value) {
                        encryption_successes.fetch_add(1);
                    }
                } catch (...) {
                    encryption_failures.fetch_add(1);
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
            }
        });

        // thread clearing and regenerating keys
        std::thread key_management_thread([&]() {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            context.clear_keys();
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
            context.generate_keys();
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            stop_flag.store(true);
        });

        encryption_thread.join();
        key_management_thread.join();

        // should have some operations that succeeded and some that failed
        REQUIRE(encryption_failures.load() > 0);  // some should fail when keys cleared
        REQUIRE(context.is_key_generated());      // keys should be regenerated at end
    }
}

TEST_CASE("ciphertext pool thread safety", "[bfv][thread_safety]") {
    auto& pool = CiphertextPool::instance();
    pool.clear();

    SECTION("concurrent pool operations") {
        const int num_threads = 4;
        const int operations_per_thread = 20;
        std::vector<std::thread> threads;
        std::atomic<int> successful_operations{0};

        for (int t = 0; t < num_threads; ++t) {
            threads.emplace_back([&pool, &successful_operations, operations_per_thread]() {
                try {
                    std::vector<lbcrypto::Ciphertext<lbcrypto::DCRTPoly>> acquired_cts;

                    // acquire some ciphertexts
                    for (int i = 0; i < operations_per_thread / 2; ++i) {
                        acquired_cts.push_back(pool.acquire());
                    }

                    // release them back
                    for (auto& ct : acquired_cts) {
                        pool.release(std::move(ct));
                    }

                    successful_operations.fetch_add(1);
                } catch (...) {
                    // operation failed
                }
            });
        }

        for (auto& thread : threads) {
            thread.join();
        }

        REQUIRE(successful_operations.load() == num_threads);

        // pool should be in consistent state
        REQUIRE(pool.active_count() == 0);
    }

    SECTION("stress test pool operations") {
        const int num_threads = 8;
        const int operations_per_thread = 50;
        std::vector<std::thread> threads;
        std::atomic<size_t> total_acquires{0};
        std::atomic<size_t> total_releases{0};

        for (int t = 0; t < num_threads; ++t) {
            threads.emplace_back(
                [&pool, &total_acquires, &total_releases, operations_per_thread]() {
                    std::random_device rd;
                    std::mt19937 gen(rd());
                    std::uniform_int_distribution<int> dis(1, 5);

                    std::vector<lbcrypto::Ciphertext<lbcrypto::DCRTPoly>> held_cts;

                    for (int i = 0; i < operations_per_thread; ++i) {
                        int operation = dis(gen);

                        if (operation <= 3 || held_cts.empty()) {
                            // acquire operation
                            held_cts.push_back(pool.acquire());
                            total_acquires.fetch_add(1);
                        } else {
                            // release operation
                            auto ct = std::move(held_cts.back());
                            held_cts.pop_back();
                            pool.release(std::move(ct));
                            total_releases.fetch_add(1);
                        }

                        // small delay to increase contention
                        if (i % 10 == 0) {
                            std::this_thread::sleep_for(std::chrono::microseconds(1));
                        }
                    }

                    // release remaining ciphertexts
                    for (auto& ct : held_cts) {
                        pool.release(std::move(ct));
                        total_releases.fetch_add(1);
                    }
                });
        }

        for (auto& thread : threads) {
            thread.join();
        }

        // verify consistency
        REQUIRE(total_acquires.load() == total_releases.load());
        REQUIRE(pool.active_count() == 0);
    }
}

TEST_CASE("secure memory thread safety", "[bfv][thread_safety]") {
    SECTION("concurrent secure allocations") {
        const int num_threads = 4;
        const int allocations_per_thread = 10;
        std::vector<std::thread> threads;
        std::atomic<int> successful_allocations{0};

        for (int t = 0; t < num_threads; ++t) {
            threads.emplace_back([&successful_allocations, allocations_per_thread]() {
                std::vector<std::pair<void*, size_t>> allocations;

                try {
                    // allocate memory blocks
                    for (int i = 0; i < allocations_per_thread; ++i) {
                        size_t size = 1024 + i * 64;  // varying sizes
                        void* ptr = SecureMemory::allocate_secure(size);
                        if (ptr) {
                            allocations.emplace_back(ptr, size);

                            // write some data to verify allocation works
                            std::memset(ptr, 0x42, size);
                        }
                    }

                    // verify data and deallocate
                    for (auto& [ptr, size] : allocations) {
                        // verify first few bytes
                        unsigned char* bytes = static_cast<unsigned char*>(ptr);
                        bool data_ok = true;
                        for (size_t i = 0; i < std::min(size, size_t(16)); ++i) {
                            if (bytes[i] != 0x42) {
                                data_ok = false;
                                break;
                            }
                        }

                        if (data_ok) {
                            SecureMemory::deallocate_secure(ptr, size);
                        }
                    }

                    successful_allocations.fetch_add(1);
                } catch (...) {
                    // cleanup on exception
                    for (auto& [ptr, size] : allocations) {
                        if (ptr) {
                            SecureMemory::deallocate_secure(ptr, size);
                        }
                    }
                }
            });
        }

        for (auto& thread : threads) {
            thread.join();
        }

        REQUIRE(successful_allocations.load() == num_threads);
    }

    SECTION("concurrent secure zero operations") {
        const size_t buffer_size = 4096;
        const int num_threads = 4;
        std::vector<std::thread> threads;
        std::atomic<int> successful_operations{0};

        // allocate shared buffer
        void* shared_buffer = SecureMemory::allocate_secure(buffer_size);
        REQUIRE(shared_buffer != nullptr);

        // fill with test pattern
        std::memset(shared_buffer, 0xAA, buffer_size);

        for (int t = 0; t < num_threads; ++t) {
            threads.emplace_back(
                [shared_buffer, buffer_size, &successful_operations, t, num_threads]() {
                    try {
                        // each thread zeros a different section
                        size_t section_size = buffer_size / num_threads;
                        size_t offset = t * section_size;

                        char* buffer_ptr = static_cast<char*>(shared_buffer);
                        SecureMemory::secure_zero(buffer_ptr + offset, section_size);

                        successful_operations.fetch_add(1);
                    } catch (...) {
                        // operation failed
                    }
                });
        }

        for (auto& thread : threads) {
            thread.join();
        }

        REQUIRE(successful_operations.load() == num_threads);

        // verify that buffer was properly zeroed
        unsigned char* bytes = static_cast<unsigned char*>(shared_buffer);
        for (size_t i = 0; i < buffer_size; ++i) {
            REQUIRE(bytes[i] == 0);
        }

        SecureMemory::deallocate_secure(shared_buffer, buffer_size);
    }
}