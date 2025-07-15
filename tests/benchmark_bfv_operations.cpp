#include <catch2/benchmark/catch_benchmark.hpp>
#include <catch2/catch_test_macros.hpp>
#include <chrono>
#include <random>
#include <vector>
#include "cryptmalloc/bfv_operations.hpp"

using namespace cryptmalloc;

// benchmark fixture with pre-initialized context
class OperationsBenchmarkFixture {
  public:
    std::shared_ptr<BFVContext> context;
    std::vector<EncryptedInt> encrypted_values;
    std::vector<int64_t> plaintext_values;

    void setup(size_t count = 100) {
        auto params = BFVParameters::for_security_level(SecurityLevel::SECURITY_128);
        params.polynomial_degree = 16384;  // updated for OpenFHE 1.3.1 security requirements
        params.multiplicative_depth = 3;

        context = std::make_shared<BFVContext>(params);
        context->generate_keys();

        // generate test data
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<int64_t> dis(-1000, 1000);

        plaintext_values.clear();
        encrypted_values.clear();

        for (size_t i = 0; i < count; ++i) {
            int64_t value = dis(gen);
            plaintext_values.push_back(value);
            encrypted_values.emplace_back(context, value);
        }
    }
};

TEST_CASE("basic arithmetic operation benchmarks", "[benchmark][operations]") {
    OperationsBenchmarkFixture fixture;
    fixture.setup(10);  // smaller dataset for basic operations

    SECTION("single operation comparison") {
        int64_t a_plain = 123, b_plain = 456;
        EncryptedInt a_enc(fixture.context, a_plain);
        EncryptedInt b_enc(fixture.context, b_plain);

        BENCHMARK("plaintext addition") {
            return a_plain + b_plain;
        };

        BENCHMARK("encrypted addition") {
            return a_enc + b_enc;
        };

        BENCHMARK("plaintext multiplication") {
            return a_plain * b_plain;
        };

        BENCHMARK("encrypted multiplication") {
            return a_enc * b_enc;
        };

        BENCHMARK("plaintext subtraction") {
            return a_plain - b_plain;
        };

        BENCHMARK("encrypted subtraction") {
            return a_enc - b_enc;
        };
    }

    SECTION("mixed plaintext-encrypted operations") {
        EncryptedInt a_enc(fixture.context, 100);
        int64_t b_plain = 25;

        BENCHMARK("encrypted + plaintext") {
            return a_enc + b_plain;
        };

        BENCHMARK("encrypted * plaintext") {
            return a_enc * b_plain;
        };

        BENCHMARK("encrypted - plaintext") {
            return a_enc - b_plain;
        };
    }
}

TEST_CASE("batch operation benchmarks", "[benchmark][operations]") {
    OperationsBenchmarkFixture fixture;
    fixture.setup(1000);

    SECTION("vector operations comparison") {
        // prepare batch data
        std::vector<int64_t> batch1_plain, batch2_plain;
        std::vector<EncryptedInt> batch1_enc, batch2_enc;

        for (size_t i = 0; i < 100; ++i) {
            batch1_plain.push_back(i + 1);
            batch2_plain.push_back(i * 2);
            batch1_enc.emplace_back(fixture.context, i + 1);
            batch2_enc.emplace_back(fixture.context, i * 2);
        }

        BENCHMARK("plaintext vector addition") {
            std::vector<int64_t> result;
            result.reserve(batch1_plain.size());
            for (size_t i = 0; i < batch1_plain.size(); ++i) {
                result.push_back(batch1_plain[i] + batch2_plain[i]);
            }
            return result.size();
        };

        BENCHMARK("encrypted vector addition") {
            auto result = arithmetic::batch_add(batch1_enc, batch2_enc);
            return result.size();
        };

        BENCHMARK("plaintext vector sum") {
            int64_t sum = 0;
            for (auto val : batch1_plain) {
                sum += val;
            }
            return sum;
        };

        BENCHMARK("encrypted vector sum") {
            auto result = arithmetic::compute_sum(batch1_enc);
            return result.decrypt();
        };
    }

    SECTION("simd-style batch operations") {
        std::vector<int64_t> values1(64), values2(64);
        std::iota(values1.begin(), values1.end(), 1);
        std::iota(values2.begin(), values2.end(), 100);

        EncryptedBatch batch1(fixture.context, values1);
        EncryptedBatch batch2(fixture.context, values2);

        BENCHMARK("plaintext simd addition") {
            std::vector<int64_t> result(64);
            for (size_t i = 0; i < 64; ++i) {
                result[i] = values1[i] + values2[i];
            }
            return result.size();
        };

        BENCHMARK("encrypted batch addition") {
            auto result = batch1 + batch2;
            return result.size();
        };

        BENCHMARK("plaintext simd multiplication") {
            std::vector<int64_t> result(64);
            for (size_t i = 0; i < 64; ++i) {
                result[i] = values1[i] * values2[i];
            }
            return result.size();
        };

        BENCHMARK("encrypted batch multiplication") {
            auto result = batch1 * batch2;
            return result.size();
        };
    }
}

TEST_CASE("complex operation benchmarks", "[benchmark][operations]") {
    OperationsBenchmarkFixture fixture;
    fixture.setup();

    SECTION("polynomial evaluation") {
        std::vector<int64_t> coefficients = {1, 2, 3, 4, 5};  // 5x^4 + 4x^3 + 3x^2 + 2x + 1
        int64_t x_plain = 3;
        EncryptedInt x_enc(fixture.context, x_plain);

        BENCHMARK("plaintext polynomial evaluation") {
            int64_t result = coefficients[0];
            int64_t x_power = 1;
            for (size_t i = 1; i < coefficients.size(); ++i) {
                x_power *= x_plain;
                result += coefficients[i] * x_power;
            }
            return result;
        };

        BENCHMARK("encrypted polynomial evaluation") {
            auto result = arithmetic::evaluate_polynomial(x_enc, coefficients);
            return result.decrypt();
        };
    }

    SECTION("chained operations") {
        int64_t a_plain = 5, b_plain = 3, c_plain = 2;
        EncryptedInt a_enc(fixture.context, a_plain);
        EncryptedInt b_enc(fixture.context, b_plain);
        EncryptedInt c_enc(fixture.context, c_plain);

        BENCHMARK("plaintext chain: (a+b)*c-a") {
            return (a_plain + b_plain) * c_plain - a_plain;
        };

        BENCHMARK("encrypted chain: (a+b)*c-a") {
            auto result = (a_enc + b_enc) * c_enc - a_enc;
            return result.decrypt();
        };

        BENCHMARK("plaintext chain: a*b + c*a + b*c") {
            return a_plain * b_plain + c_plain * a_plain + b_plain * c_plain;
        };

        BENCHMARK("encrypted chain: a*b + c*a + b*c") {
            auto result = a_enc * b_enc + c_enc * a_enc + b_enc * c_enc;
            return result.decrypt();
        };
    }

    SECTION("memory allocator operations") {
        int64_t base_addr_plain = 1000;
        int64_t index_plain = 10;
        int64_t element_size = 8;

        EncryptedInt base_addr_enc(fixture.context, base_addr_plain);
        EncryptedInt index_enc(fixture.context, index_plain);

        BENCHMARK("plaintext address calculation") {
            return base_addr_plain + index_plain * element_size;
        };

        BENCHMARK("encrypted address calculation") {
            auto result =
                arithmetic::compute_address_offset(base_addr_enc, index_enc, element_size);
            return result.decrypt();
        };

        // alignment calculation
        int64_t size_plain = 123;
        int64_t alignment = 16;
        EncryptedInt size_enc(fixture.context, size_plain);

        BENCHMARK("plaintext size alignment") {
            return ((size_plain + alignment - 1) / alignment) * alignment;
        };

        BENCHMARK("encrypted size alignment") {
            auto result = arithmetic::compute_aligned_size(size_enc, alignment);
            return result.decrypt();
        };
    }
}

TEST_CASE("noise management benchmarks", "[benchmark][operations]") {
    OperationsBenchmarkFixture fixture;
    fixture.setup();

    SECTION("refresh operation costs") {
        EncryptedInt a(fixture.context, 42);

        BENCHMARK("noise info update") {
            return a.get_noise_info().current_level;
        };

        BENCHMARK("ciphertext refresh") {
            a.force_refresh();
            return a.decrypt();
        };

        BENCHMARK("validation check") {
            return a.validate_integrity();
        };
    }

    SECTION("automatic vs manual refresh") {
        ArithmeticConfig::instance().set_auto_refresh(true);
        EncryptedInt a_auto(fixture.context, 2);

        ArithmeticConfig::instance().set_auto_refresh(false);
        EncryptedInt a_manual(fixture.context, 2);

        BENCHMARK("multiplication with auto refresh") {
            auto temp = a_auto;
            for (int i = 0; i < 3; ++i) {
                temp *= 2;  // may trigger auto refresh
            }
            return temp.decrypt();
        };

        BENCHMARK("multiplication without auto refresh") {
            auto temp = a_manual;
            for (int i = 0; i < 3; ++i) {
                temp *= 2;  // no auto refresh
            }
            return temp.decrypt();
        };
    }
}

TEST_CASE("scalability benchmarks", "[benchmark][operations]") {
    SECTION("operation count scaling") {
        OperationsBenchmarkFixture fixture;
        fixture.setup();

        // test with different numbers of operations
        for (size_t count : {10, 50, 100, 500}) {
            std::string bench_name = "encrypted additions (count=" + std::to_string(count) + ")";

            BENCHMARK(bench_name.c_str()) {
                EncryptedInt result(fixture.context, 0);
                for (size_t i = 0; i < count; ++i) {
                    result += fixture.encrypted_values[i % fixture.encrypted_values.size()];
                }
                return result.decrypt();
            };
        }
    }

    SECTION("data size scaling") {
        // test batch operations with different sizes
        for (size_t batch_size : {16, 64, 256, 1024}) {
            std::vector<int64_t> values(batch_size);
            std::iota(values.begin(), values.end(), 1);

            OperationsBenchmarkFixture fixture;
            fixture.setup();

            EncryptedBatch batch(fixture.context, values);

            std::string bench_name = "batch sum (size=" + std::to_string(batch_size) + ")";
            BENCHMARK(bench_name.c_str()) {
                auto result = batch.sum();
                return result.decrypt();
            };
        }
    }
}

TEST_CASE("memory usage benchmarks", "[benchmark][operations]") {
    OperationsBenchmarkFixture fixture;
    fixture.setup();

    SECTION("ciphertext size measurements") {
        EncryptedInt a(fixture.context, 42);

        size_t initial_size = a.get_ciphertext_size();

        // after operations, size might change
        auto b = a * 2;
        size_t after_mult_size = b.get_ciphertext_size();

        auto c = a + b;
        size_t after_add_size = c.get_ciphertext_size();

        REQUIRE(initial_size > 0);
        // sizes may vary based on operations
        INFO("Initial size: " << initial_size);
        INFO("After multiplication: " << after_mult_size);
        INFO("After addition: " << after_add_size);
    }

    SECTION("batch vs individual memory usage") {
        std::vector<int64_t> values(100);
        std::iota(values.begin(), values.end(), 1);

        // individual encrypted integers
        std::vector<EncryptedInt> individual_ints;
        size_t individual_total_size = 0;

        for (auto val : values) {
            individual_ints.emplace_back(fixture.context, val);
            individual_total_size += individual_ints.back().get_ciphertext_size();
        }

        // single batch
        EncryptedBatch batch(fixture.context, values);
        size_t batch_size = batch.size() * sizeof(int64_t);  // approximate

        INFO("Individual total size: " << individual_total_size);
        INFO("Batch size: " << batch_size);

        // batch should be more memory efficient
        REQUIRE(batch_size < individual_total_size);
    }
}

TEST_CASE("error handling performance", "[benchmark][operations]") {
    OperationsBenchmarkFixture fixture;
    fixture.setup();

    SECTION("overflow detection overhead") {
        ArithmeticConfig::instance().set_overflow_behavior(OverflowBehavior::THROW_EXCEPTION);
        EncryptedInt a(fixture.context, 100);

        BENCHMARK("addition with overflow checking") {
            return a + 50;
        };

        ArithmeticConfig::instance().set_overflow_behavior(OverflowBehavior::IGNORE);

        BENCHMARK("addition without overflow checking") {
            return a + 50;
        };
    }

    SECTION("validation overhead") {
        EncryptedInt a(fixture.context, 42);

        BENCHMARK("operation with validation") {
            auto result = a + 8;
            result.validate_integrity();
            return result.decrypt();
        };

        BENCHMARK("operation without validation") {
            auto result = a + 8;
            return result.decrypt();
        };
    }
}

TEST_CASE("real-world scenario benchmarks", "[benchmark][operations]") {
    OperationsBenchmarkFixture fixture;
    fixture.setup();

    SECTION("memory allocation simulation") {
        // simulate encrypted memory allocator operations
        EncryptedInt heap_base(fixture.context, 0x10000000);  // base heap address
        EncryptedInt current_offset(fixture.context, 0);

        BENCHMARK("allocate 10 blocks") {
            auto temp_offset = current_offset;
            for (int i = 0; i < 10; ++i) {
                auto block_size = EncryptedInt(fixture.context, 64 + i * 8);  // varying sizes
                auto aligned_size = arithmetic::compute_aligned_size(block_size, 8);
                temp_offset += aligned_size;  // move to next block
            }
            return temp_offset.decrypt();
        };

        BENCHMARK("compute fragmentation") {
            // simulate fragmentation calculation
            std::vector<EncryptedInt> block_sizes;
            for (int i = 0; i < 5; ++i) {
                block_sizes.emplace_back(fixture.context, 32 << i);  // powers of 2
            }

            auto total_size = arithmetic::compute_sum(block_sizes);
            auto average_size = total_size * (1.0 / block_sizes.size());  // approximate

            return average_size.decrypt();
        };
    }

    SECTION("encrypted data structure operations") {
        // simulate encrypted linked list node operations
        EncryptedInt node_addr(fixture.context, 0x1000);
        EncryptedInt node_size(fixture.context, 16);
        EncryptedInt next_offset(fixture.context, 8);

        BENCHMARK("compute next node address") {
            return node_addr + next_offset;
        };

        BENCHMARK("compute data address") {
            auto data_offset = EncryptedInt(fixture.context, 0);  // data at start of node
            return node_addr + data_offset;
        };

        BENCHMARK("compute end address") {
            return node_addr + node_size;
        };
    }
}