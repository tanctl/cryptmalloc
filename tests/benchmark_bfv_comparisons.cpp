#include <catch2/catch_test_macros.hpp>
#include <catch2/benchmark/catch_benchmark.hpp>
#include <chrono>
#include <random>
#include <vector>
#include "cryptmalloc/bfv_comparisons.hpp"
#include "cryptmalloc/bfv_operations.hpp"

using namespace cryptmalloc;

class ComparisonBenchmarkFixture {
  protected:
    std::shared_ptr<BFVContext> context_;
    std::vector<EncryptedInt> test_values_;
    std::random_device rd_;
    std::mt19937 gen_;

    void SetUp() {
        auto params = BFVParameters::for_security_level(SecurityLevel::SECURITY_128);
        params.polynomial_degree = 16384;
        params.multiplicative_depth = 8;
        context_ = std::make_shared<BFVContext>(params);
        context_->generate_keys();

        gen_.seed(42);  // deterministic for reproducible benchmarks
        
        // prepare test values
        std::uniform_int_distribution<int64_t> dis(-10000, 10000);
        for (int i = 0; i < 100; ++i) {
            test_values_.emplace_back(context_, dis(gen_));
        }
    }

  public:
    ComparisonBenchmarkFixture() : gen_(rd_()) {
        SetUp();
    }
};

TEST_CASE_METHOD(ComparisonBenchmarkFixture, "comparison method benchmarks", "[benchmark][methods]") {
    EncryptedInt a(context_, 1000);
    EncryptedInt b(context_, 500);

    SECTION("sign detection method benchmark") {
        BENCHMARK("Sign detection - greater than") {
            auto result = comparisons::greater_than(a, b, ComparisonMethod::SIGN_DETECTION);
            return result.decrypt();
        };

        BENCHMARK("Sign detection - less than") {
            auto result = comparisons::less_than(a, b, ComparisonMethod::SIGN_DETECTION);
            return result.decrypt();
        };

        BENCHMARK("Sign detection - equal") {
            auto result = comparisons::equal(a, a, ComparisonMethod::SIGN_DETECTION);
            return result.decrypt();
        };
    }

    SECTION("polynomial approximation method benchmark") {
        BENCHMARK("Polynomial approx - greater than") {
            auto result = comparisons::greater_than(a, b, ComparisonMethod::POLYNOMIAL_APPROX);
            return result.decrypt();
        };

        BENCHMARK("Polynomial approx - less than") {
            auto result = comparisons::less_than(a, b, ComparisonMethod::POLYNOMIAL_APPROX);
            return result.decrypt();
        };

        BENCHMARK("Polynomial approx - equal") {
            auto result = comparisons::equal(a, a, ComparisonMethod::POLYNOMIAL_APPROX);
            return result.decrypt();
        };
    }

    SECTION("bitwise comparison method benchmark") {
        BENCHMARK("Bitwise - greater than") {
            auto result = comparisons::greater_than(a, b, ComparisonMethod::BITWISE_COMPARISON);
            return result.decrypt();
        };

        BENCHMARK("Bitwise - less than") {
            auto result = comparisons::less_than(a, b, ComparisonMethod::BITWISE_COMPARISON);
            return result.decrypt();
        };
    }

    SECTION("optimized hybrid method benchmark") {
        BENCHMARK("Hybrid - greater than") {
            auto result = comparisons::greater_than(a, b, ComparisonMethod::OPTIMIZED_HYBRID);
            return result.decrypt();
        };

        BENCHMARK("Hybrid - less than") {
            auto result = comparisons::less_than(a, b, ComparisonMethod::OPTIMIZED_HYBRID);
            return result.decrypt();
        };
    }
}

TEST_CASE_METHOD(ComparisonBenchmarkFixture, "conditional selection benchmarks", "[benchmark][conditional]") {
    EncryptedInt true_value(context_, 100);
    EncryptedInt false_value(context_, 200);
    EncryptedBool condition_true(context_, true);
    EncryptedBool condition_false(context_, false);

    SECTION("basic conditional selection") {
        BENCHMARK("Conditional select - true condition") {
            auto result = comparisons::conditional_select(condition_true, true_value, false_value);
            return result.decrypt();
        };

        BENCHMARK("Conditional select - false condition") {
            auto result = comparisons::conditional_select(condition_false, true_value, false_value);
            return result.decrypt();
        };
    }

    SECTION("conditional selection with comparison") {
        EncryptedInt a(context_, 150);
        EncryptedInt b(context_, 75);

        BENCHMARK("Conditional select with comparison") {
            auto condition = comparisons::greater_than(a, b);
            auto result = comparisons::conditional_select(condition, a, b);
            return result.decrypt();
        };
    }

    SECTION("nested conditional selections") {
        EncryptedInt val1(context_, 10);
        EncryptedInt val2(context_, 20);
        EncryptedInt val3(context_, 30);

        BENCHMARK("Nested conditional selections") {
            auto cond1 = comparisons::greater_than(val1, val2);
            auto intermediate = comparisons::conditional_select(cond1, val1, val2);
            auto cond2 = comparisons::greater_than(intermediate, val3);
            auto result = comparisons::conditional_select(cond2, intermediate, val3);
            return result.decrypt();
        };
    }
}

TEST_CASE_METHOD(ComparisonBenchmarkFixture, "min max operation benchmarks", "[benchmark][minmax]") {
    SECTION("basic min max operations") {
        EncryptedInt a(context_, 1000);
        EncryptedInt b(context_, 500);

        BENCHMARK("Min operation") {
            auto result = comparisons::min(a, b);
            return result.decrypt();
        };

        BENCHMARK("Max operation") {
            auto result = comparisons::max(a, b);
            return result.decrypt();
        };
    }

    SECTION("vector min max operations") {
        std::vector<EncryptedInt> small_vec(test_values_.begin(), test_values_.begin() + 10);
        std::vector<EncryptedInt> medium_vec(test_values_.begin(), test_values_.begin() + 25);
        std::vector<EncryptedInt> large_vec(test_values_.begin(), test_values_.begin() + 50);

        BENCHMARK("Find min - 10 elements") {
            auto result = comparisons::find_min(small_vec);
            return result.decrypt();
        };

        BENCHMARK("Find max - 10 elements") {
            auto result = comparisons::find_max(small_vec);
            return result.decrypt();
        };

        BENCHMARK("Find min - 25 elements") {
            auto result = comparisons::find_min(medium_vec);
            return result.decrypt();
        };

        BENCHMARK("Find max - 25 elements") {
            auto result = comparisons::find_max(medium_vec);
            return result.decrypt();
        };

        BENCHMARK("Find min - 50 elements") {
            auto result = comparisons::find_min(large_vec);
            return result.decrypt();
        };

        BENCHMARK("Find max - 50 elements") {
            auto result = comparisons::find_max(large_vec);
            return result.decrypt();
        };
    }
}

TEST_CASE_METHOD(ComparisonBenchmarkFixture, "sign and absolute value benchmarks", "[benchmark][sign]") {
    EncryptedInt positive_val(context_, 1000);
    EncryptedInt negative_val(context_, -1000);
    EncryptedInt zero_val(context_, 0);

    SECTION("sign detection operations") {
        BENCHMARK("Is positive - positive value") {
            auto result = comparisons::is_positive(positive_val);
            return result.decrypt();
        };

        BENCHMARK("Is positive - negative value") {
            auto result = comparisons::is_positive(negative_val);
            return result.decrypt();
        };

        BENCHMARK("Is negative - negative value") {
            auto result = comparisons::is_negative(negative_val);
            return result.decrypt();
        };

        BENCHMARK("Is zero - zero value") {
            auto result = comparisons::is_zero(zero_val);
            return result.decrypt();
        };
    }

    SECTION("absolute value operations") {
        BENCHMARK("Absolute value - positive") {
            auto result = comparisons::absolute_value(positive_val);
            return result.decrypt();
        };

        BENCHMARK("Absolute value - negative") {
            auto result = comparisons::absolute_value(negative_val);
            return result.decrypt();
        };

        BENCHMARK("Absolute value - zero") {
            auto result = comparisons::absolute_value(zero_val);
            return result.decrypt();
        };
    }

    SECTION("sign function operations") {
        BENCHMARK("Sign function - positive") {
            auto result = comparisons::sign(positive_val);
            return result.decrypt();
        };

        BENCHMARK("Sign function - negative") {
            auto result = comparisons::sign(negative_val);
            return result.decrypt();
        };

        BENCHMARK("Sign function - zero") {
            auto result = comparisons::sign(zero_val);
            return result.decrypt();
        };
    }
}

TEST_CASE_METHOD(ComparisonBenchmarkFixture, "batch operation benchmarks", "[benchmark][batch]") {
    std::vector<EncryptedInt> vec_a(test_values_.begin(), test_values_.begin() + 20);
    std::vector<EncryptedInt> vec_b(test_values_.begin() + 20, test_values_.begin() + 40);

    SECTION("batch comparison operations") {
        BENCHMARK("Batch greater than - 20 elements") {
            auto results = comparisons::batch_greater_than(vec_a, vec_b);
            bool all_computed = true;
            for (const auto& result : results) {
                all_computed &= (result.decrypt() == true || result.decrypt() == false);
            }
            return all_computed;
        };

        BENCHMARK("Batch equal - 20 elements") {
            auto results = comparisons::batch_equal(vec_a, vec_a);  // compare with self for equality
            bool all_computed = true;
            for (const auto& result : results) {
                all_computed &= result.decrypt();
            }
            return all_computed;
        };
    }

    SECTION("batch operations scaling") {
        std::vector<EncryptedInt> small_a(test_values_.begin(), test_values_.begin() + 5);
        std::vector<EncryptedInt> small_b(test_values_.begin() + 5, test_values_.begin() + 10);
        
        std::vector<EncryptedInt> large_a(test_values_.begin(), test_values_.begin() + 50);
        std::vector<EncryptedInt> large_b(test_values_.begin() + 50, test_values_.end());

        BENCHMARK("Batch greater than - 5 elements") {
            auto results = comparisons::batch_greater_than(small_a, small_b);
            return results.size();
        };

        BENCHMARK("Batch greater than - 50 elements") {
            auto results = comparisons::batch_greater_than(large_a, large_b);
            return results.size();
        };
    }
}

TEST_CASE_METHOD(ComparisonBenchmarkFixture, "range checking benchmarks", "[benchmark][range]") {
    EncryptedInt test_value(context_, 150);
    EncryptedInt min_bound(context_, 100);
    EncryptedInt max_bound(context_, 200);

    SECTION("range checking operations") {
        BENCHMARK("In range - encrypted bounds") {
            auto result = comparisons::in_range(test_value, min_bound, max_bound);
            return result.decrypt();
        };

        BENCHMARK("In range - plaintext bounds") {
            auto result = comparisons::in_range(test_value, 100, 200);
            return result.decrypt();
        };
    }

    SECTION("range checking with different value positions") {
        EncryptedInt below_range(context_, 50);
        EncryptedInt in_range(context_, 150);
        EncryptedInt above_range(context_, 250);

        BENCHMARK("Range check - below range") {
            auto result = comparisons::in_range(below_range, min_bound, max_bound);
            return result.decrypt();
        };

        BENCHMARK("Range check - in range") {
            auto result = comparisons::in_range(in_range, min_bound, max_bound);
            return result.decrypt();
        };

        BENCHMARK("Range check - above range") {
            auto result = comparisons::in_range(above_range, min_bound, max_bound);
            return result.decrypt();
        };
    }
}

TEST_CASE_METHOD(ComparisonBenchmarkFixture, "boolean operation benchmarks", "[benchmark][boolean]") {
    EncryptedBool true_bool(context_, true);
    EncryptedBool false_bool(context_, false);

    SECTION("basic boolean operations") {
        BENCHMARK("Boolean AND - true && true") {
            auto result = true_bool && true_bool;
            return result.decrypt();
        };

        BENCHMARK("Boolean AND - true && false") {
            auto result = true_bool && false_bool;
            return result.decrypt();
        };

        BENCHMARK("Boolean OR - true || false") {
            auto result = true_bool || false_bool;
            return result.decrypt();
        };

        BENCHMARK("Boolean OR - false || false") {
            auto result = false_bool || false_bool;
            return result.decrypt();
        };

        BENCHMARK("Boolean NOT - !true") {
            auto result = !true_bool;
            return result.decrypt();
        };

        BENCHMARK("Boolean XOR - true ^ false") {
            auto result = true_bool ^ false_bool;
            return result.decrypt();
        };
    }

    SECTION("complex boolean expressions") {
        BENCHMARK("Complex boolean expression") {
            auto result = (true_bool && false_bool) || (!true_bool ^ false_bool);
            return result.decrypt();
        };

        BENCHMARK("Nested boolean operations") {
            auto intermediate1 = true_bool && false_bool;
            auto intermediate2 = !intermediate1;
            auto result = intermediate2 || true_bool;
            return result.decrypt();
        };
    }
}

TEST_CASE_METHOD(ComparisonBenchmarkFixture, "performance target verification", "[benchmark][performance]") {
    EncryptedInt a(context_, 1000);
    EncryptedInt b(context_, 500);

    SECTION("50ms performance target verification") {
        // verify that basic operations meet the <50ms requirement
        auto start = std::chrono::high_resolution_clock::now();
        
        auto result = comparisons::greater_than(a, b);
        result.decrypt();  // ensure computation is complete
        
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
        
        REQUIRE(duration.count() < 50);  // must meet performance requirement
        INFO("Greater than comparison took: " << duration.count() << "ms");
    }

    SECTION("conditional selection performance target") {
        EncryptedBool condition(context_, true);
        
        auto start = std::chrono::high_resolution_clock::now();
        
        auto result = comparisons::conditional_select(condition, a, b);
        result.decrypt();
        
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
        
        REQUIRE(duration.count() < 50);
        INFO("Conditional selection took: " << duration.count() << "ms");
    }

    SECTION("min/max performance target") {
        auto start = std::chrono::high_resolution_clock::now();
        
        auto result = comparisons::min(a, b);
        result.decrypt();
        
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
        
        REQUIRE(duration.count() < 50);
        INFO("Min operation took: " << duration.count() << "ms");
    }
}

TEST_CASE_METHOD(ComparisonBenchmarkFixture, "memory usage benchmarks", "[benchmark][memory]") {
    SECTION("ciphertext size analysis") {
        EncryptedInt test_int(context_, 1000);
        EncryptedBool test_bool(context_, true);

        auto int_size = test_int.get_ciphertext_size();
        auto bool_size = test_bool.get_ciphertext_size();

        BENCHMARK("Memory usage - EncryptedInt creation") {
            EncryptedInt temp(context_, 42);
            return temp.get_ciphertext_size();
        };

        BENCHMARK("Memory usage - EncryptedBool creation") {
            EncryptedBool temp(context_, true);
            return temp.get_ciphertext_size();
        };

        INFO("EncryptedInt size: " << int_size << " bytes");
        INFO("EncryptedBool size: " << bool_size << " bytes");
    }

    SECTION("noise level progression") {
        EncryptedInt a(context_, 100);
        EncryptedInt b(context_, 50);

        auto initial_noise = a.get_noise_info();
        
        auto comparison_result = comparisons::greater_than(a, b);
        auto comparison_noise = comparison_result.get_noise_info();
        
        auto conditional_result = comparisons::conditional_select(comparison_result, a, b);
        auto conditional_noise = conditional_result.get_noise_info();

        INFO("Initial noise level: " << initial_noise.current_level);
        INFO("After comparison: " << comparison_noise.current_level);
        INFO("After conditional select: " << conditional_noise.current_level);

        REQUIRE(comparison_noise.current_level >= initial_noise.current_level);
        REQUIRE(conditional_noise.current_level >= comparison_noise.current_level);
    }
}

TEST_CASE_METHOD(ComparisonBenchmarkFixture, "cache performance benchmarks", "[benchmark][cache]") {
    auto& cache = ComparisonCache::instance();
    cache.clear();
    cache.set_enabled(true);
    cache.set_max_size(1000);

    EncryptedInt a(context_, 1000);
    EncryptedInt b(context_, 500);

    SECTION("cache hit vs miss performance") {
        // first comparison (cache miss)
        BENCHMARK("First comparison - cache miss") {
            cache.clear();  // ensure miss
            auto result = comparisons::greater_than(a, b);
            return result.decrypt();
        };

        // setup cache for hit scenario
        auto setup_result = comparisons::greater_than(a, b);  // populate cache
        
        BENCHMARK("Repeated comparison - potential cache hit") {
            auto result = comparisons::greater_than(a, b);
            return result.decrypt();
        };
    }

    SECTION("cache statistics") {
        cache.clear();
        cache.reset_statistics();

        // perform multiple comparisons
        for (int i = 0; i < 10; ++i) {
            auto result = comparisons::greater_than(a, b);
        }

        auto stats = cache.get_statistics();
        
        INFO("Cache hit count: " << stats.hit_count);
        INFO("Cache miss count: " << stats.miss_count);
        INFO("Cache hit rate: " << stats.hit_rate);
        INFO("Average lookup time: " << stats.average_lookup_time.count() << "ms");
    }
}