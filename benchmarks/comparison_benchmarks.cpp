/**
 * @file comparison_benchmarks.cpp
 * @brief performance benchmarks for homomorphic comparison operations
 */

#include <catch2/benchmark/catch_benchmark.hpp>
#include <catch2/catch_test_macros.hpp>
#include <chrono>
#include <random>
#include <vector>

#include "cryptmalloc/bfv_comparisons.hpp"
#include "cryptmalloc/bfv_operations.hpp"
#include "cryptmalloc/core.hpp"

namespace {

class ComparisonBenchmarkData {
   public:
    static std::vector<int64_t> random_integers(size_t count, int64_t min_val = -1000, int64_t max_val = 1000) {
        static std::random_device rd;
        static std::mt19937 gen(rd());
        std::uniform_int_distribution<int64_t> dis(min_val, max_val);

        std::vector<int64_t> data(count);
        for(auto& value : data) {
            value = dis(gen);
        }
        return data;
    }

    static std::vector<bool> random_booleans(size_t count) {
        static std::random_device rd;
        static std::mt19937 gen(rd());
        std::uniform_int_distribution<int> dis(0, 1);

        std::vector<bool> data(count);
        for(size_t i = 0; i < data.size(); ++i) {
            data[i] = dis(gen) == 1;
        }
        return data;
    }

    static std::vector<std::pair<int64_t, int64_t>> random_pairs(size_t count) {
        auto values = random_integers(count * 2);
        std::vector<std::pair<int64_t, int64_t>> pairs;
        pairs.reserve(count);
        
        for(size_t i = 0; i < count; ++i) {
            pairs.emplace_back(values[i * 2], values[i * 2 + 1]);
        }
        return pairs;
    }
};

}  // anonymous namespace

TEST_CASE("Comparison operation scaling benchmarks", "[benchmark][comparisons][scaling]") {
    // initialize context and comparisons
    auto params = cryptmalloc::BFVParameters::recommended(cryptmalloc::SecurityLevel::HEStd_128_classic, 100000, 3);
    auto context = std::make_shared<cryptmalloc::BFVContext>(params);
    auto init_result = context->initialize();
    REQUIRE(init_result.has_value());

    auto operations = std::make_shared<cryptmalloc::BFVOperations>(context);
    auto comparisons = std::make_shared<cryptmalloc::BFVComparisons>(context, operations);

    SECTION("Basic comparison operations") {
        // prepare test data
        auto test_pairs = ComparisonBenchmarkData::random_pairs(10);
        std::vector<cryptmalloc::EncryptedInt> encrypted_a, encrypted_b;
        
        for(const auto& [a, b] : test_pairs) {
            encrypted_a.emplace_back(a, context);
            encrypted_b.emplace_back(b, context);
        }

        BENCHMARK("Greater than comparison") {
            size_t idx = 0;
            for(size_t i = 0; i < encrypted_a.size(); ++i) {
                auto result = comparisons->greater_than(encrypted_a[i], encrypted_b[i]);
                if(result.has_value()) idx++;
            }
            return idx;
        };

        BENCHMARK("Less than comparison") {
            size_t idx = 0;
            for(size_t i = 0; i < encrypted_a.size(); ++i) {
                auto result = comparisons->less_than(encrypted_a[i], encrypted_b[i]);
                if(result.has_value()) idx++;
            }
            return idx;
        };

        BENCHMARK("Equality comparison") {
            size_t idx = 0;
            for(size_t i = 0; i < encrypted_a.size(); ++i) {
                auto result = comparisons->equal(encrypted_a[i], encrypted_b[i]);
                if(result.has_value()) idx++;
            }
            return idx;
        };

        BENCHMARK("Greater equal comparison") {
            size_t idx = 0;
            for(size_t i = 0; i < encrypted_a.size(); ++i) {
                auto result = comparisons->greater_equal(encrypted_a[i], encrypted_b[i]);
                if(result.has_value()) idx++;
            }
            return idx;
        };

        BENCHMARK("Less equal comparison") {
            size_t idx = 0;
            for(size_t i = 0; i < encrypted_a.size(); ++i) {
                auto result = comparisons->less_equal(encrypted_a[i], encrypted_b[i]);
                if(result.has_value()) idx++;
            }
            return idx;
        };

        BENCHMARK("Not equal comparison") {
            size_t idx = 0;
            for(size_t i = 0; i < encrypted_a.size(); ++i) {
                auto result = comparisons->not_equal(encrypted_a[i], encrypted_b[i]);
                if(result.has_value()) idx++;
            }
            return idx;
        };
    }

    SECTION("Constant comparison operations") {
        auto test_values = ComparisonBenchmarkData::random_integers(20);
        std::vector<cryptmalloc::EncryptedInt> encrypted_values;
        
        for(int64_t val : test_values) {
            encrypted_values.emplace_back(val, context);
        }

        BENCHMARK("Compare with constant (greater than)") {
            size_t count = 0;
            for(const auto& enc_val : encrypted_values) {
                auto result = comparisons->compare_constant(enc_val, 0, "gt");
                if(result.has_value()) count++;
            }
            return count;
        };

        BENCHMARK("Compare with constant (equal)") {
            size_t count = 0;
            for(const auto& enc_val : encrypted_values) {
                auto result = comparisons->compare_constant(enc_val, 42, "eq");
                if(result.has_value()) count++;
            }
            return count;
        };

        BENCHMARK("Compare with constant (less than)") {
            size_t count = 0;
            for(const auto& enc_val : encrypted_values) {
                auto result = comparisons->compare_constant(enc_val, 100, "lt");
                if(result.has_value()) count++;
            }
            return count;
        };
    }
}

TEST_CASE("Conditional selection benchmarks", "[benchmark][comparisons][conditional]") {
    auto params = cryptmalloc::BFVParameters::recommended(cryptmalloc::SecurityLevel::HEStd_128_classic, 100000, 3);
    auto context = std::make_shared<cryptmalloc::BFVContext>(params);
    context->initialize();

    auto operations = std::make_shared<cryptmalloc::BFVOperations>(context);
    auto comparisons = std::make_shared<cryptmalloc::BFVComparisons>(context, operations);

    SECTION("Conditional selection operations") {
        // prepare test data
        auto bool_values = ComparisonBenchmarkData::random_booleans(15);
        auto int_pairs = ComparisonBenchmarkData::random_pairs(15);
        
        std::vector<cryptmalloc::EncryptedBool> conditions;
        std::vector<cryptmalloc::EncryptedInt> true_values, false_values;
        
        for(size_t i = 0; i < bool_values.size(); ++i) {
            conditions.emplace_back(bool_values[i], context);
            true_values.emplace_back(int_pairs[i].first, context);
            false_values.emplace_back(int_pairs[i].second, context);
        }

        BENCHMARK("Conditional select (encrypted values)") {
            size_t count = 0;
            for(size_t i = 0; i < conditions.size(); ++i) {
                auto result = comparisons->conditional_select(conditions[i], true_values[i], false_values[i]);
                if(result.has_value()) count++;
            }
            return count;
        };

        BENCHMARK("Conditional select (constant values)") {
            size_t count = 0;
            for(const auto& condition : conditions) {
                auto result = comparisons->conditional_select_constants(condition, 100, 200);
                if(result.has_value()) count++;
            }
            return count;
        };
    }

    SECTION("Nested conditional selections") {
        // create complex conditions: select among 4 values based on 2 boolean conditions
        auto condition1 = cryptmalloc::EncryptedBool(true, context);
        auto condition2 = cryptmalloc::EncryptedBool(false, context);
        auto val1 = cryptmalloc::EncryptedInt(10, context);
        auto val2 = cryptmalloc::EncryptedInt(20, context);
        auto val3 = cryptmalloc::EncryptedInt(30, context);
        auto val4 = cryptmalloc::EncryptedInt(40, context);

        BENCHMARK("Nested conditional selection (4-way)") {
            // select val1 if both true, val2 if first true second false, etc.
            auto inner_select1 = comparisons->conditional_select(condition2, val1, val2);
            REQUIRE(inner_select1.has_value());
            
            auto inner_select2 = comparisons->conditional_select(condition2, val3, val4);
            REQUIRE(inner_select2.has_value());
            
            auto final_select = comparisons->conditional_select(condition1, inner_select1.value(), inner_select2.value());
            return final_select.has_value() ? 1 : 0;
        };
    }
}

TEST_CASE("Min/max operation benchmarks", "[benchmark][comparisons][minmax]") {
    auto params = cryptmalloc::BFVParameters::recommended(cryptmalloc::SecurityLevel::HEStd_128_classic, 100000, 3);
    auto context = std::make_shared<cryptmalloc::BFVContext>(params);
    context->initialize();

    auto operations = std::make_shared<cryptmalloc::BFVOperations>(context);
    auto comparisons = std::make_shared<cryptmalloc::BFVComparisons>(context, operations);

    SECTION("Pairwise min/max operations") {
        auto test_pairs = ComparisonBenchmarkData::random_pairs(20);
        std::vector<cryptmalloc::EncryptedInt> encrypted_a, encrypted_b;
        
        for(const auto& [a, b] : test_pairs) {
            encrypted_a.emplace_back(a, context);
            encrypted_b.emplace_back(b, context);
        }

        BENCHMARK("Pairwise minimum") {
            size_t count = 0;
            for(size_t i = 0; i < encrypted_a.size(); ++i) {
                auto result = comparisons->min(encrypted_a[i], encrypted_b[i]);
                if(result.has_value()) count++;
            }
            return count;
        };

        BENCHMARK("Pairwise maximum") {
            size_t count = 0;
            for(size_t i = 0; i < encrypted_a.size(); ++i) {
                auto result = comparisons->max(encrypted_a[i], encrypted_b[i]);
                if(result.has_value()) count++;
            }
            return count;
        };
    }

    SECTION("Vector min/max operations") {
        std::vector<size_t> vector_sizes = {5, 10, 15, 20};

        for(auto size : vector_sizes) {
            std::string min_test_name = "Vector minimum (size " + std::to_string(size) + ")";
            std::string max_test_name = "Vector maximum (size " + std::to_string(size) + ")";
            std::string argmin_test_name = "Vector argmin (size " + std::to_string(size) + ")";
            std::string argmax_test_name = "Vector argmax (size " + std::to_string(size) + ")";

            BENCHMARK(min_test_name.c_str()) {
                auto values = ComparisonBenchmarkData::random_integers(size);
                std::vector<cryptmalloc::EncryptedInt> encrypted_values;
                
                for(int64_t val : values) {
                    encrypted_values.emplace_back(val, context);
                }
                
                auto result = comparisons->min_vector(encrypted_values);
                return result.has_value() ? 1 : 0;
            };

            BENCHMARK(max_test_name.c_str()) {
                auto values = ComparisonBenchmarkData::random_integers(size);
                std::vector<cryptmalloc::EncryptedInt> encrypted_values;
                
                for(int64_t val : values) {
                    encrypted_values.emplace_back(val, context);
                }
                
                auto result = comparisons->max_vector(encrypted_values);
                return result.has_value() ? 1 : 0;
            };

            BENCHMARK(argmin_test_name.c_str()) {
                auto values = ComparisonBenchmarkData::random_integers(size);
                std::vector<cryptmalloc::EncryptedInt> encrypted_values;
                
                for(int64_t val : values) {
                    encrypted_values.emplace_back(val, context);
                }
                
                auto result = comparisons->argmin(encrypted_values);
                return result.has_value() ? 1 : 0;
            };

            BENCHMARK(argmax_test_name.c_str()) {
                auto values = ComparisonBenchmarkData::random_integers(size);
                std::vector<cryptmalloc::EncryptedInt> encrypted_values;
                
                for(int64_t val : values) {
                    encrypted_values.emplace_back(val, context);
                }
                
                auto result = comparisons->argmax(encrypted_values);
                return result.has_value() ? 1 : 0;
            };
        }
    }

    SECTION("Tournament-style operations") {
        std::vector<size_t> tournament_sizes = {8, 16, 32};

        for(auto size : tournament_sizes) {
            std::string tournament_min_name = "Tournament minimum (size " + std::to_string(size) + ")";
            std::string tournament_max_name = "Tournament maximum (size " + std::to_string(size) + ")";

            auto values = ComparisonBenchmarkData::random_integers(size);
            std::vector<cryptmalloc::EncryptedInt> encrypted_values;
            
            for(int64_t val : values) {
                encrypted_values.emplace_back(val, context);
            }

            BENCHMARK(tournament_min_name.c_str()) {
                auto result = cryptmalloc::encrypted_comparison_utils::tournament_min_max(
                    encrypted_values, false, comparisons);
                return result.has_value() ? 1 : 0;
            };

            BENCHMARK(tournament_max_name.c_str()) {
                auto result = cryptmalloc::encrypted_comparison_utils::tournament_min_max(
                    encrypted_values, true, comparisons);
                return result.has_value() ? 1 : 0;
            };
        }
    }
}

TEST_CASE("Boolean logic operation benchmarks", "[benchmark][comparisons][boolean]") {
    auto params = cryptmalloc::BFVParameters::recommended(cryptmalloc::SecurityLevel::HEStd_128_classic, 100000, 3);
    auto context = std::make_shared<cryptmalloc::BFVContext>(params);
    context->initialize();

    auto operations = std::make_shared<cryptmalloc::BFVOperations>(context);
    auto comparisons = std::make_shared<cryptmalloc::BFVComparisons>(context, operations);

    SECTION("Basic boolean operations") {
        auto bool_pairs = ComparisonBenchmarkData::random_booleans(30); // 15 pairs
        std::vector<cryptmalloc::EncryptedBool> encrypted_a, encrypted_b;
        
        for(size_t i = 0; i < bool_pairs.size(); i += 2) {
            encrypted_a.emplace_back(bool_pairs[i], context);
            if(i + 1 < bool_pairs.size()) {
                encrypted_b.emplace_back(bool_pairs[i + 1], context);
            }
        }

        // adjust sizes to match
        size_t min_size = std::min(encrypted_a.size(), encrypted_b.size());
        if (encrypted_a.size() > min_size) {
            encrypted_a.erase(encrypted_a.begin() + min_size, encrypted_a.end());
        }
        if (encrypted_b.size() > min_size) {
            encrypted_b.erase(encrypted_b.begin() + min_size, encrypted_b.end());
        }

        BENCHMARK("Logical AND operations") {
            size_t count = 0;
            for(size_t i = 0; i < encrypted_a.size(); ++i) {
                auto result = comparisons->logical_and(encrypted_a[i], encrypted_b[i]);
                if(result.has_value()) count++;
            }
            return count;
        };

        BENCHMARK("Logical OR operations") {
            size_t count = 0;
            for(size_t i = 0; i < encrypted_a.size(); ++i) {
                auto result = comparisons->logical_or(encrypted_a[i], encrypted_b[i]);
                if(result.has_value()) count++;
            }
            return count;
        };

        BENCHMARK("Logical XOR operations") {
            size_t count = 0;
            for(size_t i = 0; i < encrypted_a.size(); ++i) {
                auto result = comparisons->logical_xor(encrypted_a[i], encrypted_b[i]);
                if(result.has_value()) count++;
            }
            return count;
        };

        BENCHMARK("Logical NOT operations") {
            size_t count = 0;
            for(const auto& enc_bool : encrypted_a) {
                auto result = comparisons->logical_not(enc_bool);
                if(result.has_value()) count++;
            }
            return count;
        };
    }

    SECTION("Complex boolean expressions") {
        auto bool_values = ComparisonBenchmarkData::random_booleans(12); // 4 triplets
        std::vector<cryptmalloc::EncryptedBool> enc_a, enc_b, enc_c;
        
        for(size_t i = 0; i < bool_values.size(); i += 3) {
            enc_a.emplace_back(bool_values[i], context);
            if(i + 1 < bool_values.size()) enc_b.emplace_back(bool_values[i + 1], context);
            if(i + 2 < bool_values.size()) enc_c.emplace_back(bool_values[i + 2], context);
        }

        size_t min_size = std::min({enc_a.size(), enc_b.size(), enc_c.size()});
        if (enc_a.size() > min_size) {
            enc_a.erase(enc_a.begin() + min_size, enc_a.end());
        }
        if (enc_b.size() > min_size) {
            enc_b.erase(enc_b.begin() + min_size, enc_b.end());
        }
        if (enc_c.size() > min_size) {
            enc_c.erase(enc_c.begin() + min_size, enc_c.end());
        }

        BENCHMARK("Complex boolean expression: (A AND B) OR (NOT C)") {
            size_t count = 0;
            for(size_t i = 0; i < min_size; ++i) {
                auto and_result = comparisons->logical_and(enc_a[i], enc_b[i]);
                if(!and_result.has_value()) continue;
                
                auto not_result = comparisons->logical_not(enc_c[i]);
                if(!not_result.has_value()) continue;
                
                auto or_result = comparisons->logical_or(and_result.value(), not_result.value());
                if(or_result.has_value()) count++;
            }
            return count;
        };

        BENCHMARK("Complex boolean expression: (A OR B) AND (B XOR C)") {
            size_t count = 0;
            for(size_t i = 0; i < min_size; ++i) {
                auto or_result = comparisons->logical_or(enc_a[i], enc_b[i]);
                if(!or_result.has_value()) continue;
                
                auto xor_result = comparisons->logical_xor(enc_b[i], enc_c[i]);
                if(!xor_result.has_value()) continue;
                
                auto and_result = comparisons->logical_and(or_result.value(), xor_result.value());
                if(and_result.has_value()) count++;
            }
            return count;
        };
    }
}

TEST_CASE("Sign and absolute value benchmarks", "[benchmark][comparisons][sign]") {
    auto params = cryptmalloc::BFVParameters::recommended(cryptmalloc::SecurityLevel::HEStd_128_classic, 100000, 3);
    auto context = std::make_shared<cryptmalloc::BFVContext>(params);
    context->initialize();

    auto operations = std::make_shared<cryptmalloc::BFVOperations>(context);
    auto comparisons = std::make_shared<cryptmalloc::BFVComparisons>(context, operations);

    SECTION("Sign detection operations") {
        auto test_values = ComparisonBenchmarkData::random_integers(25, -500, 500);
        std::vector<cryptmalloc::EncryptedInt> encrypted_values;
        
        for(int64_t val : test_values) {
            encrypted_values.emplace_back(val, context);
        }

        BENCHMARK("Is positive detection") {
            size_t count = 0;
            for(const auto& enc_val : encrypted_values) {
                auto result = comparisons->is_positive(enc_val);
                if(result.has_value()) count++;
            }
            return count;
        };

        BENCHMARK("Is negative detection") {
            size_t count = 0;
            for(const auto& enc_val : encrypted_values) {
                auto result = comparisons->is_negative(enc_val);
                if(result.has_value()) count++;
            }
            return count;
        };

        BENCHMARK("Is zero detection") {
            size_t count = 0;
            for(const auto& enc_val : encrypted_values) {
                auto result = comparisons->is_zero(enc_val);
                if(result.has_value()) count++;
            }
            return count;
        };

        BENCHMARK("Sign function") {
            size_t count = 0;
            for(const auto& enc_val : encrypted_values) {
                auto result = comparisons->sign(enc_val);
                if(result.has_value()) count++;
            }
            return count;
        };

        BENCHMARK("Absolute value") {
            size_t count = 0;
            for(const auto& enc_val : encrypted_values) {
                auto result = comparisons->abs(enc_val);
                if(result.has_value()) count++;
            }
            return count;
        };
    }
}

TEST_CASE("Range and boundary operation benchmarks", "[benchmark][comparisons][range]") {
    auto params = cryptmalloc::BFVParameters::recommended(cryptmalloc::SecurityLevel::HEStd_128_classic, 100000, 3);
    auto context = std::make_shared<cryptmalloc::BFVContext>(params);
    context->initialize();

    auto operations = std::make_shared<cryptmalloc::BFVOperations>(context);
    auto comparisons = std::make_shared<cryptmalloc::BFVComparisons>(context, operations);

    SECTION("Range check operations") {
        auto test_values = ComparisonBenchmarkData::random_integers(30, -100, 200);
        std::vector<cryptmalloc::EncryptedInt> encrypted_values;
        
        for(int64_t val : test_values) {
            encrypted_values.emplace_back(val, context);
        }

        BENCHMARK("In range checks [0, 100]") {
            size_t count = 0;
            for(const auto& enc_val : encrypted_values) {
                auto result = comparisons->in_range(enc_val, 0, 100);
                if(result.has_value()) count++;
            }
            return count;
        };

        BENCHMARK("In range checks [-50, 50]") {
            size_t count = 0;
            for(const auto& enc_val : encrypted_values) {
                auto result = comparisons->in_range(enc_val, -50, 50);
                if(result.has_value()) count++;
            }
            return count;
        };

        BENCHMARK("Clamp operations [0, 100]") {
            size_t count = 0;
            for(const auto& enc_val : encrypted_values) {
                auto result = comparisons->clamp(enc_val, 0, 100);
                if(result.has_value()) count++;
            }
            return count;
        };

        BENCHMARK("Clamp operations [-25, 75]") {
            size_t count = 0;
            for(const auto& enc_val : encrypted_values) {
                auto result = comparisons->clamp(enc_val, -25, 75);
                if(result.has_value()) count++;
            }
            return count;
        };
    }
}

TEST_CASE("Cache performance benchmarks", "[benchmark][comparisons][cache]") {
    auto params = cryptmalloc::BFVParameters::recommended(cryptmalloc::SecurityLevel::HEStd_128_classic, 100000, 3);
    auto context = std::make_shared<cryptmalloc::BFVContext>(params);
    context->initialize();

    auto operations = std::make_shared<cryptmalloc::BFVOperations>(context);
    auto comparisons = std::make_shared<cryptmalloc::BFVComparisons>(context, operations);

    SECTION("Cache enabled vs disabled") {
        auto test_pairs = ComparisonBenchmarkData::random_pairs(20);
        std::vector<cryptmalloc::EncryptedInt> encrypted_a, encrypted_b;
        
        for(const auto& [a, b] : test_pairs) {
            encrypted_a.emplace_back(a, context);
            encrypted_b.emplace_back(b, context);
        }

        BENCHMARK("Comparisons without cache") {
            comparisons->configure_cache(false);
            
            size_t count = 0;
            for(size_t i = 0; i < encrypted_a.size(); ++i) {
                // perform same comparison twice
                auto result1 = comparisons->greater_than(encrypted_a[i], encrypted_b[i]);
                auto result2 = comparisons->greater_than(encrypted_a[i], encrypted_b[i]);
                if(result1.has_value() && result2.has_value()) count += 2;
            }
            return count;
        };

        BENCHMARK("Comparisons with cache enabled") {
            comparisons->configure_cache(true, 100, 300);
            
            size_t count = 0;
            for(size_t i = 0; i < encrypted_a.size(); ++i) {
                // perform same comparison twice - second should hit cache
                auto result1 = comparisons->greater_than(encrypted_a[i], encrypted_b[i]);
                auto result2 = comparisons->greater_than(encrypted_a[i], encrypted_b[i]);
                if(result1.has_value() && result2.has_value()) count += 2;
            }
            return count;
        };
    }
}

TEST_CASE("Constant-time behavior verification", "[benchmark][comparisons][constant_time]") {
    auto params = cryptmalloc::BFVParameters::recommended(cryptmalloc::SecurityLevel::HEStd_128_classic, 100000, 3);
    auto context = std::make_shared<cryptmalloc::BFVContext>(params);
    context->initialize();

    auto operations = std::make_shared<cryptmalloc::BFVOperations>(context);
    auto comparisons = std::make_shared<cryptmalloc::BFVComparisons>(context, operations);

    SECTION("Constant-time comparison timing") {
        // create different input pairs that might have different execution paths
        std::vector<std::pair<int64_t, int64_t>> test_cases = {
            {0, 0},        // equal values
            {1, 0},        // small difference
            {100, 50},     // medium difference
            {1000, -1000}, // large difference
            {-500, -500},  // equal negative values
            {42, 43}       // adjacent values
        };

        std::vector<cryptmalloc::EncryptedInt> encrypted_a, encrypted_b;
        for(const auto& [a, b] : test_cases) {
            encrypted_a.emplace_back(a, context);
            encrypted_b.emplace_back(b, context);
        }

        BENCHMARK("Constant-time greater than") {
            std::vector<double> timings;
            
            for(size_t i = 0; i < encrypted_a.size(); ++i) {
                auto start = std::chrono::high_resolution_clock::now();
                auto result = comparisons->greater_than(encrypted_a[i], encrypted_b[i], true); // constant_time = true
                auto end = std::chrono::high_resolution_clock::now();
                
                if(result.has_value()) {
                    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
                    timings.push_back(duration.count());
                }
            }
            
            // calculate coefficient of variation (should be low for constant-time)
            if(!timings.empty()) {
                double mean = std::accumulate(timings.begin(), timings.end(), 0.0) / timings.size();
                double variance = 0.0;
                for(double time : timings) {
                    variance += (time - mean) * (time - mean);
                }
                variance /= timings.size();
                double cv = std::sqrt(variance) / mean;
                
                INFO("Coefficient of variation: " << cv);
                INFO("Mean execution time: " << mean << " microseconds");
                REQUIRE(cv < 0.2); // less than 20% variation
            }
            
            return timings.size();
        };

        BENCHMARK("Variable-time greater than") {
            std::vector<double> timings;
            
            for(size_t i = 0; i < encrypted_a.size(); ++i) {
                auto start = std::chrono::high_resolution_clock::now();
                auto result = comparisons->greater_than(encrypted_a[i], encrypted_b[i], false); // constant_time = false
                auto end = std::chrono::high_resolution_clock::now();
                
                if(result.has_value()) {
                    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
                    timings.push_back(duration.count());
                }
            }
            
            // this might have more variation, but we still measure it
            if(!timings.empty()) {
                double mean = std::accumulate(timings.begin(), timings.end(), 0.0) / timings.size();
                INFO("Mean execution time (variable): " << mean << " microseconds");
            }
            
            return timings.size();
        };
    }
}

TEST_CASE("Memory usage and throughput benchmarks", "[benchmark][comparisons][throughput]") {
    auto params = cryptmalloc::BFVParameters::recommended(cryptmalloc::SecurityLevel::HEStd_128_classic, 100000, 3);
    auto context = std::make_shared<cryptmalloc::BFVContext>(params);
    context->initialize();

    auto operations = std::make_shared<cryptmalloc::BFVOperations>(context);
    auto comparisons = std::make_shared<cryptmalloc::BFVComparisons>(context, operations);

    SECTION("Comparison throughput") {
        constexpr size_t batch_size = 50;
        
        BENCHMARK("Comparison throughput (50 operations)") {
            auto test_pairs = ComparisonBenchmarkData::random_pairs(batch_size);
            size_t successful_ops = 0;
            
            for(const auto& [a, b] : test_pairs) {
                auto enc_a = cryptmalloc::EncryptedInt(a, context);
                auto enc_b = cryptmalloc::EncryptedInt(b, context);
                
                auto result = comparisons->greater_than(enc_a, enc_b);
                if(result.has_value()) {
                    successful_ops++;
                }
            }
            
            return successful_ops;
        };

        BENCHMARK("Mixed operation throughput") {
            auto test_values = ComparisonBenchmarkData::random_integers(batch_size);
            size_t successful_ops = 0;
            
            for(size_t i = 0; i < test_values.size() - 1; ++i) {
                auto enc_a = cryptmalloc::EncryptedInt(test_values[i], context);
                auto enc_b = cryptmalloc::EncryptedInt(test_values[i + 1], context);
                
                // mix of different operations
                if(i % 4 == 0) {
                    auto result = comparisons->greater_than(enc_a, enc_b);
                    if(result.has_value()) successful_ops++;
                } else if(i % 4 == 1) {
                    auto result = comparisons->equal(enc_a, enc_b);
                    if(result.has_value()) successful_ops++;
                } else if(i % 4 == 2) {
                    auto result = comparisons->min(enc_a, enc_b);
                    if(result.has_value()) successful_ops++;
                } else {
                    auto result = comparisons->abs(enc_a);
                    if(result.has_value()) successful_ops++;
                }
            }
            
            return successful_ops;
        };
    }
}