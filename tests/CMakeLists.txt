# test executable
add_executable(cryptmalloc_tests
    test_main.cpp
    test_openfhe_basic.cpp
    test_bfv_context.cpp
    test_bfv_thread_safety.cpp
    test_bfv_operations.cpp
)

target_link_libraries(cryptmalloc_tests
    PRIVATE
    cryptmalloc
    Catch2::Catch2WithMain
)

# benchmark executable
add_executable(cryptmalloc_benchmarks
    benchmark_crypto_ops.cpp
    benchmark_bfv_context.cpp
    benchmark_bfv_operations.cpp
)

target_link_libraries(cryptmalloc_benchmarks
    PRIVATE
    cryptmalloc
    Catch2::Catch2WithMain
)

# register tests with ctest
include(CTest)
include(Catch)
catch_discover_tests(cryptmalloc_tests)

# register benchmarks
add_test(NAME benchmarks COMMAND cryptmalloc_benchmarks)