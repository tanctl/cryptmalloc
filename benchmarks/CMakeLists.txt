add_executable(benchmarks
    benchmark_main.cpp
    crypto_benchmarks.cpp
    allocator_benchmarks.cpp
    bfv_benchmarks.cpp
    comparison_benchmarks.cpp
)

target_link_libraries(benchmarks PRIVATE
    cryptmalloc
    Catch2::Catch2WithMain
)

target_compile_definitions(benchmarks PRIVATE
    CATCH_CONFIG_ENABLE_BENCHMARKING
)

if(CMAKE_BUILD_TYPE STREQUAL "Release")
    target_compile_options(benchmarks PRIVATE -O3 -march=native)
endif()