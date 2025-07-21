add_executable(test_main
    test_main.cpp
    test_openfhe_basic.cpp
    test_bfv_context.cpp
    test_bfv_operations.cpp
    test_bfv_comparisons.cpp
    test_encrypted_types.cpp
    test_serialization_enhanced.cpp
    test_memory_pool.cpp
    test_encrypted_block.cpp
)

target_link_libraries(test_main PRIVATE
    cryptmalloc
    Catch2::Catch2WithMain
)

target_compile_definitions(test_main PRIVATE
    CATCH_CONFIG_ENABLE_BENCHMARKING
)

add_test(NAME cryptmalloc_tests COMMAND test_main)

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    if(ENABLE_ASAN)
        target_compile_options(test_main PRIVATE -fsanitize=address)
        target_link_options(test_main PRIVATE -fsanitize=address)
    endif()
    if(ENABLE_MSAN)
        target_compile_options(test_main PRIVATE -fsanitize=memory)
        target_link_options(test_main PRIVATE -fsanitize=memory)
    endif()
endif()