add_executable(basic_encryption_demo
    basic_encryption_demo.cpp
)

target_link_libraries(basic_encryption_demo PRIVATE cryptmalloc)

add_custom_target(run_examples
    COMMAND basic_encryption_demo
    DEPENDS basic_encryption_demo
    COMMENT "Running example applications"
)