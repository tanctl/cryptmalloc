# basic encryption demo
add_executable(basic_encryption_demo
    basic_encryption_demo.cpp
)

target_link_libraries(basic_encryption_demo
    PRIVATE
    cryptmalloc
)