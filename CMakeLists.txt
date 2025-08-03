cmake_minimum_required(VERSION 3.20)
project(CryptMalloc VERSION 1.0.0 LANGUAGES CXX)

# c++20 standard required
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# compiler flags
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -Werror")
set(CMAKE_CXX_FLAGS_DEBUG "-g -O0")
set(CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEBUG")

# find openfhe
find_package(OpenFHE REQUIRED)

# include directories
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)
include_directories(/usr/local/include)
include_directories(/usr/local/include/openfhe)
include_directories(/usr/local/include/openfhe/core)
include_directories(/usr/local/include/openfhe/pke)
include_directories(/usr/local/include/openfhe/binfhe)

# source files
set(CRYPTMALLOC_SOURCES
    src/core.cpp
    src/openfhe_context.cpp
    src/bfv_context.cpp
    src/bfv_operations.cpp
    src/bfv_comparisons.cpp
    src/encrypted_types.cpp
)

# main library
add_library(cryptmalloc ${CRYPTMALLOC_SOURCES})
target_include_directories(cryptmalloc PUBLIC include)
target_link_libraries(cryptmalloc PUBLIC OPENFHEpke OPENFHEbinfhe OPENFHEcore)

# main executable
add_executable(cryptmalloc_demo src/main.cpp)
target_link_libraries(cryptmalloc_demo cryptmalloc)

# sanitizer options
option(ENABLE_ASAN "enable addresssanitizer" OFF)
option(ENABLE_MSAN "enable memorysanitizer" OFF)
option(ENABLE_TSAN "enable threadsanitizer" OFF)

if(ENABLE_ASAN)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=address -fno-omit-frame-pointer")
    set(CMAKE_LINKER_FLAGS "${CMAKE_LINKER_FLAGS} -fsanitize=address")
endif()

if(ENABLE_MSAN)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=memory -fno-omit-frame-pointer")
    set(CMAKE_LINKER_FLAGS "${CMAKE_LINKER_FLAGS} -fsanitize=memory")
endif()

if(ENABLE_TSAN)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=thread")
    set(CMAKE_LINKER_FLAGS "${CMAKE_LINKER_FLAGS} -fsanitize=thread")
endif()

# find catch2 for testing
find_package(Catch2 3 QUIET)
if(Catch2_FOUND)
    enable_testing()
    add_subdirectory(tests)
endif()

# examples
add_subdirectory(examples)

# doxygen documentation
find_package(Doxygen QUIET)
if(DOXYGEN_FOUND)
    set(DOXYGEN_IN ${CMAKE_CURRENT_SOURCE_DIR}/docs/Doxyfile.in)
    set(DOXYGEN_OUT ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile)
    
    configure_file(${DOXYGEN_IN} ${DOXYGEN_OUT} @ONLY)
    
    add_custom_target(docs
        COMMAND ${DOXYGEN_EXECUTABLE} ${DOXYGEN_OUT}
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
        COMMENT "generating api documentation with doxygen"
        VERBATIM
    )
endif()