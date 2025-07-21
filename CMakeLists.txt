cmake_minimum_required(VERSION 3.20)
project(cryptmalloc VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -g -O0")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -O3 -DNDEBUG")

# Enable sanitizers only if explicitly requested
option(ENABLE_ASAN "Enable AddressSanitizer" OFF)
option(ENABLE_MSAN "Enable MemorySanitizer" OFF)

if(ENABLE_ASAN)
    set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -fsanitize=address")
endif()

if(ENABLE_MSAN)
    set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -fsanitize=memory")
endif()

# Find OpenFHE - try system installation first
find_package(PkgConfig QUIET)
if(PKG_CONFIG_FOUND)
    pkg_check_modules(OPENFHE QUIET openfhe)
endif()

if(NOT OPENFHE_FOUND)
    # Try to find OpenFHE using find_package
    find_package(OpenFHE QUIET PATHS /usr/local/lib/cmake/openfhe /usr/local/lib/OpenFHE)
endif()

if(NOT OpenFHE_FOUND AND NOT OPENFHE_FOUND)
    # Fallback to manual detection
    find_path(OPENFHE_INCLUDE_DIR
        NAMES openfhe/pke/openfhe.h
        PATHS /usr/local/include /usr/include
        DOC "OpenFHE include directory"
    )
    
    find_library(OPENFHE_PKE_LIB
        NAMES OPENFHEpke openfhe-pke
        PATHS /usr/local/lib /usr/lib
        DOC "OpenFHE PKE library"
    )
    
    find_library(OPENFHE_BINFHE_LIB
        NAMES OPENFHEbinfhe openfhe-binfhe
        PATHS /usr/local/lib /usr/lib
        DOC "OpenFHE BINFHE library"
    )
    
    find_library(OPENFHE_CORE_LIB
        NAMES OPENFHEcore openfhe-core
        PATHS /usr/local/lib /usr/lib
        DOC "OpenFHE CORE library"
    )
    
    if(OPENFHE_INCLUDE_DIR AND OPENFHE_PKE_LIB AND OPENFHE_BINFHE_LIB AND OPENFHE_CORE_LIB)
        set(OPENFHE_FOUND TRUE)
        set(OPENFHE_INCLUDE_DIRS ${OPENFHE_INCLUDE_DIR})
        set(OPENFHE_LIBRARIES ${OPENFHE_PKE_LIB} ${OPENFHE_BINFHE_LIB} ${OPENFHE_CORE_LIB})
        message(STATUS "Found OpenFHE manually: ${OPENFHE_INCLUDE_DIR}")
    endif()
endif()

if(NOT OpenFHE_FOUND AND NOT OPENFHE_FOUND)
    message(FATAL_ERROR "OpenFHE not found. Please install OpenFHE or set CMAKE_PREFIX_PATH to its installation directory.")
endif()

# Find optional dependencies
find_package(Catch2 3 QUIET)
if(NOT Catch2_FOUND)
    message(STATUS "Catch2 not found - tests will be disabled")
    set(BUILD_TESTING OFF)
endif()

find_package(Doxygen QUIET OPTIONAL_COMPONENTS dot)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

set(CRYPTMALLOC_SOURCES
    src/core.cpp
    src/openfhe_context.cpp
    src/bfv_context.cpp
    src/bfv_operations.cpp
    src/bfv_comparisons.cpp
    src/encrypted_types.cpp
    src/memory_pool.cpp
    src/encrypted_block.cpp
)

set(CRYPTMALLOC_HEADERS
    include/cryptmalloc/core.hpp
    include/cryptmalloc/openfhe_context.hpp
    include/cryptmalloc/allocator.hpp
    include/cryptmalloc/bfv_context.hpp
    include/cryptmalloc/bfv_operations.hpp
    include/cryptmalloc/bfv_comparisons.hpp
    include/cryptmalloc/encrypted_types.hpp
    include/cryptmalloc/memory_pool.hpp
    include/cryptmalloc/encrypted_block.hpp
)

add_library(cryptmalloc ${CRYPTMALLOC_SOURCES} ${CRYPTMALLOC_HEADERS})

# Set include directories based on what we found
if(OpenFHE_FOUND)
    target_include_directories(cryptmalloc PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
        ${OpenFHE_INCLUDE}
        ${OpenFHE_INCLUDE}/core
        ${OpenFHE_INCLUDE}/pke
        ${OpenFHE_INCLUDE}/binfhe
    )
    target_link_libraries(cryptmalloc PUBLIC
        OPENFHEpke
        OPENFHEbinfhe  
        OPENFHEcore
    )
elseif(OPENFHE_FOUND)
    target_include_directories(cryptmalloc PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
        ${OPENFHE_INCLUDE_DIRS}
    )
    target_link_libraries(cryptmalloc PUBLIC
        ${OPENFHE_LIBRARIES}
    )
endif()

add_executable(cryptmalloc_demo src/main.cpp)
target_link_libraries(cryptmalloc_demo PRIVATE cryptmalloc)

# Enable testing only if Catch2 is available
if(Catch2_FOUND)
    enable_testing()
    add_subdirectory(tests)
else()
    message(STATUS "Skipping tests - Catch2 not found")
endif()

add_subdirectory(benchmarks)
add_subdirectory(examples)

if(DOXYGEN_FOUND)
    add_subdirectory(docs)
endif()

install(TARGETS cryptmalloc
    EXPORT cryptmallocTargets
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    RUNTIME DESTINATION bin
    INCLUDES DESTINATION include
)

install(DIRECTORY include/cryptmalloc
    DESTINATION include
    FILES_MATCHING PATTERN "*.hpp"
)

install(EXPORT cryptmallocTargets
    FILE cryptmallocTargets.cmake
    NAMESPACE cryptmalloc::
    DESTINATION lib/cmake/cryptmalloc
)