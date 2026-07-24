cmake_minimum_required(VERSION 3.12)
project(csprng_cpp CXX)

# Require C++17
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Add our CSPRNG Library
add_library(csprng
    src/chacha20_csprng.cpp
)

# Expose the include directory
target_include_directories(csprng PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

# Add our custom test runner
add_executable(chacha20_csprng_test
    tests/chacha20_csprng_test.cpp
)

# Link library and Threads dependency (required for concurrency test)
find_package(Threads REQUIRED)
target_link_libraries(chacha20_csprng_test PRIVATE csprng Threads::Threads)

# Optional AddressSanitizer and UndefinedBehaviorSanitizer configuration
option(ENABLE_SANITIZERS "Enable Address and UndefinedBehavior Sanitizers" OFF)
if(ENABLE_SANITIZERS)
    target_compile_options(csprng PUBLIC -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_compile_options(chacha20_csprng_test PUBLIC -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(chacha20_csprng_test PUBLIC -fsanitize=address,undefined)
endif()

