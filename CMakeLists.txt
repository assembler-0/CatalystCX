cmake_minimum_required(VERSION 3.10)
project(CatalystCX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Compiler flags
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pedantic -Wall -Wextra -O2")

# Test suite executable
add_executable(cxtest Evaluate.cpp)

# Custom target to run tests
add_custom_target(test
    COMMAND cxtest
    DEPENDS cxtest
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
)

add_compile_definitions(
        WCOREDUMP
)

# Install header
install(FILES CatalystCX.hpp DESTINATION include)

find_package(Threads REQUIRED)
target_link_libraries(cxtest PRIVATE Threads::Threads)
