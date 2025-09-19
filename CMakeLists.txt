cmake_minimum_required(VERSION 3.10)
project(CatalystCX VERSION 0.0.1)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O2 -g0")

add_executable(CatalystCX
        CatalystCX.cpp
)

# --- Run Target ---
add_custom_target(run
    COMMAND ${CMAKE_COMMAND} -E env "PATH=$ENV{PATH}" ./CatalystCX
    DEPENDS CatalystCX
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
)

# --- Install Target ---
include(GNUInstallDirs)

install(FILES CatalystCX.hpp
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)