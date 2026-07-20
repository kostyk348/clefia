cmake_minimum_required(VERSION 3.10)
project(clefia C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O2 -Wall -Wextra")

# Core library
add_library(clefia_static STATIC src/clefia.c)
add_library(clefia_shared SHARED src/clefia.c)
target_include_directories(clefia_static PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_include_directories(clefia_shared PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
set_target_properties(clefia_static PROPERTIES OUTPUT_NAME clefia)
set_target_properties(clefia_shared PROPERTIES OUTPUT_NAME clefia)

# Self-test
add_executable(test_clefia tests/test_clefia.c)
target_link_libraries(test_clefia clefia_static)
add_test(NAME selftest COMMAND test_clefia)

# CLI
add_executable(clefia-cli tools/clefia-cli.c)
target_link_libraries(clefia-cli clefia_static)

enable_testing()
