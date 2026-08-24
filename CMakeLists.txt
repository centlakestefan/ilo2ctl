cmake_minimum_required(VERSION 3.16)
project(ilo2console LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Every local include is written root-relative ("crypto/md5.hpp", "ilo/telnet.hpp"),
# so the source root is the one include directory anyone needs.
add_library(ilo2_core INTERFACE)
target_include_directories(ilo2_core INTERFACE ${CMAKE_CURRENT_SOURCE_DIR})
if(WIN32)
    # ws2_32: sockets (ilo/telnet.hpp).  bcrypt: BCryptGenRandom (crypto/random.hpp).
    target_link_libraries(ilo2_core INTERFACE ws2_32 bcrypt)
endif()

if(MSVC)
    target_compile_options(ilo2_core INTERFACE /W4)
else()
    target_compile_options(ilo2_core INTERFACE -Wall -Wextra)
endif()

# ---------------------------------------------------------------------------
# Tests
#
# Two kinds live side by side, deliberately:
#   * self-asserting  -- known-answer vectors / reference oracles, exit non-zero
#                        on mismatch, so CTest is meaningful.
#   * oracle-diff     -- print a trace to be diffed against the Java probe in
#                        tests/*Probe.java (needs HP's rc175p10.jar, which is not
#                        redistributable). Registered anyway: running them proves
#                        the ports still compile and execute.
# ---------------------------------------------------------------------------
enable_testing()

set(SELF_ASSERTING_TESTS
    test_sha1
    test_hmac
    test_bigint
    test_rsa
    test_random
    test_crypto
)
set(ORACLE_DIFF_TESTS
    test_dvc_bits
    test_dvc_cache
    test_dvc_decoder
    test_ilo2_input
    test_png
    test_telnet
)

foreach(t ${SELF_ASSERTING_TESTS} ${ORACLE_DIFF_TESTS})
    add_executable(${t} tests/${t}.cpp)
    target_link_libraries(${t} PRIVATE ilo2_core)
    add_test(NAME ${t} COMMAND ${t} WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
endforeach()

# Several oracle-diff tests write traces into build/ from the source root.
file(MAKE_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/build)

# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------
add_executable(replay_dvc tools/replay_dvc.cpp)
target_link_libraries(replay_dvc PRIVATE ilo2_core)

add_executable(capture_dvc tools/capture_dvc.cpp)
target_link_libraries(capture_dvc PRIVATE ilo2_core)
