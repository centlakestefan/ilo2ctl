cmake_minimum_required(VERSION 3.16)
project(ilo2console LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Every local include is written root-relative ("crypto/md5.hpp", "ilo/telnet.hpp"),
# so the source root is the one include directory anyone needs.
find_package(Threads REQUIRED)

add_library(ilo2_core INTERFACE)
target_include_directories(ilo2_core INTERFACE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(ilo2_core INTERFACE Threads::Threads)
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
# Every test is self-asserting: it exits non-zero on mismatch, so CTest is
# meaningful and `ctest` is the whole story. The ports that were validated
# against HP's bytecode compare against frozen recordings of it in
# tests/oracle/ -- see that directory's README. Nothing here needs Java or
# HP's rc175p10.jar, which is not redistributable and is not in this repo.
# ---------------------------------------------------------------------------
enable_testing()

set(TESTS
    test_sha1
    test_hmac
    test_bigint
    test_rsa
    test_der
    test_prf
    test_record
    test_handshake
    test_client
    test_ilo_session
    test_console_core
    test_ribcl
    test_connections
    test_health
    test_random
    test_crypto
    test_dvc_bits
    test_dvc_cache
    test_dvc_decoder
    test_ilo2_input
    test_png
    test_telnet
)

foreach(t ${TESTS})
    add_executable(${t} tests/${t}.cpp)
    target_link_libraries(${t} PRIVATE ilo2_core)
    add_test(NAME ${t} COMMAND ${t} WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
endforeach()

# A few tests write intermediate streams into build/ from the source root.
file(MAKE_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/build)

# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------
add_executable(replay_dvc tools/replay_dvc.cpp)
target_link_libraries(replay_dvc PRIVATE ilo2_core)

add_executable(capture_dvc tools/capture_dvc.cpp)
target_link_libraries(capture_dvc PRIVATE ilo2_core)

add_executable(tls_get tools/tls_get.cpp)
target_link_libraries(tls_get PRIVATE ilo2_core)

add_executable(console_probe tools/console_probe.cpp)
target_link_libraries(console_probe PRIVATE ilo2_core)

add_executable(ilo_power tools/ilo_power.cpp)
target_link_libraries(ilo_power PRIVATE ilo2_core)

# ---------------------------------------------------------------------------
# GUI (SDL3 + Dear ImGui)
#
# Off by default so the test suite never needs a network fetch: everything
# above this point builds and runs from a bare clone. Turn it on with
#   cmake -S . -B build/cmake -DILO2_BUILD_GUI=ON
# and CMake will clone the pinned SDL3 and Dear ImGui tags and build them as
# part of the project. Pinning matters more than convenience here -- the whole
# point of vendoring rather than find_package is that both platforms build the
# same versions without depending on what a distro happens to ship.
# ---------------------------------------------------------------------------
option(ILO2_BUILD_GUI "Build the SDL3 console window" OFF)

if(ILO2_BUILD_GUI)
    include(FetchContent)

    set(SDL_SHARED       OFF CACHE BOOL "" FORCE)
    set(SDL_STATIC       ON  CACHE BOOL "" FORCE)
    set(SDL_TEST_LIBRARY OFF CACHE BOOL "" FORCE)
    set(SDL_TESTS        OFF CACHE BOOL "" FORCE)
    set(SDL_EXAMPLES     OFF CACHE BOOL "" FORCE)
    set(SDL_INSTALL      OFF CACHE BOOL "" FORCE)

    FetchContent_Declare(SDL3
        GIT_REPOSITORY https://github.com/libsdl-org/SDL.git
        GIT_TAG        release-3.4.14
        GIT_SHALLOW    TRUE)
    FetchContent_Declare(imgui
        GIT_REPOSITORY https://github.com/ocornut/imgui.git
        GIT_TAG        v1.92.9
        GIT_SHALLOW    TRUE)

    FetchContent_MakeAvailable(SDL3 imgui)

    # Dear ImGui ships no CMakeLists; it is meant to be compiled into the
    # consumer. The SDL_Renderer backend is enough -- the console is one
    # streaming texture, so there is nothing an OpenGL backend would add.
    add_library(imgui STATIC
        ${imgui_SOURCE_DIR}/imgui.cpp
        ${imgui_SOURCE_DIR}/imgui_draw.cpp
        ${imgui_SOURCE_DIR}/imgui_tables.cpp
        ${imgui_SOURCE_DIR}/imgui_widgets.cpp
        ${imgui_SOURCE_DIR}/backends/imgui_impl_sdl3.cpp
        ${imgui_SOURCE_DIR}/backends/imgui_impl_sdlrenderer3.cpp)
    target_include_directories(imgui PUBLIC
        ${imgui_SOURCE_DIR}
        ${imgui_SOURCE_DIR}/backends)
    target_link_libraries(imgui PUBLIC SDL3::SDL3-static)

    add_executable(ilo2_console WIN32 ui/sdl_main.cpp)
    target_link_libraries(ilo2_console PRIVATE ilo2_core imgui SDL3::SDL3-static)
    # WIN32 above suppresses the console window on Windows; SDL provides main().
endif()
