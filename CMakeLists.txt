cmake_minimum_required(VERSION 3.5)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
project(coro LANGUAGES C ASM)

option(BUILD_TESTS "Build testing code" ON)
option(BUILD_SAMPLES "Build sample code" ON)
option(MEM_SAN "Use memory sanitizer" OFF)
option(UB_SAN "Use undefined behavior sanitizer" OFF)
option(COVERAGE "Use coverage tools" OFF)
option(GCC_ANALYZE "Use GCC's static analyzer" OFF)

option(ENABLE_LIBEV_BACKEND "Compile in libev backend and link" ON)

include(CheckSymbolExists)
include(deps/configure_ev.cmake)

set(coro_srcs
    # main module functions
    include/coro.h src/coro.c src/coro_hooks.c

    # some header only things
    src/coro_ctx.h src/macro.h src/list.h
    src/backends/coro_backend.h
    src/backends/coro_backend.c

    # Custom context swap code for an arch
    src/arch/${CMAKE_SYSTEM_PROCESSOR}/coro_swap.s
    src/arch/${CMAKE_SYSTEM_PROCESSOR}/coro_arch.h

    # Other things cmake knows to ignore
    README.md
    )

add_library(coro ${coro_srcs})
target_compile_options(coro PRIVATE -Wall -Wextra)
target_include_directories(coro
    PUBLIC
        include
    PRIVATE
        src
        ${PROJECT_SOURCE_DIR}
        src/arch/${CMAKE_SYSTEM_PROCESSOR}
    )

if (ENABLE_LIBEV_BACKEND)
    target_sources(coro PRIVATE
        # Custom config for libev
        src/backends/coro_backend_ev.h
        src/backends/coro_backend_ev.c)
    target_link_libraries(coro PUBLIC ev m)
    target_compile_definitions(coro PRIVATE CORO_LIBEV_BACKEND_ENABLED=1)
endif()

if (MEM_SAN)
    target_compile_options(coro PUBLIC -fsanitize=address)
    target_link_options(coro PUBLIC -fsanitize=address)
endif()

if (UB_SAN)
    target_compile_options(coro PUBLIC -fsanitize=undefined)
    target_link_options(coro PUBLIC -fsanitize=undefined)
endif()

if (COVERAGE)
    target_compile_options(coro PUBLIC --coverage)
    target_link_options(coro PUBLIC --coverage)
endif()

if (GCC_ANALYZE)
    target_compile_options(coro PUBLIC -fanalyzer)
endif()

set_source_files_properties(src/coro_ev.c
    PROPERTIES
    INCLUDE_DIRECTORIES "${PROJECT_SOURCE_DIR}/deps/libev;${CMAKE_CURRENT_BINARY_DIR}/deps/libev")

if (BUILD_SAMPLES)
    add_subdirectory(samples)
endif()

if (BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()
