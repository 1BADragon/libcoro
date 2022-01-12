cmake_minimum_required(VERSION 3.5)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
project(coro LANGUAGES C ASM)

option(BUILD_TESTS "Build testing code" ON)
option(MEM_SAN "Use memory sanitizer" OFF)
option(UB_SAN "Use undefined behavior sanitizer" OFF)

include(CheckSymbolExists)
include(deps/configure_ev.cmake)

set(coro_srcs
    # main module functions
    include/coro.h src/coro.c src/coro_hooks.c

    # some header only things
    src/coro_ctx.h src/macro.h src/list.h

    # Custom config for libev
    src/coro_ev.h src/coro_ev.c

    src/arch/${CMAKE_SYSTEM_PROCESSOR}/coro_swap.s
    src/arch/${CMAKE_SYSTEM_PROCESSOR}/coro_arch.h
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
target_link_libraries(coro PUBLIC m)

if (MEM_SAN)
    target_compile_options(coro PUBLIC -fsanitize=address)
    target_link_options(coro PUBLIC -fsanitize=address)
endif()

if (UB_SAN)
    target_compile_options(coro PUBLIC -fsanitize=undefined)
    target_link_options(coro PUBLIC -fsanitize=undefined)
endif()

set_source_files_properties(src/coro_ev.c
    PROPERTIES
    INCLUDE_DIRECTORIES "${PROJECT_SOURCE_DIR}/deps/libev;${CMAKE_CURRENT_BINARY_DIR}/deps/libev")

if (BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()
