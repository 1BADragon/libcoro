cmake_minimum_required(VERSION 3.5)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
project(coro LANGUAGES C ASM)

include(CheckSymbolExists)
include(deps/configure_ev.cmake)

set(coro_srcs
    include/coro.h

    src/task.h src/task.c src/macro.h
    src/scheduler.h src/coro_ctx.h

    src/coro_ev.h src/coro_ev.c src/list.h
    src/coro.c src/scheduler.c

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

set_source_files_properties(src/coro_ev.c
    PROPERTIES
    INCLUDE_DIRECTORIES "${PROJECT_SOURCE_DIR}/deps/libev;${CMAKE_CURRENT_BINARY_DIR}/deps/libev")
