cmake_minimum_required(VERSION 3.5)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
project(coro LANGUAGES C)

add_subdirectory(deps)

set(coro_srcs
    include/coro.h
    include/coro/task.h include/coro/scheduler.h

    src/coro.c src/scheduler.c)

add_library(coro ${coro_srcs})
target_compile_options(coro PRIVATE -Wall -Wextra)
target_include_directories(coro
    PUBLIC include
    PRIVATE src
    )
#target_link_libraries(coro PUBLIC coro::ev)
