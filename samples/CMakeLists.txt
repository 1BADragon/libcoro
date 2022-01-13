macro(build_sample name)
    add_executable(${name} ${ARGN})
    target_link_libraries(${name} coro)
    target_include_directories(${name} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
endmacro()

build_sample(tcp_echo_server tcp_echo_server.c)
