macro(new_test TEST_NAME)
    add_executable(${TEST_NAME} ${ARGN})
    target_link_libraries(${TEST_NAME} coro)

    add_test(NAME test_${TEST_NAME} COMMAND ${TEST_NAME})
endmacro()

new_test(hello hello_world.c)
new_test(multi_hello multi_hello.c)
new_test(timer timer.c)
new_test(pipe_io pipe_io.c)
