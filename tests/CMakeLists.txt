macro(new_test TEST_NAME)
    add_executable(${TEST_NAME} ${ARGN})
    target_link_libraries(${TEST_NAME} coro)

    add_test(test_${TEST_NAME} COMMAND ${TEST_NAME})
endmacro()

new_test(hello hello_world.c)
