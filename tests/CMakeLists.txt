macro(new_test TEST_NAME)
    add_executable(${TEST_NAME} ${ARGN})
    target_link_libraries(${TEST_NAME} coro)

    add_test(NAME test_${TEST_NAME} COMMAND ${TEST_NAME})
endmacro()

new_test(basic_run basic_run.c)
new_test(multi_run multi_run.c)
new_test(queue queue.c)
new_test(multi_consumer multi_consumer.c)
