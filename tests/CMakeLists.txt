macro(new_test BASE_NAME)
    add_executable(${BASE_NAME}_test ${ARGN})
    target_link_libraries(${BASE_NAME}_test coro)

    add_test(NAME test_${BASE_NAME}_test COMMAND ${BASE_NAME}_test)
endmacro()

new_test(basic_run basic_run.c)
new_test(multi_run multi_run.c)
new_test(queue queue.c)
new_test(multi_producer multi_producer.c)
new_test(multi_consumer multi_consumer.c)
new_test(queue_cleanup queue_cleanup.c)
new_test(timer timer.c)
