macro(new_test BASE_NAME)
    add_executable(${BASE_NAME}_test
        test_harness.c test_harness.h ${ARGN})
    target_link_libraries(${BASE_NAME}_test coro)

    add_test(NAME test_${BASE_NAME}_test COMMAND ${BASE_NAME}_test)
endmacro()

new_test(basic_run basic_run.c)
new_test(multi_run multi_run.c)
new_test(queue multi_queue.c)
target_compile_definitions(queue_test PUBLIC
    -DN_PRODS=1u
    -DN_CONSUM=1u
    -DN_VALS_P_PROD=100u)

new_test(multi_producer multi_queue.c)
target_compile_definitions(multi_producer_test PUBLIC
    -DN_PRODS=1000u
    -DN_CONSUM=1u
    -DN_VALS_P_PROD=100u)

new_test(multi_consumer multi_queue.c)
target_compile_definitions(multi_consumer_test PUBLIC
    -DN_PRODS=1u
    -DN_CONSUM=100u
    -DN_VALS_P_PROD=100u)

new_test(multi_consumer_producer multi_queue.c)
target_compile_definitions(multi_consumer_producer_test PUBLIC
    -DN_PRODS=100u
    -DN_CONSUM=100u
    -DN_VALS_P_PROD=10u)

new_test(queue_cleanup queue_cleanup.c)
new_test(timer timer.c)
new_test(cleanup cleanup.c)
new_test(yeild_many yeild_many.c)
new_test(custom_watcher custom_watcher.c)
