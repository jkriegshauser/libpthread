cmake_minimum_required(VERSION 3.0)

project(pthread)

add_compile_definitions(MAKE_STATIC)

add_library(pthread STATIC src/pthread.c)

include_directories(
    include
)

project(Test)

link_libraries(pthread)
target_link_libraries(pthread)

add_executable(Test src/tests/main.cpp)

include_directories(
    include
    doctest
)
