cmake_minimum_required(VERSION 3.16.0)

project(8086_disasm)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(PROJECT_SOURCE_DIR "${CMAKE_SOURCE_DIR}/src")

add_executable(${PROJECT_NAME}
    "${PROJECT_SOURCE_DIR}/decoder.cpp"
)
