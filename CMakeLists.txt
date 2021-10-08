cmake_minimum_required(VERSION 3.8)

project(noitaload LANGUAGES CXX)

add_executable(loader
    src/enc.cpp
)

target_compile_features(loader PUBLIC cxx_std_17)
