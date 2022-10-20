cmake_minimum_required(VERSION 3.8)

project(noitaload LANGUAGES CXX)

find_package(OpenSSL REQUIRED)

add_executable(loader
    src/enc.cpp
)

target_link_libraries(loader
    OpenSSL::Crypto
)

target_compile_features(loader PUBLIC cxx_std_17)
