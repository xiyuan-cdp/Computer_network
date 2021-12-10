
cmake_minimum_required(VERSION 3.19)
project(Computer_network)

set(CMAKE_CXX_STANDARD 14)
add_executable(Computer_network main.c struct/pcap.h struct/pcap.c)
target_link_libraries(Computer_network ws2_32.lib)
