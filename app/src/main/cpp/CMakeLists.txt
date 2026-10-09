cmake_minimum_required(VERSION 3.22.1)
project(ant_spawn)

add_library(ant_spawn SHARED spawn_fd.c)

find_library(log-lib log)
target_link_libraries(ant_spawn ${log-lib})
