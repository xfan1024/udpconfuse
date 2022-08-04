cmake_minimum_required(VERSION 3.10)

project(udpconfuse)
set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake" ${CMAKE_MODULE_PATH})
set(CMAKE_C_FLAGS "-Werror -Wall -Wextra")
set(CMAKE_C_FLAGS_DEBUG "-g")
set(CMAKE_C_FLAGS_RELEASE "-O3")

find_package(Libev REQUIRED)
add_executable(${PROJECT_NAME} main.c confuse.c sockaddr_utils.c udp_utils.c)
target_include_directories(${PROJECT_NAME} PRIVATE ${LIBEV_INCLUDE_DIR})
target_link_libraries(${PROJECT_NAME} PRIVATE ${LIBEV_LIBRARY})
