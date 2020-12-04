cmake_minimum_required(VERSION 3.0 FATAL_ERROR)

project(securefsname)
if (POLICY CMP0048)
  cmake_policy(SET CMP0048 NEW)
endif()

set (CMAKE_FIND_FRAMEWORK NEVER)

execute_process (
    COMMAND bash -c "uname -m"
    OUTPUT_VARIABLE architecture
)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake-modules/")

if (UNIX)
    add_compile_options(-Wall -Wextra -Wno-unknown-pragmas)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} --std=gnu++11")

    if (CMAKE_CXX_COMPILER_ID MATCHES "Clang")
        add_compile_options(-Wthread-safety -Wthread-safety-negative)
    endif()

    add_compile_options(-pthread)
    link_libraries(-pthread)
    link_libraries(-lbsd)
    link_libraries(${CMAKE_DL_LIBS})
else ()
    add_definitions(-DNOMINMAX=1)
    add_definitions(-D_CRT_SECURE_NO_WARNINGS=1)
    add_definitions(-D__STDC__=1)
    if (${CMAKE_SIZEOF_VOID_P} EQUAL 8)
        set(ARCH x64)
    else ()
        set(ARCH x86)
    endif ()
    link_libraries(delayimp.lib)
    add_compile_options(/MP)
endif ()

add_definitions(-D_REENTRANT -D_FILE_OFFSET_BITS=64 -DFUSE_USE_VERSION=28 -DUTF8PROC_EXPORTS=1)

if (NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug)
endif ()

include_directories(sources)
set(EXTERNAL_DIR external)
include_directories(${EXTERNAL_DIR})

set(CRYPTOPP_DIR ${EXTERNAL_DIR}/cryptopp)
add_subdirectory(${CRYPTOPP_DIR})
link_libraries(cryptopp-static)

file(GLOB SOURCES sources/*.cpp sources/*.h ${EXTERNAL_DIR}/*.h ${EXTERNAL_DIR}/*.hpp ${EXTERNAL_DIR}/*.cpp ${CMAKE_BINARY_DIR}/git-version.cpp ${EXTERNAL_DIR}/utf8proc/utf8proc.h ${EXTERNAL_DIR}/utf8proc/utf8proc.c)
add_library(securefs-static STATIC ${SOURCES})
link_libraries(securefs-static)

add_executable(securefsname sources/main.cpp)

include(CheckCXXSourceRuns)
CHECK_CXX_SOURCE_RUNS("int main() { thread_local int i = 0; return i; }" HAS_THREAD_LOCAL)

CHECK_CXX_SOURCE_RUNS("
#include <time.h>

int main() {
    timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return 0;
}
" HAS_CLOCK_GETTIME)

CHECK_CXX_SOURCE_RUNS("
#include <unistd.h>
#include <sys/stat.h>

int main() {
    futimens(-1, nullptr);
    return 0;
}
" HAS_FUTIMENS)

CHECK_CXX_SOURCE_RUNS("
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>

int main() {
    utimensat(-1, nullptr, nullptr, 0);
    return 0;
}
" HAS_UTIMENSAT)

configure_file(sources/securefsname_config.in securefsname_config.h)
include_directories(${CMAKE_CURRENT_BINARY_DIR})

