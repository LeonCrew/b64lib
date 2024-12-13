cmake_minimum_required(VERSION 3.5)

file(READ "b64lib.h" B64LIB_MAIN_FILE)
string(REGEX MATCH "#define[ ]+B64LIB_VERSION_MAJOR[ ]+([0-9]+)" _ ${B64LIB_MAIN_FILE})
set(B64LIB_VERSION_MAJOR "${CMAKE_MATCH_1}")
string(REGEX MATCH "#define[ ]+B64LIB_VERSION_MINOR[ ]+([0-9]+)" _ ${B64LIB_MAIN_FILE})
set(B64LIB_VERSION_MINOR "${CMAKE_MATCH_1}")
string(REGEX MATCH "#define[ ]+B64LIB_VERSION_PATCH[ ]+([0-9]+)" _ ${B64LIB_MAIN_FILE})
set(B64LIB_VERSION_PATCH "${CMAKE_MATCH_1}")
set(B64LIB_VERSION ${B64LIB_VERSION_MAJOR}.${B64LIB_VERSION_MINOR}.${B64LIB_VERSION_PATCH})

project(b64lib
        VERSION ${B64LIB_VERSION}
        DESCRIPTION "B64Lib - simple base64/hex library"
        LANGUAGES C)

include(GNUInstallDirs)

message(STATUS "B64Lib: Version " ${B64LIB_VERSION})
set(CMAKE_C_STANDARD 99)
    
option(B64LIB_BUILD_STATIC "Build as static library" ON)
option(B64LIB_BUILD_DEMO "Build demo programs" ON)

if(B64LIB_BUILD_STATIC)
    add_library(b64lib STATIC b64lib.c b64lib.h)
    include_directories(${PROJECT_SOURCE_DIR})

    export(TARGETS b64lib
           FILE ${CMAKE_BINARY_DIR}/${CMAKE_PROJECT_NAME}Targets.cmake)

    install(TARGETS b64lib
            EXPORT ${CMAKE_PROJECT_NAME}Targets
            RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
            LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
            ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})
endif()

if(B64LIB_BUILD_DEMO)
    add_executable(b64libDemo example.c)
    add_dependencies(b64libDemo b64lib)
    target_link_libraries(b64libDemo b64lib)
endif()
