cmake_minimum_required(VERSION 3.17)
project(ueransim)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_C_STANDARD 11)

include_directories(src)

option(UERANSIM_USE_READLINE "Use GNU Readline for nr-cli interactive editing/history when available" ON)

#################### SUB DIRECTORIES ####################

add_subdirectory(src/ext)
add_subdirectory(src/utils)
add_subdirectory(src/asn/asn1c)
add_subdirectory(src/asn/rrc)
add_subdirectory(src/asn/ngap)
add_subdirectory(src/lib)
add_subdirectory(src/gnb)
add_subdirectory(src/ue)

#################### GNB EXECUTABLE ####################

add_executable(nr-gnb src/gnb.cpp)

target_link_libraries(nr-gnb pthread)

target_compile_options(nr-gnb PRIVATE -Wall -Wextra -pedantic)

target_link_libraries(nr-gnb asn-rrc)
target_link_libraries(nr-gnb asn-ngap)
target_link_libraries(nr-gnb common-lib)
target_link_libraries(nr-gnb gnb)

#################### UE EXECUTABLE ####################

add_executable(nr-ue src/ue.cpp)
target_link_libraries(nr-ue pthread)
target_compile_options(nr-ue PRIVATE -Wall -Wextra -pedantic)

target_link_libraries(nr-ue common-lib)
target_link_libraries(nr-ue ue)

###################### IF BINDER ######################
add_library(devbnd SHARED src/binder.cpp)
target_compile_options(devbnd PRIVATE -D_GNU_SOURCE -Wall -Wextra)
target_link_options(devbnd PRIVATE -nostartfiles)
target_link_libraries(devbnd dl)

#################### CLI EXECUTABLE ####################
add_executable(nr-cli src/cli.cpp)
target_link_libraries(nr-cli pthread)
target_compile_options(nr-cli PRIVATE -Wall -Wextra -pedantic)

target_link_libraries(nr-cli common-lib)

if (UERANSIM_USE_READLINE)
    find_path(READLINE_INCLUDE_DIR readline/readline.h)
    find_library(READLINE_LIBRARY readline)
    find_library(HISTORY_LIBRARY history)
    find_package(Curses QUIET)
    find_library(TINFO_LIBRARY tinfo)

    if (READLINE_INCLUDE_DIR AND READLINE_LIBRARY AND HISTORY_LIBRARY)
        target_include_directories(nr-cli PRIVATE ${READLINE_INCLUDE_DIR})
        target_link_libraries(nr-cli ${READLINE_LIBRARY})
        target_link_libraries(nr-cli ${HISTORY_LIBRARY})
        if (CURSES_FOUND)
            target_link_libraries(nr-cli ${CURSES_LIBRARIES})
        elseif (TINFO_LIBRARY)
            target_link_libraries(nr-cli ${TINFO_LIBRARY})
        endif()
        target_compile_definitions(nr-cli PRIVATE UERANSIM_HAVE_READLINE=1)
    else()
        message(WARNING "GNU Readline not found (need headers + libreadline + libhistory); nr-cli will use the basic line reader")
        target_compile_definitions(nr-cli PRIVATE UERANSIM_HAVE_READLINE=0)
    endif()
else()
    target_compile_definitions(nr-cli PRIVATE UERANSIM_HAVE_READLINE=0)
endif()
