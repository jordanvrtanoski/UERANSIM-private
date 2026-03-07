file(GLOB_RECURSE H_FILES CONFIGURE_DEPENDS *.h)
file(GLOB_RECURSE C_FILES CONFIGURE_DEPENDS *.c)
file(GLOB_RECURSE HDR_FILES CONFIGURE_DEPENDS *.hpp)
file(GLOB_RECURSE SRC_FILES CONFIGURE_DEPENDS *.cpp)

add_library(ext ${H_FILES} ${C_FILES} ${HDR_FILES} ${SRC_FILES})

target_compile_options(ext PRIVATE -Wall -Wextra -pedantic -Wno-unused-parameter)
target_include_directories(ext PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
