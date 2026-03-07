file(GLOB_RECURSE HDR_FILES CONFIGURE_DEPENDS *.hpp)
file(GLOB_RECURSE SRC_FILES CONFIGURE_DEPENDS *.cpp)

add_library(utils ${HDR_FILES} ${SRC_FILES})

target_compile_options(utils PRIVATE -Wall -Wextra -pedantic -Wno-unused-parameter)
target_compile_options(utils PUBLIC -Wformat-security)

target_link_libraries(utils ext)
