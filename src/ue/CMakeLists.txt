file(GLOB_RECURSE HDR_FILES CONFIGURE_DEPENDS *.hpp)
file(GLOB_RECURSE SRC_FILES CONFIGURE_DEPENDS *.cpp)

add_library(ue ${HDR_FILES} ${SRC_FILES})

target_compile_options(ue PRIVATE -Wall -Wextra -pedantic -Wno-unused-parameter)
target_link_libraries(ue common-lib)
