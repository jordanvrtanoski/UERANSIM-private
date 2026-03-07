file(GLOB_RECURSE HDR_FILES CONFIGURE_DEPENDS *.hpp)
file(GLOB_RECURSE SRC_FILES CONFIGURE_DEPENDS *.cpp)

add_library(gnb ${HDR_FILES} ${SRC_FILES})

target_compile_options(gnb PRIVATE -Wall -Wextra -pedantic -Wno-unused-parameter)

target_link_libraries(gnb asn-ngap)
target_link_libraries(gnb asn-rrc)
target_link_libraries(gnb common-lib)
