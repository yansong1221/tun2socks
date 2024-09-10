set(MODULE tun2socks)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(${MODULE} argparse.hpp main.cpp)

target_link_libraries(${MODULE} PRIVATE libtun2socks)


if(MSVC)
    set_target_properties(${MODULE} PROPERTIES
        COMPILE_PDB_NAME ${MODULE}
        LINK_FLAGS "/MANIFESTUAC:\"level='requireAdministrator' uiAccess='false'\""
    )
endif(MSVC)