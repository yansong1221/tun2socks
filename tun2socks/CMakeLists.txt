set(MODULE tun2socks)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

file(GLOB_RECURSE MODULE_SOURCES *.h *.hpp *.cpp )
source_group(TREE ${CMAKE_CURRENT_SOURCE_DIR} FILES ${MODULE_SOURCES})


add_executable(${MODULE} ${MODULE_SOURCES})

target_compile_options(${MODULE} 
    PRIVATE 
    "$<$<CXX_COMPILER_ID:MSVC>:/source-charset:utf-8>" 
    "$<$<CXX_COMPILER_ID:MSVC>:/execution-charset:utf-8>"
)

target_link_libraries(${MODULE} PRIVATE libtun2socks)

if(MSVC)
# 设置目标属性以嵌入 Manifest 文件
set_target_properties(${MODULE} PROPERTIES
    COMPILE_PDB_NAME ${MODULE}
    LINK_FLAGS "/MANIFESTUAC:\"level='requireAdministrator' uiAccess='false'\""
    #LINK_FLAGS_DEBUG "/MANIFESTUAC:\"level='requireAdministrator' uiAccess='false'\""
)
endif()