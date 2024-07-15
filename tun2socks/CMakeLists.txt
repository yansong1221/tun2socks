set(MODULE tun2socks)

file(GLOB_RECURSE MODULE_SOURCES *.h *.hpp *.cpp )
source_group(TREE ${CMAKE_CURRENT_SOURCE_DIR} FILES ${MODULE_SOURCES})


add_executable(${MODULE} ${MODULE_SOURCES})

target_compile_options(${MODULE} 
    PRIVATE 
    "$<$<CXX_COMPILER_ID:MSVC>:/source-charset:utf-8>" 
    "$<$<CXX_COMPILER_ID:MSVC>:/execution-charset:utf-8>"
)