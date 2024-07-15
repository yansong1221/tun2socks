
set(MODULE libtun2socks)


find_package(Boost REQUIRED COMPONENTS asio)
find_package(spdlog CONFIG REQUIRED)
find_package(fmt CONFIG REQUIRED)

add_library(${MODULE})


target_sources(${MODULE} PRIVATE

${CMAKE_CURRENT_SOURCE_DIR}/include/tun2socks/tun2socks.h

${CMAKE_CURRENT_SOURCE_DIR}/src/wintun_service.h
${CMAKE_CURRENT_SOURCE_DIR}/src/wintun_service.cpp
${CMAKE_CURRENT_SOURCE_DIR}/src/tun2socks.cpp
${CMAKE_CURRENT_SOURCE_DIR}/src/tun_device.h
${CMAKE_CURRENT_SOURCE_DIR}/src/tun_device.cpp
)

target_include_directories(${MODULE}
	PUBLIC
	${CMAKE_CURRENT_SOURCE_DIR}/include/
)

target_link_libraries(${MODULE} 
PRIVATE Boost::asio
PRIVATE spdlog::spdlog fmt::fmt
)

if(MSVC)
	target_compile_definitions(${MODULE} PRIVATE _WIN32_WINDOWS)
	set_target_properties(${MODULE} PROPERTIES
    LINK_FLAGS "/MANIFESTUAC:\"level='requireAdministrator' uiAccess='false'\" /SUBSYSTEM:WINDOWS"
)

endif(MSVC)
