
set(MODULE libtun2socks)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(Boost REQUIRED COMPONENTS asio)
find_package(spdlog CONFIG REQUIRED)
find_package(fmt CONFIG REQUIRED)

add_library(${MODULE})


SET(HEADER_FILES
${CMAKE_CURRENT_SOURCE_DIR}/include/tun2socks/tun2socks.h
)

SET(SRC_FILES

${CMAKE_CURRENT_SOURCE_DIR}/src/socks_client/socks_client.hpp
${CMAKE_CURRENT_SOURCE_DIR}/src/socks_client/socks_enums.hpp
${CMAKE_CURRENT_SOURCE_DIR}/src/socks_client/socks_error_code.hpp
${CMAKE_CURRENT_SOURCE_DIR}/src/socks_client/socks_io.hpp

${CMAKE_CURRENT_SOURCE_DIR}/src/tuntap/tuntap.hpp
${CMAKE_CURRENT_SOURCE_DIR}/src/tuntap/basic_tuntap.hpp

${CMAKE_CURRENT_SOURCE_DIR}/src/route/route.hpp

${CMAKE_CURRENT_SOURCE_DIR}/src/process_info/process_info.hpp


${CMAKE_CURRENT_SOURCE_DIR}/src/buffer.hpp
${CMAKE_CURRENT_SOURCE_DIR}/src/interface.hpp
${CMAKE_CURRENT_SOURCE_DIR}/src/basic_proxy.hpp
${CMAKE_CURRENT_SOURCE_DIR}/src/misc.hpp
${CMAKE_CURRENT_SOURCE_DIR}/src/platform.hpp
${CMAKE_CURRENT_SOURCE_DIR}/src/udp_proxy.hpp
${CMAKE_CURRENT_SOURCE_DIR}/src/address_pair.hpp
${CMAKE_CURRENT_SOURCE_DIR}/src/endpoint_pair.hpp
${CMAKE_CURRENT_SOURCE_DIR}/src/checksum.hpp
${CMAKE_CURRENT_SOURCE_DIR}/src/ip_packet.hpp
${CMAKE_CURRENT_SOURCE_DIR}/src/udp_packet.hpp
${CMAKE_CURRENT_SOURCE_DIR}/src/tcp_packet.hpp
${CMAKE_CURRENT_SOURCE_DIR}/src/tcp_proxy.hpp
${CMAKE_CURRENT_SOURCE_DIR}/src/ip_layer_stack.hpp
${CMAKE_CURRENT_SOURCE_DIR}/src/use_awaitable.hpp
${CMAKE_CURRENT_SOURCE_DIR}/src/tun2socks.cpp
${CMAKE_CURRENT_SOURCE_DIR}/src/tun_device.h
${CMAKE_CURRENT_SOURCE_DIR}/src/tun_device.cpp
)
if(APPLE)
	list(APPEND SRC_FILES
		${CMAKE_CURRENT_SOURCE_DIR}/src/tuntap/tun_service_mac.hpp
	)
elseif(MSVC)
	list(APPEND SRC_FILES 
		${CMAKE_CURRENT_SOURCE_DIR}/src/tuntap/wintun_service.hpp
		${CMAKE_CURRENT_SOURCE_DIR}/src/tuntap/wintun_library.hpp
		${CMAKE_CURRENT_SOURCE_DIR}/src/route/route_win32.hpp
		${CMAKE_CURRENT_SOURCE_DIR}/src/process_info/process_info_win32.hpp
	)
endif()

source_group(TREE ${CMAKE_CURRENT_SOURCE_DIR} FILES ${HEADER_FILES} ${SRC_FILES})

target_sources(${MODULE} PRIVATE
${HEADER_FILES}
${SRC_FILES}
)

target_include_directories(${MODULE}
	PUBLIC
	${CMAKE_CURRENT_SOURCE_DIR}/include/
	PRIVATE
	${CMAKE_CURRENT_SOURCE_DIR}/src/
)

target_link_libraries(${MODULE} 
PRIVATE Boost::asio
PRIVATE spdlog::spdlog fmt::fmt
)

if(MSVC)
	#target_compile_definitions(${MODULE} PRIVATE _WIN32_WINDOWS)
	target_compile_options( ${MODULE} PRIVATE
		"$<$<CXX_COMPILER_ID:MSVC>:/source-charset:utf-8>"
		"$<$<CXX_COMPILER_ID:MSVC>:/execution-charset:utf-8>"
	)
	set_target_properties(${MODULE} PROPERTIES
    LINK_FLAGS "/MANIFESTUAC:\"level='requireAdministrator' uiAccess='false'\" /SUBSYSTEM:WINDOWS"
)

endif(MSVC)
