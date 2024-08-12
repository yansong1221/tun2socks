
set(MODULE libtun2socks)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/lwip/src/include/)
add_subdirectory(lwip)

find_package(Boost REQUIRED COMPONENTS asio)
find_package(spdlog CONFIG REQUIRED)
find_package(fmt CONFIG REQUIRED)

add_library(${MODULE})


SET(HEADER_FILES
${CMAKE_CURRENT_SOURCE_DIR}/include/tun2socks/core.h
${CMAKE_CURRENT_SOURCE_DIR}/include/tun2socks/platform.h
${CMAKE_CURRENT_SOURCE_DIR}/include/tun2socks/parameter.h
${CMAKE_CURRENT_SOURCE_DIR}/include/tun2socks/proxy_policy.h
${CMAKE_CURRENT_SOURCE_DIR}/include/tun2socks/connection.h
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


${CMAKE_CURRENT_SOURCE_DIR}/src/basic_connection.hpp
${CMAKE_CURRENT_SOURCE_DIR}/src/core_impl_api.h
${CMAKE_CURRENT_SOURCE_DIR}/src/misc.hpp
${CMAKE_CURRENT_SOURCE_DIR}/src/udp_proxy.hpp
${CMAKE_CURRENT_SOURCE_DIR}/src/address_pair.hpp
${CMAKE_CURRENT_SOURCE_DIR}/src/endpoint_pair.hpp
${CMAKE_CURRENT_SOURCE_DIR}/src/tcp_proxy.hpp
${CMAKE_CURRENT_SOURCE_DIR}/src/use_awaitable.hpp
${CMAKE_CURRENT_SOURCE_DIR}/src/core.cpp
${CMAKE_CURRENT_SOURCE_DIR}/src/core_impl.hpp
${CMAKE_CURRENT_SOURCE_DIR}/src/lwip.hpp
${CMAKE_CURRENT_SOURCE_DIR}/src/pbuf.hpp
${CMAKE_CURRENT_SOURCE_DIR}/src/proxy_policy_impl.hpp
${CMAKE_CURRENT_SOURCE_DIR}/src/network_monitor.hpp
${CMAKE_CURRENT_SOURCE_DIR}/src/thread.hpp
)
if(APPLE)
	list(APPEND SRC_FILES
		${CMAKE_CURRENT_SOURCE_DIR}/src/tuntap/tun_service_mac.hpp
	)
elseif(MSVC)
	list(APPEND SRC_FILES 
		${CMAKE_CURRENT_SOURCE_DIR}/src/tuntap/wintun_service.hpp
		${CMAKE_CURRENT_SOURCE_DIR}/src/tuntap/wintun_library.hpp
		${CMAKE_CURRENT_SOURCE_DIR}/src/tuntap/wintun.h
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
	${CMAKE_CURRENT_SOURCE_DIR}/lwip/src/include/
)

target_link_libraries(${MODULE} 
PRIVATE Boost::asio
PRIVATE spdlog::spdlog fmt::fmt
PUBLIC lwipcore
)


#target_compile_definitions(${MODULE} PRIVATE _WIN32_WINDOWS)
target_compile_options( ${MODULE} PRIVATE
	"$<$<CXX_COMPILER_ID:MSVC>:/source-charset:utf-8>"
	"$<$<CXX_COMPILER_ID:MSVC>:/execution-charset:utf-8>"
)
