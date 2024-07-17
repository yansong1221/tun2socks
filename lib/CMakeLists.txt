
set(MODULE libtun2socks)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(Boost REQUIRED COMPONENTS asio)
find_package(spdlog CONFIG REQUIRED)
find_package(fmt CONFIG REQUIRED)

add_library(${MODULE})


SET(HEADER_FILES
${CMAKE_CURRENT_SOURCE_DIR}/include/tun2socks/tun2socks.h
)

SET(SRC_FILES
${CMAKE_CURRENT_SOURCE_DIR}/src/tuntap.hpp
${CMAKE_CURRENT_SOURCE_DIR}/src/basic_tuntap.hpp
${CMAKE_CURRENT_SOURCE_DIR}/src/use_awaitable.hpp
${CMAKE_CURRENT_SOURCE_DIR}/src/tun2socks.cpp
${CMAKE_CURRENT_SOURCE_DIR}/src/tun_device.h
${CMAKE_CURRENT_SOURCE_DIR}/src/tun_device.cpp
)
if(APPLE)
	list(APPEND SRC_FILES
		${CMAKE_CURRENT_SOURCE_DIR}/src/tun_service_mac.hpp
	)
elseif(MSVC)
	list(APPEND SRC_FILES 
		${CMAKE_CURRENT_SOURCE_DIR}/src/wintun_service.hpp
		${CMAKE_CURRENT_SOURCE_DIR}/src/wintun_library.hpp
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
