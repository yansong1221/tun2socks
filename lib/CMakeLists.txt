
set(MODULE libtun2socks)


find_package(Boost REQUIRED COMPONENTS asio dll)
find_package(spdlog CONFIG REQUIRED)

add_library(${MODULE})


target_sources(${MODULE} PRIVATE
${CMAKE_CURRENT_SOURCE_DIR}/src/wintun_service.h
${CMAKE_CURRENT_SOURCE_DIR}/src/wintun_service.cpp
)

target_include_directories(${MODULE}
	PUBLIC
	${CMAKE_CURRENT_SOURCE_DIR}/include/
)

target_link_libraries(${MODULE} 
PRIVATE Boost::asio Boost::dll
PRIVATE spdlog::spdlog
)