#pragma once

// Detect operating system
#if defined(_WIN32) || defined(_WIN64)
#define OS_WINDOWS
#elif defined(__APPLE__) || defined(__MACH__)
#define OS_MACOS
#elif defined(__linux__)
#define OS_LINUX
#elif defined(__unix__) || defined(__unix)
#define OS_UNIX
#else
#error "Unknown or unsupported operating system."
#endif

// Detect compiler
#if defined(__clang__)
#define COMPILER_CLANG
#define COMPILER_NAME "Clang"
#define COMPILER_VERSION (__clang_major__ * 10000 + __clang_minor__ * 100 + __clang_patchlevel__)
#elif defined(__GNUC__) || defined(__GNUG__)
#define COMPILER_GCC
#define COMPILER_NAME "GCC"
#define COMPILER_VERSION (__GNUC__ * 10000 + __GNUC_MINOR__ * 100 + __GNUC_PATCHLEVEL__)
#elif defined(_MSC_VER)
#define COMPILER_MSVC
#define COMPILER_NAME "MSVC"
#define COMPILER_VERSION _MSC_VER
#else
#error "Unknown or unsupported compiler."
#endif

#include "basic_tuntap.hpp"
#ifdef OS_WINDOWS
#include "wintun_service.hpp"
#elif defined(OS_MACOS)
#include "tun_service_mac.hpp"
#endif

namespace tuntap {

#ifdef OS_WINDOWS
using tuntap = basic_tuntap<wintun_service>;
#elif defined(OS_MACOS)
using tuntap = basic_tuntap<tun_service_mac>;
#endif

} // namespace tuntap