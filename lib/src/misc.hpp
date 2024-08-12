
#pragma once

#include <codecvt>
#include <string>

namespace misc {

inline static std::wstring utf8_utf16(const std::string& utf8)
{
    std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
    return converter.from_bytes(utf8);
}

inline static std::string utf16_utf8(const std::wstring& utf16)
{
    std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
    return converter.to_bytes(utf16);
}

}  // namespace misc