#pragma once
#include <boost/asio.hpp>
#include <boost/asio/windows/object_handle.hpp>
#include "wintun.h"

class wintun_service
{
public:
    wintun_service(boost::asio::io_context &ioc);

    static bool initialize_wintun();

    void open();

private:
    boost::asio::windows::object_handle event_;

    WINTUN_ADAPTER_HANDLE wintun_adapter_ = nullptr;
    WINTUN_SESSION_HANDLE wintun_session_ = nullptr;
};