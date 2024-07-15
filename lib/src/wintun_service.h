#pragma once
#include <boost/asio.hpp>
#include <boost/asio/windows/object_handle.hpp>

class wintun_service
{
public:
    wintun_service(boost::asio::io_context& ioc);

    static bool initialize_wintun();
private:
    boost::asio::windows::object_handle event_;
};