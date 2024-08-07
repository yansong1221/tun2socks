#pragma once

class tun2socks_impl;
class tun2socks
{
public:
    tun2socks();
    ~tun2socks();

public:
    void start();

private:
    tun2socks_impl *impl_;
};