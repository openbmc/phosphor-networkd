#pragma once

#include <ifaddrs.h>

#include <list>
#include <string>
#include <vector>
#include <map>
#include <memory>

namespace phosphor
{
namespace network
{
namespace systemd
{
namespace config
{

constexpr auto networkFilePrefix = "00-bmc-";
constexpr auto networkFileSuffix = ".network";
constexpr auto deviceFileSuffix = ".netdev";

}// namespace config
}// namespace systemd

using IntfName = std::string;

struct AddrInfo {
    uint8_t addrType;
    std::string ipaddress;
    uint16_t prefix;
};

using Addr_t = ifaddrs*;

struct AddrDeleter
{
    void operator()(Addr_t ptr) const
    {
        freeifaddrs(ptr);
    }
};

using AddrPtr = std::unique_ptr<ifaddrs, AddrDeleter>;


template<typename T>
using UniquePtr = std::unique_ptr<T, std::function<void(T*)>>;

using AddrList = std::list<AddrInfo>;
using IntfAddrMap = std::map<IntfName, AddrList>;


}//namespace network
}//namespace phosphor
