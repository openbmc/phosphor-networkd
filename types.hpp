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

constexpr auto filePrefix = "00-bmc-";
constexpr auto networkFileSuffix = ".network";
constexpr auto deviceFileSuffix = ".netdev";

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


using AddrList = std::list<AddrInfo>;
using IntfAddrMap = std::map<IntfName, AddrList>;


}//namespace network
}//namespace phosphor
