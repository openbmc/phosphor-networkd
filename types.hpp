#pragma once

#include <ifaddrs.h>

#include <chrono>
#include <functional>
#include <list>
#include <map>
#include <memory>
#include <sdeventplus/clock.hpp>
#include <sdeventplus/utility/timer.hpp>
#include <set>
#include <string>
#include <vector>

namespace phosphor
{
namespace network
{

using namespace std::chrono_literals;

// wait for three seconds before restarting the networkd
constexpr auto restartTimeout = 3s;

// refresh the objets after five seconds as network
// configuration takes 3-4 sec after systemd-networkd restart.
constexpr auto refreshTimeout = restartTimeout + 7s;

namespace systemd
{
namespace config
{

constexpr auto networkFilePrefix = "00-bmc-";
constexpr auto networkFileSuffix = ".network";
constexpr auto deviceFileSuffix = ".netdev";

} // namespace config
} // namespace systemd

using IntfName = std::string;

struct AddrInfo
{
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
using InterfaceList = std::set<IntfName>;

using Timer = sdeventplus::utility::Timer<sdeventplus::ClockId::Monotonic>;

} // namespace network
} // namespace phosphor
