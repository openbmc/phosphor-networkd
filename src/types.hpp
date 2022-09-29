#pragma once

#include <ifaddrs.h>
#include <netinet/in.h>

#include <chrono>
#include <memory>
#include <sdeventplus/clock.hpp>
#include <sdeventplus/utility/timer.hpp>
#include <string>
#include <variant>

namespace phosphor
{
namespace network
{

using namespace std::chrono_literals;

// wait for three seconds before reloading systemd-networkd
constexpr auto reloadTimeout = 3s;

// refresh the objets after four seconds as network
// configuration takes 3-4 sec to reconfigure at most.
constexpr auto refreshTimeout = 4s;

using IntfName = std::string;

using Addr_t = ifaddrs*;

struct AddrDeleter
{
    void operator()(Addr_t ptr) const
    {
        freeifaddrs(ptr);
    }
};

using AddrPtr = std::unique_ptr<ifaddrs, AddrDeleter>;

// Byte representations for common address types in network byte order
using InAddrAny = std::variant<struct in_addr, struct in6_addr>;

using InterfaceList = std::vector<IntfName>;

using Timer = sdeventplus::utility::Timer<sdeventplus::ClockId::Monotonic>;

} // namespace network
} // namespace phosphor
