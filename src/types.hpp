#pragma once

#include <ifaddrs.h>
#include <netinet/in.h>
#include <systemd/sd-event.h>

#include <chrono>
#include <memory>
#include <sdeventplus/clock.hpp>
#include <sdeventplus/utility/timer.hpp>
#include <string>
#include <unordered_map>
#include <unordered_set>
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

using Addr_t = ifaddrs*;

struct AddrDeleter
{
    void operator()(Addr_t ptr) const
    {
        freeifaddrs(ptr);
    }
};

using AddrPtr = std::unique_ptr<ifaddrs, AddrDeleter>;

/* Need a custom deleter for freeing up sd_event */
struct EventDeleter
{
    void operator()(sd_event* event) const
    {
        sd_event_unref(event);
    }
};
using EventPtr = std::unique_ptr<sd_event, EventDeleter>;

// Byte representations for common address types in network byte order
using InAddrAny = std::variant<struct in_addr, struct in6_addr>;

using Timer = sdeventplus::utility::Timer<sdeventplus::ClockId::Monotonic>;

struct string_hash : public std::hash<std::string_view>
{
    using is_transparent = void;
};
template <typename V>
using string_umap =
    std::unordered_map<std::string, V, string_hash, std::equal_to<>>;
using string_uset =
    std::unordered_set<std::string, string_hash, std::equal_to<>>;

} // namespace network
} // namespace phosphor
