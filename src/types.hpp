#pragma once
#include <fmt/core.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <systemd/sd-event.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <memory>
#include <sdeventplus/clock.hpp>
#include <sdeventplus/utility/timer.hpp>
#include <string>
#include <string_view>
#include <type_traits>
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
using InAddrAny = std::variant<in_addr, in6_addr>;

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

constexpr std::size_t hash_multi()
{
    return 0;
}

template <typename T, typename... Args>
constexpr std::size_t hash_multi(const T& v, Args... args)
{
    const std::size_t seed = hash_multi(args...);
    return seed ^ (std::hash<T>{}(v) + 0x9e3779b9 + (seed << 6) + (seed >> 2));
}

namespace detail
{

template <typename T>
constexpr bool vcontains() noexcept
{
    return false;
}

template <typename T, typename V, typename... Vs>
constexpr bool vcontains() noexcept
{
    return vcontains<T, Vs...>() || std::is_same_v<T, V>;
}

template <typename T, typename... Types>
constexpr std::enable_if_t<vcontains<T, Types...>(), bool>
    veq(T t, std::variant<Types...> v) noexcept
{
    return std::visit(
        [t](auto v) {
            if constexpr (std::is_same_v<T, decltype(v)>)
            {
                return v == t;
            }
            else
            {
                return false;
            }
        },
        v);
}

template <typename T>
struct AddrBufMaker
{
};

template <>
struct AddrBufMaker<ether_addr>
{
  public:
    std::string_view operator()(ether_addr val) noexcept;

  private:
    std::array<char, /*octet*/ 2 * /*octets*/ 6 + /*seps*/ 5> buf;
};

template <>
struct AddrBufMaker<in_addr>
{
  public:
    std::string_view operator()(in_addr val) noexcept;

  private:
    std::array<char, /*octet*/ 3 * /*octets*/ 4 + /*seps*/ 3> buf;
};

template <>
struct AddrBufMaker<in6_addr>
{
  public:
    std::string_view operator()(in6_addr val) noexcept;

  private:
    std::array<char, /*hextet*/ 4 * /*hextets*/ 8 + /*seps*/ 7> buf;
};

template <typename BufMaker>
struct FormatFromBuf
{
  private:
    fmt::formatter<std::string_view> formatter;

  public:
    template <typename ParseContext>
    constexpr auto parse(ParseContext& ctx)
    {
        return ctx.begin();
    }

    template <typename FormatContext>
    auto format(auto v, FormatContext& ctx) const
    {
        return formatter.format(BufMaker{}(v), ctx);
    }
};
} // namespace detail
} // namespace network
} // namespace phosphor

namespace fmt
{
template <>
struct formatter<ether_addr>
    : phosphor::network::detail::FormatFromBuf<
          phosphor::network::detail::AddrBufMaker<ether_addr>>
{
};
template <>
struct formatter<in_addr>
    : phosphor::network::detail::FormatFromBuf<
          phosphor::network::detail::AddrBufMaker<in_addr>>
{
};
template <>
struct formatter<in6_addr>
    : phosphor::network::detail::FormatFromBuf<
          phosphor::network::detail::AddrBufMaker<in6_addr>>
{
};
template <>
struct formatter<phosphor::network::InAddrAny>
{
  private:
    fmt::formatter<std::string_view> formatter;

  public:
    template <typename ParseContext>
    constexpr auto parse(ParseContext& ctx)
    {
        return ctx.begin();
    }

    template <typename FormatContext>
    auto format(auto v, FormatContext& ctx) const
    {
        return std::visit(
            [&](auto v) {
                auto abm =
                    phosphor::network::detail::AddrBufMaker<decltype(v)>{};
                return formatter.format(abm(v), ctx);
            },
            v);
    }
};
} // namespace fmt

namespace std
{
string to_string(ether_addr value);
string to_string(in_addr value);
string to_string(in6_addr value);
string to_string(phosphor::network::InAddrAny value);
} // namespace std

constexpr bool operator==(ether_addr lhs, ether_addr rhs) noexcept
{
    return std::equal(lhs.ether_addr_octet, lhs.ether_addr_octet + 6,
                      rhs.ether_addr_octet);
}

constexpr bool operator==(in_addr lhs, in_addr rhs) noexcept
{
    return lhs.s_addr == rhs.s_addr;
}

constexpr bool operator==(in6_addr lhs, in6_addr rhs) noexcept
{
    return std::equal(lhs.s6_addr32, lhs.s6_addr32 + 4, rhs.s6_addr32);
}

constexpr bool operator==(phosphor::network::InAddrAny lhs, auto rhs) noexcept
{
    return phosphor::network::detail::veq(rhs, lhs);
}

template <typename CharT, typename Traits>
std::basic_ostream<CharT, Traits>&
    operator<<(std::basic_ostream<CharT, Traits>& os, ether_addr v)
{
    return os << phosphor::network::detail::AddrBufMaker<ether_addr>{}(v);
}

template <typename CharT, typename Traits>
std::basic_ostream<CharT, Traits>&
    operator<<(std::basic_ostream<CharT, Traits>& os, in_addr v)
{
    return os << phosphor::network::detail::AddrBufMaker<in_addr>{}(v);
}

template <typename CharT, typename Traits>
std::basic_ostream<CharT, Traits>&
    operator<<(std::basic_ostream<CharT, Traits>& os, in6_addr v)
{
    return os << phosphor::network::detail::AddrBufMaker<in6_addr>{}(v);
}

template <typename CharT, typename Traits>
std::basic_ostream<CharT, Traits>&
    operator<<(std::basic_ostream<CharT, Traits>& os,
               phosphor::network::InAddrAny v)
{
    return os << std::visit(
               [](auto v) {
                   return phosphor::network::detail::AddrBufMaker<
                       decltype(v)>{}(v);
               },
               v);
}
