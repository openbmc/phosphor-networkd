#pragma once
#include <fmt/core.h>
#include <net/ethernet.h>
#include <netinet/in.h>

#include <algorithm>
#include <array>
#include <chrono>
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

constexpr std::size_t hash_multi() noexcept
{
    return 0;
}

template <typename T, typename... Args>
constexpr std::size_t hash_multi(const T& v, Args... args) noexcept
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

template <typename... Ts>
struct std::hash<std::tuple<Ts...>>
{
    constexpr auto operator()(const std::tuple<Ts...>& t) const noexcept
    {
        return std::apply(phosphor::network::hash_multi<Ts...>, t);
    }
};

template <>
struct std::hash<in_addr>
{
    std::size_t operator()(in_addr addr) const noexcept;
};

template <>
struct std::hash<in6_addr>
{
    std::size_t operator()(in6_addr addr) const noexcept;
};

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

template <typename T>
constexpr std::enable_if_t<!std::is_same_v<phosphor::network::InAddrAny, T>,
                           bool>
    operator==(phosphor::network::InAddrAny lhs, T rhs) noexcept
{
    return phosphor::network::detail::veq(rhs, lhs);
}

auto& operator<<(auto& os, ether_addr v)
{
    return os << phosphor::network::detail::AddrBufMaker<ether_addr>{}(v);
}

auto& operator<<(auto& os, in_addr v)
{
    return os << phosphor::network::detail::AddrBufMaker<in_addr>{}(v);
}

auto& operator<<(auto& os, in6_addr v)
{
    return os << phosphor::network::detail::AddrBufMaker<in6_addr>{}(v);
}

auto& operator<<(auto& os, phosphor::network::InAddrAny v)
{
    return os << std::visit(
               [](auto v) {
                   return phosphor::network::detail::AddrBufMaker<
                       decltype(v)>{}(v);
               },
               v);
}
