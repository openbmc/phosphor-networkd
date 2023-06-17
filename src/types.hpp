#pragma once
#include <fmt/core.h>
#include <netinet/in.h>

#include <stdplus/net/addr/ether.hpp>
#include <stdplus/numeric/endian.hpp>

#include <algorithm>
#include <array>
#include <numeric>
#include <optional>
#include <string>
#include <string_view>
#include <type_traits>
#include <unordered_map>
#include <unordered_set>
#include <variant>

constexpr bool operator==(in_addr lhs, in_addr rhs) noexcept
{
    return lhs.s_addr == rhs.s_addr;
}

constexpr bool operator==(in6_addr lhs, in6_addr rhs) noexcept
{
    return std::equal(lhs.s6_addr32, lhs.s6_addr32 + 4, rhs.s6_addr32);
}

namespace phosphor
{
namespace network
{

// Byte representations for common address types in network byte order
using InAddrAny = std::variant<in_addr, in6_addr>;
class IfAddr
{
  private:
    InAddrAny addr;
    uint8_t pfx;

    static void invalidPfx(uint8_t pfx);

  public:
    constexpr IfAddr() : addr({}), pfx(0) {}

    constexpr IfAddr(InAddrAny addr, uint8_t pfx) : addr(addr), pfx(pfx)
    {
        std::visit(
            [pfx](auto v) {
            if (sizeof(v) * 8 < pfx)
            {
                invalidPfx(pfx);
            }
            },
            addr);
    }

    constexpr auto getAddr() const
    {
        return addr;
    }

    constexpr auto getPfx() const
    {
        return pfx;
    }

    constexpr bool operator==(phosphor::network::IfAddr rhs) const noexcept
    {
        return addr == rhs.addr && pfx == rhs.pfx;
    }
};

/** @class InterfaceInfo
 *  @brief Information about interfaces from the kernel
 */
struct InterfaceInfo
{
    unsigned short type;
    unsigned idx;
    unsigned flags;
    std::optional<std::string> name = std::nullopt;
    std::optional<stdplus::EtherAddr> mac = std::nullopt;
    std::optional<unsigned> mtu = std::nullopt;
    std::optional<unsigned> parent_idx = std::nullopt;
    std::optional<std::string> kind = std::nullopt;
    std::optional<uint16_t> vlan_id = std::nullopt;

    constexpr bool operator==(const InterfaceInfo& rhs) const noexcept
    {
        return idx == rhs.idx && flags == rhs.flags && name == rhs.name &&
               mac == rhs.mac && mtu == rhs.mtu &&
               parent_idx == rhs.parent_idx && kind == rhs.kind &&
               vlan_id == rhs.vlan_id;
    }
};

/** @class AddressInfo
 *  @brief Information about a addresses from the kernel
 */
struct AddressInfo
{
    unsigned ifidx;
    IfAddr ifaddr;
    uint8_t scope;
    uint32_t flags;

    constexpr bool operator==(const AddressInfo& rhs) const noexcept
    {
        return ifidx == rhs.ifidx && ifaddr == rhs.ifaddr &&
               scope == rhs.scope && flags == rhs.flags;
    }
};

/** @class NeighborInfo
 *  @brief Information about a neighbor from the kernel
 */
struct NeighborInfo
{
    unsigned ifidx;
    uint16_t state;
    std::optional<InAddrAny> addr;
    std::optional<stdplus::EtherAddr> mac;

    constexpr bool operator==(const NeighborInfo& rhs) const noexcept
    {
        return ifidx == rhs.ifidx && state == rhs.state && addr == rhs.addr &&
               mac == rhs.mac;
    }
};

namespace detail
{
inline constexpr auto charLookup = []() {
    std::array<int8_t, 256> ret;
    std::fill(ret.begin(), ret.end(), -1);
    for (int8_t i = 0; i < 10; ++i)
    {
        ret[i + '0'] = i;
    }
    for (int8_t i = 0; i < 26; ++i)
    {
        ret[i + 'A'] = i + 10;
        ret[i + 'a'] = i + 10;
    }
    return ret;
}();
inline constexpr auto intLookup = []() {
    std::array<char, 36> ret;
    for (int8_t i = 0; i < 10; ++i)
    {
        ret[i] = i + '0';
    }
    for (int8_t i = 0; i < 26; ++i)
    {
        ret[i + 10] = i + 'a';
    }
    return ret;
}();
} // namespace detail

template <typename T, uint8_t base>
struct DecodeInt
{
    static_assert(base > 1 && base <= 36);
    static_assert(std::is_unsigned_v<T>);

    constexpr T operator()(std::string_view str) const
    {
        if (str.empty())
        {
            throw std::invalid_argument("Empty Str");
        }
        constexpr auto max = std::numeric_limits<T>::max();
        auto ret = std::accumulate(str.begin(), str.end(), T{},
                                   [&](T r, char c) {
            auto v = detail::charLookup[c];
            if (v < 0 || v >= base)
            {
                throw std::invalid_argument("Invalid numeral");
            }
            if constexpr (std::popcount(base) == 1)
            {
                constexpr auto shift = std::countr_zero(base);
                constexpr auto maxshift = max >> shift;
                if (r > maxshift)
                {
                    throw std::overflow_error("Integer Decode");
                }
                return (r << shift) | v;
            }
            else
            {
                constexpr auto maxbase = max / base;
                if (r > maxbase)
                {
                    throw std::overflow_error("Integer Decode");
                }
                r *= base;
                if (max - v < r)
                {
                    throw std::overflow_error("Integer Decode");
                }
                return r + v;
            }
        });
        return ret;
    }
};

template <typename T, uint8_t base>
struct EncodeInt
{
    static_assert(base > 1 && base <= 36);
    static_assert(std::is_unsigned_v<T>);

    static constexpr uint8_t buf_size = []() {
        T v = std::numeric_limits<T>::max();
        uint8_t i = 0;
        for (; v != 0; ++i)
        {
            v /= base;
        }
        return i;
    }();
    using buf_type = std::array<char, buf_size>;

    constexpr uint8_t reverseFill(char* buf, T v) const noexcept
    {
        uint8_t i = 0;
        do
        {
            if constexpr (std::popcount(base) == 1)
            {
                buf[i++] = detail::intLookup[v & 0xf];
                v >>= 4;
            }
            else
            {
                buf[i++] = detail::intLookup[v % base];
                v /= base;
            }
        } while (v > 0);
        return i;
    }

    constexpr char* operator()(char* buf, T v) const noexcept
    {
        uint8_t i = reverseFill(buf, v);
        std::reverse(buf, buf + i);
        return buf + i;
    }

    constexpr char* operator()(char* buf, T v, uint8_t min_width) const noexcept
    {
        uint8_t i = reverseFill(buf, v);
        auto end = buf + std::max(i, min_width);
        std::fill(buf + i, end, '0');
        std::reverse(buf, end);
        return end;
    }
};

template <typename T>
struct ToAddr
{};

template <>
struct ToAddr<in_addr>
{
    constexpr in_addr operator()(std::string_view str) const
    {
        constexpr DecodeInt<uint8_t, 10> di;
        uint32_t addr = {};
        for (size_t i = 0; i < 3; ++i)
        {
            auto loc = str.find(".");
            addr |= di(str.substr(0, loc));
            addr <<= 8;
            str.remove_prefix(loc == str.npos ? str.size() : loc + 1);
            if (str.empty())
            {
                throw std::invalid_argument("Missing addr data");
            }
        }
        addr |= di(str);
        return {stdplus::hton(addr)};
    }
};

template <>
struct ToAddr<in6_addr>
{
    constexpr in6_addr operator()(std::string_view str) const
    {
        constexpr DecodeInt<uint16_t, 16> di;
        in6_addr ret = {};
        size_t i = 0;
        while (i < 8)
        {
            auto loc = str.find(':');
            if (i == 6 && loc == str.npos)
            {
                ret.s6_addr32[3] = ToAddr<in_addr>{}(str).s_addr;
                return ret;
            }
            if (loc != 0 && !str.empty())
            {
                ret.s6_addr16[i++] = stdplus::hton(di(str.substr(0, loc)));
            }
            if (i < 8 && str.size() > loc + 1 && str[loc + 1] == ':')
            {
                str.remove_prefix(loc + 2);
                break;
            }
            else if (str.empty())
            {
                throw std::invalid_argument("IPv6 Data");
            }
            str.remove_prefix(loc == str.npos ? str.size() : loc + 1);
        }
        if (str.starts_with(':'))
        {
            throw std::invalid_argument("Extra separator");
        }
        size_t j = 7;
        if (!str.empty() && i < 6 && str.find('.') != str.npos)
        {
            auto loc = str.rfind(':');
            ret.s6_addr32[3] =
                ToAddr<in_addr>{}(str.substr(loc == str.npos ? 0 : loc + 1))
                    .s_addr;
            str.remove_suffix(loc == str.npos ? str.size() : str.size() - loc);
            j -= 2;
        }
        while (!str.empty() && j > i)
        {
            auto loc = str.rfind(':');
            ret.s6_addr16[j--] =
                stdplus::hton(di(str.substr(loc == str.npos ? 0 : loc + 1)));
            str.remove_suffix(loc == str.npos ? str.size() : str.size() - loc);
        }
        if (!str.empty())
        {
            throw std::invalid_argument("Too much data");
        }
        return ret;
    }
};

template <>
struct ToAddr<InAddrAny>
{
    constexpr InAddrAny operator()(std::string_view str) const
    {
        if (str.find(':') == str.npos)
        {
            return ToAddr<in_addr>{}(str);
        }
        return ToAddr<in6_addr>{}(str);
    }
};

template <>
struct ToAddr<IfAddr>
{
    constexpr IfAddr operator()(std::string_view str) const
    {
        auto pos = str.rfind('/');
        if (pos == str.npos)
        {
            throw std::invalid_argument("Invalid IfAddr");
        }
        return {ToAddr<InAddrAny>{}(str.substr(0, pos)),
                DecodeInt<uint8_t, 10>{}(str.substr(pos + 1))};
    }
};

template <typename T>
struct ToStr
{};

template <>
struct ToStr<char>
{
    static constexpr uint8_t buf_size = 1;
    using buf_type = std::array<char, buf_size>;

    constexpr char* operator()(char* buf, char v) const noexcept
    {
        buf[0] = v;
        return buf + 1;
    }
};

template <>
struct ToStr<in_addr>
{
    // 4 octets * 3 dec chars + 3 separators
    static constexpr uint8_t buf_size = 15;
    using buf_type = std::array<char, buf_size>;

    constexpr char* operator()(char* buf, in_addr v) const noexcept
    {
        auto n = stdplus::bswap(stdplus::ntoh(v.s_addr));
        for (size_t i = 0; i < 3; ++i)
        {
            buf = ToStr<char>{}(EncodeInt<uint8_t, 10>{}(buf, n & 0xff), '.');
            n >>= 8;
        }
        return EncodeInt<uint8_t, 10>{}(buf, n & 0xff);
    }
};

template <>
struct ToStr<in6_addr>
{
    // 8 hextets * 4 hex chars + 7 separators
    static constexpr uint8_t buf_size = 39;
    using buf_type = std::array<char, buf_size>;

    constexpr char* operator()(char* buf, in6_addr v) const noexcept
    {
        // IPv4 in IPv6 Addr
        if (v.s6_addr32[0] == 0 && v.s6_addr32[1] == 0 &&
            v.s6_addr32[2] == stdplus::hton(uint32_t(0xffff)))
        {
            constexpr auto prefix = std::string_view("::ffff:");
            return ToStr<in_addr>{}(
                std::copy(prefix.begin(), prefix.end(), buf), {v.s6_addr32[3]});
        }

        size_t skip_start = 0;
        size_t skip_size = 0;
        {
            size_t new_start = 0;
            size_t new_size = 0;
            for (size_t i = 0; i < 9; ++i)
            {
                if (i < 8 && v.s6_addr16[i] == 0)
                {
                    if (new_start + new_size == i)
                    {
                        new_size++;
                    }
                    else
                    {
                        new_start = i;
                        new_size = 1;
                    }
                }
                else if (new_start + new_size == i && new_size > skip_size)
                {
                    skip_start = new_start;
                    skip_size = new_size;
                }
            }
        }
        for (size_t i = 0; i < 8; ++i)
        {
            if (i == skip_start && skip_size > 1)
            {
                if (i == 0)
                {
                    *(buf++) = ':';
                }
                *(buf++) = ':';
                i += skip_size - 1;
                continue;
            }
            buf = EncodeInt<uint16_t, 16>{}(buf, stdplus::ntoh(v.s6_addr16[i]));
            if (i < 7)
            {
                *(buf++) = ':';
            }
        }
        return buf;
    }
};

template <>
struct ToStr<InAddrAny>
{
    // IPv6 is the bigger of the addrs
    static constexpr uint8_t buf_size = ToStr<in6_addr>::buf_size;
    using buf_type = std::array<char, buf_size>;

    constexpr char* operator()(char* buf, InAddrAny v) const noexcept
    {
        return std::visit([=](auto v) { return ToStr<decltype(v)>{}(buf, v); },
                          v);
    }
};

template <>
struct ToStr<IfAddr>
{
    // InAddrAny + sep + 3 prefix chars
    static constexpr uint8_t buf_size = ToStr<InAddrAny>::buf_size + 4;
    using buf_type = std::array<char, buf_size>;

    constexpr char* operator()(char* buf, IfAddr v) const noexcept
    {
        buf = ToStr<InAddrAny>{}(buf, v.getAddr());
        buf = ToStr<char>{}(buf, '/');
        return EncodeInt<uint8_t, 10>{}(buf, v.getPfx());
    }
};

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
struct ToStrBuf
{
  public:
    constexpr std::string_view operator()(T v) noexcept
    {
        return {buf.data(), ToStr<T>{}(buf.data(), v)};
    }

  private:
    typename ToStr<T>::buf_type buf;
};

template <typename T>
struct Format
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
        return formatter.format(ToStrBuf<T>{}(v), ctx);
    }
};
} // namespace detail
} // namespace network
} // namespace phosphor

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

template <>
struct std::hash<phosphor::network::IfAddr>
{
    std::size_t operator()(phosphor::network::IfAddr addr) const noexcept;
};

namespace fmt
{
template <>
struct formatter<in_addr> : phosphor::network::detail::Format<in_addr>
{};
template <>
struct formatter<in6_addr> : phosphor::network::detail::Format<in6_addr>
{};
template <>
struct formatter<phosphor::network::InAddrAny> :
    phosphor::network::detail::Format<phosphor::network::InAddrAny>
{};
template <>
struct formatter<phosphor::network::IfAddr> :
    phosphor::network::detail::Format<phosphor::network::IfAddr>
{};
} // namespace fmt

namespace std
{
string to_string(in_addr value);
string to_string(in6_addr value);
string to_string(phosphor::network::InAddrAny value);
string to_string(phosphor::network::IfAddr value);
} // namespace std

template <typename T>
constexpr std::enable_if_t<!std::is_same_v<phosphor::network::InAddrAny, T>,
                           bool>
    operator==(phosphor::network::InAddrAny lhs, T rhs) noexcept
{
    return phosphor::network::detail::veq(rhs, lhs);
}

auto& operator<<(auto& os, in_addr v)
{
    return os << phosphor::network::detail::ToStrBuf<in_addr>{}(v);
}

auto& operator<<(auto& os, in6_addr v)
{
    return os << phosphor::network::detail::ToStrBuf<in6_addr>{}(v);
}

auto& operator<<(auto& os, phosphor::network::InAddrAny v)
{
    phosphor::network::detail::ToStrBuf<phosphor::network::InAddrAny> tsb;
    return os << tsb(v);
}

auto& operator<<(auto& os, phosphor::network::IfAddr v)
{
    phosphor::network::detail::ToStrBuf<phosphor::network::IfAddr> tsb;
    return os << tsb(v);
}

namespace phosphor::network
{

/** @brief Contains all of the object information about the interface */
struct AllIntfInfo
{
    InterfaceInfo intf;
    std::optional<in_addr> defgw4 = std::nullopt;
    std::optional<in6_addr> defgw6 = std::nullopt;
    std::unordered_map<IfAddr, AddressInfo> addrs = {};
    std::unordered_map<InAddrAny, NeighborInfo> staticNeighs = {};
};

} // namespace phosphor::network
