#include "types.hpp"

#include <fmt/format.h>

#include <charconv>

namespace phosphor::network
{

void IfAddr::invalidPfx(uint8_t pfx)
{
    throw std::invalid_argument(fmt::format("Invalid prefix {}", pfx));
}

namespace detail
{

std::string_view AddrBufMaker<ether_addr>::operator()(ether_addr val) noexcept
{
    for (char* ptr = buf.data() + 2; ptr < buf.end(); ptr += 3)
    {
        *ptr = ':';
    }
    for (size_t i = 0; i < 6; ++i)
    {
        char* tmp = buf.data() + i * 3;
        uint8_t byte = val.ether_addr_octet[i];
        if (byte < 16)
        {
            *(tmp++) = '0';
        }
        std::to_chars(tmp, buf.end(), byte, 16);
    }
    return {buf.begin(), buf.size()};
}

std::string_view AddrBufMaker<in_addr>::operator()(in_addr val) noexcept
{
    auto v = bswap(ntoh(val.s_addr));
    char* ptr = buf.begin();
    for (size_t i = 0; i < 3; ++i)
    {
        const auto res = std::to_chars(ptr, buf.end(), v & 0xff, 10);
        *res.ptr = '.';
        ptr = res.ptr + 1;
        v >>= 8;
    }
    const auto res = std::to_chars(ptr, buf.end(), v & 0xff, 10);
    return {buf.data(), res.ptr};
}

std::string_view AddrBufMaker<in6_addr>::operator()(in6_addr val) noexcept
{
    size_t skip_start = 0;
    size_t skip_size = 0;
    {
        size_t new_start = 0;
        size_t new_size = 0;
        for (size_t i = 0; i < 9; ++i)
        {
            if (i < 8 && val.s6_addr16[i] == 0)
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
    char* ptr = buf.begin();
    for (size_t i = 0; i < 8; ++i)
    {
        if (i == skip_start && skip_size > 0)
        {
            if (i == 0)
            {
                *(ptr++) = ':';
            }
            *(ptr++) = ':';
            i += skip_size - 1;
            continue;
        }
        const auto res =
            std::to_chars(ptr, buf.end(), ntoh(val.s6_addr16[i]), 16);
        ptr = res.ptr;
        if (i < 7)
        {
            *(ptr++) = ':';
        }
    }
    return {buf.data(), ptr};
}

} // namespace detail
} // namespace phosphor::network

std::size_t std::hash<in_addr>::operator()(in_addr addr) const noexcept
{
    return std::hash<decltype(addr.s_addr)>{}(addr.s_addr);
}

std::size_t std::hash<in6_addr>::operator()(in6_addr addr) const noexcept
{
    return phosphor::network::hash_multi(addr.s6_addr32[0], addr.s6_addr32[1],
                                         addr.s6_addr32[2], addr.s6_addr32[3]);
}

std::size_t std::hash<phosphor::network::IfAddr>::operator()(
    phosphor::network::IfAddr addr) const noexcept
{
    return phosphor::network::hash_multi(addr.getAddr(), addr.getPfx());
}

std::string std::to_string(ether_addr value)
{
    return string(phosphor::network::detail::AddrBufMaker<ether_addr>{}(value));
}
std::string std::to_string(in_addr value)
{
    return string(phosphor::network::detail::AddrBufMaker<in_addr>{}(value));
}
std::string std::to_string(in6_addr value)
{
    return string(phosphor::network::detail::AddrBufMaker<in6_addr>{}(value));
}
std::string std::to_string(phosphor::network::InAddrAny value)
{
    return std::visit([](auto v) { return std::to_string(v); }, value);
}

std::string std::to_string(phosphor::network::IfAddr value)
{
    return fmt::to_string(value);
}
