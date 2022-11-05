#include "types.hpp"

#include <fmt/format.h>

#include <charconv>

namespace phosphor::network
{

void IfAddr::invalidPfx(uint8_t pfx)
{
    throw std::invalid_argument(fmt::format("Invalid prefix {}", pfx));
}

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
    return string(phosphor::network::detail::ToStrBuf<ether_addr>{}(value));
}
std::string std::to_string(in_addr value)
{
    return string(phosphor::network::detail::ToStrBuf<in_addr>{}(value));
}
std::string std::to_string(in6_addr value)
{
    return string(phosphor::network::detail::ToStrBuf<in6_addr>{}(value));
}
std::string std::to_string(phosphor::network::InAddrAny value)
{
    phosphor::network::detail::ToStrBuf<phosphor::network::InAddrAny> tsb;
    return string(tsb(value));
}

std::string std::to_string(phosphor::network::IfAddr value)
{
    phosphor::network::detail::ToStrBuf<phosphor::network::IfAddr> tsb;
    return string(tsb(value));
}
