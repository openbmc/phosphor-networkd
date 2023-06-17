#include "types.hpp"

#include <fmt/format.h>

#include <stdplus/hash.hpp>

void phosphor::network::IfAddr::invalidPfx(uint8_t pfx)
{
    throw std::invalid_argument(fmt::format("Invalid prefix {}", pfx));
}

std::size_t std::hash<in_addr>::operator()(in_addr addr) const noexcept
{
    return stdplus::hashMulti(addr.s_addr);
}

std::size_t std::hash<in6_addr>::operator()(in6_addr addr) const noexcept
{
    return stdplus::hashMulti(addr.s6_addr32);
}

std::size_t std::hash<phosphor::network::IfAddr>::operator()(
    phosphor::network::IfAddr addr) const noexcept
{
    return stdplus::hashMulti(addr.getAddr(), addr.getPfx());
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
