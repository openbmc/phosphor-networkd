#pragma once
#include "types.hpp"

#include <cstdint>
#include <stdplus/zstring_view.hpp>
#include <string_view>

namespace phosphor::network::system
{
struct EthInfo
{
    bool autoneg;
    uint16_t speed;
};
EthInfo getEthInfo(stdplus::zstring_view ifname);

void setMTU(std::string_view ifname, unsigned mtu);

void setNICUp(std::string_view ifname, bool up);

} // namespace phosphor::network::system
