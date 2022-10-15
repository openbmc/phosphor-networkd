#pragma once
#include "types.hpp"

#include <netinet/ether.h>

#include <cstdint>
#include <optional>
#include <stdplus/zstring.hpp>
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

bool intfIsRunning(std::string_view ifname);

unsigned intfIndex(stdplus::const_zstring ifname);

std::optional<ether_addr> getMAC(stdplus::zstring_view ifname);

std::optional<unsigned> getMTU(stdplus::zstring_view ifname);

void setMTU(std::string_view ifname, unsigned mtu);

void setNICUp(std::string_view ifname, bool up);

/** @brief Get all the interfaces from the system.
 *  @returns list of interface names.
 */
string_uset getInterfaces();

} // namespace phosphor::network::system
