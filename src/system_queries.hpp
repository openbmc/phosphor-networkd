#pragma once
#include "types.hpp"

#include <stdplus/zstring_view.hpp>

#include <cstdint>
#include <string_view>

namespace phosphor::network::system
{
struct EthInfo
{
    bool autoneg;
    uint16_t speed;
    bool fullDuplex;
};
EthInfo getEthInfo(stdplus::zstring_view ifname);

void setMTU(std::string_view ifname, unsigned mtu);

void setNICUp(std::string_view ifname, bool up);

/** @brief Sets the IP address of the interface
 *  use for interfaces explicitly marked as ignored.
 *  @param[in] ifname - Interface name
 *  @param[in] ipAddress - IP address string
 *  @param[in] prefixLength - Prefix length
 */
void setIPV4Address(std::string_view ifname, std::string_view ipAddress,
                    uint8_t prefixLength);

void deleteIntf(unsigned idx);

bool deleteLinkLocalIPv4ViaNetlink(unsigned ifidx,
                                   const stdplus::SubnetAny& ip);

} // namespace phosphor::network::system
