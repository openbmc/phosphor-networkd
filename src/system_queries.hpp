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

/** @brief Flush ALL existing IPv4 addresses from an interface.
 *         Equivalent to "ip -4 addr flush dev <ifname>".
 *         Call before setIPV4Address() to ensure a clean slate.
 *
 *  @param[in] ifidx - Interface index (from if_nametoindex)
 *  @return true if all deletions succeeded (no addresses = success)
 */
bool deleteIPv4(unsigned ifidx);

/** @brief Flush ALL existing IPv6 addresses from an interface.
 *         Equivalent to "ip -6 addr flush dev <ifname>".
 *         Call before setIPV6Address() to ensure a clean slate.
 *
 *  @param[in] ifidx - Interface index (from if_nametoindex)
 *  @return true if all deletions succeeded (no addresses = success)
 */
bool deleteIPv6(unsigned ifidx);

/** @brief Set an IPv4 address on an ignored interface via RTM_NEWADDR.
 *         Caller flushes stale addresses first via deleteIPv4() if needed.
 *
 *  @param[in] ifname       - Interface name (e.g. "eth2")
 *  @param[in] ipAddress    - IPv4 address string (e.g. "9.6.1.100")
 *  @param[in] prefixLength - CIDR prefix length (1-31)
 *
 *  @throws std::system_error     if interface doesn't exist
 *  @throws std::invalid_argument if address or prefix is invalid
 *  @throws std::runtime_error    if netlink operation fails
 */
void setIPV4Address(std::string_view ifname, std::string_view ipAddress,
                    uint8_t prefixLength);

/** @brief Set an IPv6 address on an ignored interface via RTM_NEWADDR.
 *         Caller flushes stale addresses first via deleteIPv6() if needed.
 *
 *  @param[in] ifname       - Interface name (e.g. "eth2")
 *  @param[in] ipAddress    - IPv6 address string (e.g. "2001:db8::1")
 *  @param[in] prefixLength - CIDR prefix length (1-128)
 *
 *  @throws std::system_error     if interface doesn't exist
 *  @throws std::invalid_argument if address or prefix is invalid
 *  @throws std::runtime_error    if netlink operation fails
 */
void setIPV6Address(std::string_view ifname, std::string_view ipAddress,
                    uint8_t prefixLength);

void deleteIntf(unsigned idx);

bool deleteLinkLocalIPv4ViaNetlink(unsigned ifidx,
                                   const stdplus::SubnetAny& ip);

} // namespace phosphor::network::system
