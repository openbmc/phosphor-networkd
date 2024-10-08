#pragma once

#include "ncsi_util.hpp"

namespace phosphor
{
namespace network
{
namespace ncsi
{
namespace internal
{

struct DisableVlanResponsePacket
{
    NCSIPacketHeader header;
    uint16_t response;
    uint16_t reason;
    uint32_t checksum;
    uint8_t pad[22];
};

} // namespace internal

/* @brief This function will ask underlying NCSI driver
 *        to send a Disable VLAN (command type 0x0D)
 *        This function talks with the NCSI driver over
 *        netlink messages.
 * @param[in] ifindex - Interface Index.
 * @param[in] package - NCSI Package.
 * @param[in] channel - Channel number with in the package.
 * @returns 0 on success and negative value for failure.
 */
size_t disableVlan(int ifindex, int package, int channel);
} // namespace ncsi
} // namespace network
} // namespace phosphor
