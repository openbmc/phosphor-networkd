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

struct DisableMulticastFilterResponsePacket
{
    NCSIPacketHeader header;
    uint16_t response;
    uint16_t reason;
    uint32_t checksum;
    uint8_t pad[22];
};

} // namespace internal

/* @brief  This function will request underlying NCSI driver
 *         to disable multicast filtering for the channel.
 *         This function communicate with the NCSI driver over
 *         netlink messages.
 * @param[in] ifindex - Interface Index.
 * @param[in] package - NCSI Package.
 * @param[in] channel - Channel number with in the package.
 * @returns 0 on success and negative value for failure.
 */
size_t disableGlobalMulticastFilter(int ifindex, int package, int channel);
} // namespace ncsi
} // namespace network
} // namespace phosphor
