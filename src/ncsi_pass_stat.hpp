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

struct getPassthruStatResponsePacket
{
    NCSIPacketHeader header;
    uint16_t response;
    uint16_t reason;
    uint64_t txPacketsRcvdOnNcsi;
    uint32_t txPacketsDropped;
    uint32_t txChannelStateErr;
    uint32_t txUndersizeErr;
    uint32_t txOversizeErr;
    uint32_t rxPacketsRcvdOnLan;
    uint32_t totalRxPacketsDropped;
    uint32_t rxChannelStateErr;
    uint32_t rxUndersizeErr;
    uint32_t rxOversizeErr;
    uint32_t checksum;
    uint8_t pad[22];

    getPassthruStatResponsePacket(std::span<const uint8_t> data);
}; // DSP0222 NCSI Spec 8.4.53

} // namespace internal

/* @brief  This function is used to get NCSI Pass through statistics (command type 0x1a).
 * @param[in] ifindex - Interface Index.
 * @param[in] package - NCSI Package.
 * @param[in] channel - Channel number with in the package.
 * @returns 0 on success and negative value for failure.
 */
size_t getNCSIPassthroughStats(int ifindex, int package, int channel);
} // namespace ncsi
} // namespace network
} // namespace phosphor
