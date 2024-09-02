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

// Get Capabilities Response Structure
// DSP0222 NCSI Spec 8.4.46

struct NCSIGetCapabilitiesInfo
{
    uint32_t capabilitiesFlags;
    uint32_t broadcastPacketFilterCapabilities;
    uint32_t multicastPacketFilterCapabilities;
    uint32_t bufferingCapabilities;
    uint32_t aenControlSupport;
    uint8_t  vlanFilterCnt;
    uint8_t  mixedFilterCnt;
    uint8_t  multicastFilterCnt;
    uint8_t  unicastFilterCnt;
    uint16_t reserved;
    uint8_t  vlanModeSupport;
    uint8_t  channelCnt;

};

struct GetCapabilitiesResponsePacket
{
    NCSIPacketHeader header;
    uint16_t response;
    uint16_t reason;
    NCSIGetCapabilitiesInfo capData;
    uint32_t checksum;

    GetCapabilitiesResponsePacket(std::span<const uint8_t> data);
};

} // namespace internal

/* @brief  This function will ask underlying NCSI driver
 *         to get the NIC Capabilities.
 * @param[in] ifindex - Interface Index.
 * @param[in] package - NCSI Package.
 * @param[in] channel - Channel number within the package.
 * @returns 0 on success and negative value for failure.
 */
size_t getCapabilitiesInfo(int ifindex, int package, int channel);

} // namespace ncsi
} // namespace network
} // namespace phosphor
