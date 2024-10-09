#pragma once

#include "ncsi_util.hpp"

#include <cstdint>
#include <ostream>

namespace phosphor
{
namespace network
{
namespace ncsi
{
namespace internal
{

struct NCSIControllerPacketStatsResponse
{
    NCSIPacketHeader header;
    uint16_t response;
    uint16_t reason;
    uint32_t countersClearedFromLastReadMSB;
    uint32_t countersClearedFromLastReadLSB;
    uint64_t totalBytesRcvd;
    uint64_t totalBytesTx;
    uint64_t totalUnicastPktsRcvd;
    uint64_t totalMulticastPktsRcvd;
    uint64_t totalBroadcastPktsRcvd;
    uint64_t totalUnicastPktsTx;
    uint64_t totalMulticastPktsTx;
    uint64_t totalBroadcastPktsTx;
    uint32_t fcsReceiveErrs;
    uint32_t alignmentErrs;
    uint32_t falseCarrierDetections;
    uint32_t runtPktsRcvd;
    uint32_t jabberPktsRcvd;
    uint32_t pauseXOnFramesRcvd;
    uint32_t pauseXOffFramesRcvd;
    uint32_t pauseXOnFramesTx;
    uint32_t pauseXOffFramesTx;
    uint32_t singleCollisionTxFrames;
    uint32_t multipleCollisionTxFrames;
    uint32_t lateCollisionFrames;
    uint32_t excessiveCollisionFrames;
    uint32_t controlFramesRcvd;
    uint32_t rxFrame_64;
    uint32_t rxFrame_65_127;
    uint32_t rxFrame_128_255;
    uint32_t rxFrame_256_511;
    uint32_t rxFrame_512_1023;
    uint32_t rxFrame_1024_1522;
    uint32_t rxFrame_1523_9022;
    uint32_t txFrame_64;
    uint32_t txFrame_65_127;
    uint32_t txFrame_128_255;
    uint32_t txFrame_256_511;
    uint32_t txFrame_512_1023;
    uint32_t txFrame_1024_1522;
    uint32_t txFrame_1523_9022;
    uint64_t validBytesRcvd;
    uint32_t errRuntPacketsRcvd;
    uint32_t errJabberPacketsRcvd;
    uint32_t checksum;
}; // DSP0222 NCSI Spec 8.4.50

} // namespace internal

/* @brief  This function is used to get NCSI controller
           packet stats.
 * @param[in] ifindex - Interface Index.
 * @param[in] package - NCSI Package.
 * @returns 0 on success and negative value for failure.
 */
size_t getStats(int ifindex, int package);

} // namespace ncsi
} // namespace network
} // namespace phosphor
