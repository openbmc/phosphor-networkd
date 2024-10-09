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

std::ostream& operator<<(std::ostream& os,
                         struct NCSIControllerPacketStatsResponse& pResp)
{
    os << "\nNIC statistics: " << "\nResponse: " << pResp.response
       << "\nReason: " << pResp.reason << "\nCounters cleared last read (MSB): "
       << pResp.countersClearedFromLastReadMSB
       << "\nCounters cleared last read (LSB): "
       << pResp.countersClearedFromLastReadLSB
       << "\nTotal Bytes Received: " << pResp.totalBytesRcvd
       << "\nTotal Bytes Transmitted: " << pResp.totalBytesTx
       << "\nTotal Unicast Packet Received: " << pResp.totalUnicastPktsRcvd
       << "\nTotal Multicast Packet Received: " << pResp.totalMulticastPktsRcvd
       << "\nTotal Broadcast Packet Received: " << pResp.totalBroadcastPktsRcvd
       << "\nTotal Unicast Packet Transmitted: " << pResp.totalUnicastPktsTx
       << "\nTotal Multicast Packet Transmitted: " << pResp.totalMulticastPktsTx
       << "\nTotal Broadcast Packet Transmitted: " << pResp.totalBroadcastPktsTx
       << "\nFCS Receive Errors: " << pResp.fcsReceiveErrs
       << "\nAlignment Errors: " << pResp.alignmentErrs
       << "\nFalse Carrier Detections: " << pResp.falseCarrierDetections
       << "\nRunt Packets Received: " << pResp.runtPktsRcvd
       << "\nJabber Packets Received: " << pResp.jabberPktsRcvd
       << "\nPause XON Frames Received: " << pResp.pauseXOnFramesRcvd
       << "\nPause XOFF Frames Received: " << pResp.pauseXOffFramesRcvd
       << "\nPause XON Frames Transmitted: " << pResp.pauseXOnFramesTx
       << "\nPause XOFF Frames Transmitted: " << pResp.pauseXOffFramesTx
       << "\nSingle Collision Transmit Frames: "
       << pResp.singleCollisionTxFrames
       << "\nMultiple Collision Transmit Frames: "
       << pResp.multipleCollisionTxFrames
       << "\nLate Collision Frames: " << pResp.lateCollisionFrames
       << "\nExcessive Collision Frames: " << pResp.excessiveCollisionFrames
       << "\nControl Frames Received: " << pResp.controlFramesRcvd
       << "\n64-Byte Frames Received: " << pResp.rxFrame_64
       << "\n65-127 Byte Frames Received: " << pResp.rxFrame_65_127
       << "\n128-255 Byte Frames Received: " << pResp.rxFrame_128_255
       << "\n256-511 Byte Frames Received: " << pResp.rxFrame_256_511
       << "\n512-1023 Byte Frames Received: " << pResp.rxFrame_512_1023
       << "\n1024-1522 Byte Frames Received: " << pResp.rxFrame_1024_1522
       << "\n1523-9022 Byte Frames Received: " << pResp.rxFrame_1523_9022
       << "\n64-Byte Frames Transmitted: " << pResp.txFrame_64
       << "\n65-127 Byte Frames Transmitted: " << pResp.txFrame_65_127
       << "\n128-255 Byte Frames Transmitted: " << pResp.txFrame_128_255
       << "\n256-511 Byte Frames Transmitted: " << pResp.txFrame_256_511
       << "\n512-1023 Byte Frames Transmitted: " << pResp.txFrame_512_1023
       << "\n1024-1522 Byte Frames Transmitted: " << pResp.txFrame_1024_1522
       << "\n1523-9022 Byte Frames Transmitted: " << pResp.txFrame_1523_9022
       << "\nValid Bytes Received: " << pResp.validBytesRcvd
       << "\nError Runt Packets Received: " << pResp.errRuntPacketsRcvd
       << "\nError Jabber Packets Received: " << pResp.errJabberPacketsRcvd
       << "\n";
    return os;
}

} // namespace internal
} // namespace ncsi
} // namespace network
} // namespace phosphor

