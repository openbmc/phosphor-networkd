
#include "ncsi_stats.hpp"

#include <linux/ncsi.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/genl.h>
#include <netlink/netlink.h>

#include <phosphor-logging/lg2.hpp>

#include <cstring>
#include <iostream>

PHOSPHOR_LOG2_USING_WITH_FLAGS;

namespace phosphor
{
namespace network
{
namespace ncsi
{
namespace internal
{

// converts a 64-bit/32-bit big-endian integer to a host-endian integer
static void
    convertStatsToHostEndianess(NCSIControllerPacketStatsResponse& localVar)
{
    localVar.countersClearedFromLastReadMSB =
        ntohl(localVar.countersClearedFromLastReadMSB);
    localVar.countersClearedFromLastReadLSB =
        ntohl(localVar.countersClearedFromLastReadLSB);
    localVar.totalBytesRcvd = be64toh(localVar.totalBytesRcvd);
    localVar.totalBytesTx = be64toh(localVar.totalBytesTx);
    localVar.totalUnicastPktsRcvd = be64toh(localVar.totalUnicastPktsRcvd);
    localVar.totalMulticastPktsRcvd = be64toh(localVar.totalMulticastPktsRcvd);
    localVar.totalBroadcastPktsRcvd = be64toh(localVar.totalBroadcastPktsRcvd);
    localVar.totalUnicastPktsTx = be64toh(localVar.totalUnicastPktsTx);
    localVar.totalMulticastPktsTx = be64toh(localVar.totalMulticastPktsTx);
    localVar.totalBroadcastPktsTx = be64toh(localVar.totalBroadcastPktsTx);
    localVar.validBytesRcvd = be64toh(localVar.validBytesRcvd);
    localVar.fcsReceiveErrs = ntohl(localVar.fcsReceiveErrs);
    localVar.alignmentErrs = ntohl(localVar.alignmentErrs);
    localVar.falseCarrierDetections = ntohl(localVar.falseCarrierDetections);
    localVar.runtPktsRcvd = ntohl(localVar.runtPktsRcvd);
    localVar.jabberPktsRcvd = ntohl(localVar.jabberPktsRcvd);
    localVar.pauseXOnFramesRcvd = ntohl(localVar.pauseXOnFramesRcvd);
    localVar.pauseXOffFramesRcvd = ntohl(localVar.pauseXOffFramesRcvd);
    localVar.pauseXOnFramesTx = ntohl(localVar.pauseXOnFramesTx);
    localVar.pauseXOffFramesTx = ntohl(localVar.pauseXOffFramesTx);
    localVar.singleCollisionTxFrames = ntohl(localVar.singleCollisionTxFrames);
    localVar.multipleCollisionTxFrames =
        ntohl(localVar.multipleCollisionTxFrames);
    localVar.lateCollisionFrames = ntohl(localVar.lateCollisionFrames);
    localVar.excessiveCollisionFrames =
        ntohl(localVar.excessiveCollisionFrames);
    localVar.controlFramesRcvd = ntohl(localVar.controlFramesRcvd);
    localVar.rxFrame_64 = ntohl(localVar.rxFrame_64);
    localVar.rxFrame_65_127 = ntohl(localVar.rxFrame_65_127);
    localVar.rxFrame_128_255 = ntohl(localVar.rxFrame_128_255);
    localVar.rxFrame_256_511 = ntohl(localVar.rxFrame_256_511);
    localVar.rxFrame_512_1023 = ntohl(localVar.rxFrame_512_1023);
    localVar.rxFrame_1024_1522 = ntohl(localVar.rxFrame_1024_1522);
    localVar.rxFrame_1523_9022 = ntohl(localVar.rxFrame_1523_9022);
    localVar.txFrame_64 = ntohl(localVar.txFrame_64);
    localVar.txFrame_65_127 = ntohl(localVar.txFrame_65_127);
    localVar.txFrame_128_255 = ntohl(localVar.txFrame_128_255);
    localVar.txFrame_256_511 = ntohl(localVar.txFrame_256_511);
    localVar.txFrame_512_1023 = ntohl(localVar.txFrame_512_1023);
    localVar.txFrame_1024_1522 = ntohl(localVar.txFrame_1024_1522);
    localVar.txFrame_1523_9022 = ntohl(localVar.txFrame_1523_9022);
    localVar.errRuntPacketsRcvd = ntohl(localVar.errRuntPacketsRcvd);
    localVar.errJabberPacketsRcvd = ntohl(localVar.errJabberPacketsRcvd);
}

static NCSIControllerPacketStatsResponse
    statsResponseData(std::span<const unsigned char> inVar)
{
    NCSIControllerPacketStatsResponse localVar{};
    localVar.header.MCID = inVar[0];
    localVar.header.revision = inVar[1];
    localVar.header.reserved = inVar[2];
    localVar.header.id = inVar[3];
    localVar.header.type = inVar[4];
    localVar.header.channel = inVar[5];
    std::memmove(&localVar.header.length, &inVar[6], sizeof(uint16_t));
    std::memmove(&localVar.header.rsvd[0], &inVar[8], sizeof(uint32_t));
    std::memmove(&localVar.header.rsvd[1], &inVar[12], sizeof(uint32_t));
    std::memmove(&localVar.response, &inVar[16], sizeof(uint16_t));
    std::memmove(&localVar.reason, &inVar[18], sizeof(uint16_t));
    std::memmove(&localVar.countersClearedFromLastReadMSB, &inVar[20],
                 sizeof(uint32_t));
    std::memmove(&localVar.countersClearedFromLastReadLSB, &inVar[24],
                 sizeof(uint32_t));
    std::memmove(&localVar.totalBytesRcvd, &inVar[28], sizeof(uint64_t));
    std::memmove(&localVar.totalBytesTx, &inVar[36], sizeof(uint64_t));
    std::memmove(&localVar.totalUnicastPktsRcvd, &inVar[44], sizeof(uint64_t));
    std::memmove(&localVar.totalMulticastPktsRcvd, &inVar[52],
                 sizeof(uint64_t));
    std::memmove(&localVar.totalBroadcastPktsRcvd, &inVar[60],
                 sizeof(uint64_t));
    std::memmove(&localVar.totalUnicastPktsTx, &inVar[68], sizeof(uint64_t));
    std::memmove(&localVar.totalMulticastPktsTx, &inVar[76], sizeof(uint64_t));
    std::memmove(&localVar.totalBroadcastPktsTx, &inVar[84], sizeof(uint64_t));
    std::memmove(&localVar.fcsReceiveErrs, &inVar[92], sizeof(uint32_t));
    std::memmove(&localVar.alignmentErrs, &inVar[96], sizeof(uint32_t));
    std::memmove(&localVar.falseCarrierDetections, &inVar[100],
                 sizeof(uint32_t));
    std::memmove(&localVar.runtPktsRcvd, &inVar[104], sizeof(uint32_t));
    std::memmove(&localVar.jabberPktsRcvd, &inVar[108], sizeof(uint32_t));
    std::memmove(&localVar.pauseXOnFramesRcvd, &inVar[112], sizeof(uint32_t));
    std::memmove(&localVar.pauseXOffFramesRcvd, &inVar[116], sizeof(uint32_t));
    std::memmove(&localVar.pauseXOnFramesTx, &inVar[120], sizeof(uint32_t));
    std::memmove(&localVar.pauseXOffFramesTx, &inVar[124], sizeof(uint32_t));
    std::memmove(&localVar.singleCollisionTxFrames, &inVar[128],
                 sizeof(uint32_t));
    std::memmove(&localVar.multipleCollisionTxFrames, &inVar[132],
                 sizeof(uint32_t));
    std::memmove(&localVar.lateCollisionFrames, &inVar[136], sizeof(uint32_t));
    std::memmove(&localVar.excessiveCollisionFrames, &inVar[140],
                 sizeof(uint32_t));
    std::memmove(&localVar.controlFramesRcvd, &inVar[144], sizeof(uint32_t));
    std::memmove(&localVar.rxFrame_64, &inVar[148], sizeof(uint32_t));
    std::memmove(&localVar.rxFrame_65_127, &inVar[152], sizeof(uint32_t));
    std::memmove(&localVar.rxFrame_128_255, &inVar[156], sizeof(uint32_t));
    std::memmove(&localVar.rxFrame_256_511, &inVar[160], sizeof(uint32_t));
    std::memmove(&localVar.rxFrame_512_1023, &inVar[164], sizeof(uint32_t));
    std::memmove(&localVar.rxFrame_1024_1522, &inVar[168], sizeof(uint32_t));
    std::memmove(&localVar.rxFrame_1523_9022, &inVar[172], sizeof(uint32_t));
    std::memmove(&localVar.txFrame_64, &inVar[176], sizeof(uint32_t));
    std::memmove(&localVar.txFrame_65_127, &inVar[180], sizeof(uint32_t));
    std::memmove(&localVar.txFrame_128_255, &inVar[184], sizeof(uint32_t));
    std::memmove(&localVar.txFrame_256_511, &inVar[188], sizeof(uint32_t));
    std::memmove(&localVar.txFrame_512_1023, &inVar[192], sizeof(uint32_t));
    std::memmove(&localVar.txFrame_1024_1522, &inVar[196], sizeof(uint32_t));
    std::memmove(&localVar.txFrame_1523_9022, &inVar[200], sizeof(uint32_t));
    std::memmove(&localVar.validBytesRcvd, &inVar[204], sizeof(uint64_t));
    std::memmove(&localVar.errRuntPacketsRcvd, &inVar[212], sizeof(uint32_t));
    std::memmove(&localVar.errJabberPacketsRcvd, &inVar[216], sizeof(uint32_t));
    std::memmove(&localVar.checksum, &inVar[220], sizeof(uint32_t));

    convertStatsToHostEndianess(localVar);
    return localVar;
}

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
CallBack statsCallback = [](struct nl_msg* msg, void* arg) {
    std::span<const unsigned char> payload = getNcsiCommandPayload(msg, arg);

    if (!payload.empty())
    {
        auto statsResponse = statsResponseData(payload);
        std::cout << statsResponse;
    }

    return 0;
};

} // namespace internal

size_t getStats(int ifindex, int package)
{
    constexpr auto ncsiCmdGetStatistics = 0x18;

    debug(
        "Sending NCSI command {COMMAND} to package {PACKAGE} on channel {CHANNEL}"
        " for interface index {IFINDEX}",
        "COMMAND", hex, ncsiCmdGetStatistics, "PACKAGE", hex, package,
        "IFINDEX", ifindex);

    return internal::applyCmd(
        ifindex,
        internal::Command(ncsi_nl_commands::NCSI_CMD_SEND_CMD,
                          ncsiCmdGetStatistics),
        package, NONE, NONE, internal::statsCallback);
}

} // namespace ncsi
} // namespace network
} // namespace phosphor
