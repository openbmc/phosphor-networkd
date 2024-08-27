#include "ncsi_pass_stat.hpp"

#include <linux/ncsi.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/genl.h>
#include <netlink/netlink.h>

#include <phosphor-logging/lg2.hpp>

#include <iostream>
#include <cstring>
#include <sstream>

PHOSPHOR_LOG2_USING_WITH_FLAGS;

namespace phosphor
{
namespace network
{
namespace ncsi
{
namespace internal
{

getPassthruStatResponsePacket::getPassthruStatResponsePacket(
    std::span<const uint8_t> buffer)
{
  header.type = buffer[4];
  header.length = ((buffer[6] << 8) | buffer[7]);
  response = ((buffer[16] << 8) | buffer[17]);
  reason = ((buffer[18] << 8) | buffer[19]);
  txPacketsRcvdOnNcsi = ((buffer[20] << 56) | // Byte 0 to bits 63-56
            (buffer[21] << 48) | // Byte 1 to bits 55-48
            (buffer[22] << 40) | // Byte 2 to bits 47-40
            (buffer[23] << 32) | // Byte 3 to bits 39-32
            (buffer[24] << 24) | // Byte 4 to bits 31-24
            (buffer[25] << 16) | // Byte 5 to bits 23-16
            (buffer[26] << 8)  | // Byte 6 to bits 15-8
            (buffer[27]));        // Byte 7 to bits 7-0
  txPacketsDropped = ((buffer[28] << 24) |
            (buffer[29] << 16) |
            (buffer[30] << 8)  |
            (buffer[31]));
  txChannelStateErr = ((buffer[32] << 24) |
            (buffer[33] << 16) |
            (buffer[34] << 8)  |
            (buffer[35]));
  txUndersizeErr = ((buffer[36] << 24) |
            (buffer[37] << 16) |
            (buffer[38] << 8)  |
            (buffer[39]));
  txOversizeErr = ((buffer[40] << 24) |
            (buffer[41] << 16) |
            (buffer[42] << 8)  |
            (buffer[43]));
  rxPacketsRcvdOnLan = ((buffer[44] << 24) |
            (buffer[45] << 16) |
            (buffer[46] << 8)  |
            (buffer[47]));
  totalRxPacketsDropped = ((buffer[48] << 24) |
            (buffer[49] << 16) |
            (buffer[50] << 8)  |
            (buffer[51]));
  rxChannelStateErr = ((buffer[52] << 24) |
            (buffer[53] << 16) |
            (buffer[54] << 8)  |
            (buffer[55]));
  rxUndersizeErr = ((buffer[56] << 24) |
            (buffer[57] << 16) |
            (buffer[58] << 8)  |
            (buffer[59]));
  rxOversizeErr = ((buffer[60] << 24) |
            (buffer[61] << 16) |
            (buffer[62] << 8)  |
            (buffer[63]));
}

static void
    printNCSIPassthroughStats(const getPassthruStatResponsePacket &passthroughResp)
{
    setlocale(LC_ALL, "");
    std::cout << "Packet Response Status " << "\nNC-SI Response Code: "
              << passthroughResp.response
              << "\nNC-SI Reason Code: "
              << passthroughResp.reason
              << "\nNIC NC-SI Pass-through statistics"
              << "\nPass-through TX Packets Received: "
              << passthroughResp.txPacketsRcvdOnNcsi
              << "\nPass-through TX Packets Dropped: "
              << passthroughResp.txPacketsDropped
              << "\nPass-through TX Packet Channel State Errors: "
              << passthroughResp.txChannelStateErr
              << "\nPass-through TX Packet Undersize Errors: "
              << passthroughResp.txUndersizeErr
              << "\nPass-through TX Packets Oversize Packets: "
              << passthroughResp.txOversizeErr
              << "\nPass-through RX Packets Received on LAN: "
              << passthroughResp.rxPacketsRcvdOnLan
              << "\nTotal Pass-through RX Packets Dropped: "
              << passthroughResp.totalRxPacketsDropped
              << "\nPass-through RX Packet Channel State Errors: "
              << passthroughResp.rxChannelStateErr
              << "\nPass-through RX Packet Undersize Errors: "
              << passthroughResp.rxUndersizeErr
              << "\nPass-through RX Packets Oversize Packets: "
              << passthroughResp.rxOversizeErr << "\n";
}

CallBack getPassthruStatCallBack = [](struct nl_msg* msg, void* arg) {
    auto payload = getNcsiCommandPayload(msg, arg);

    if (!payload.empty())
    {
        getPassthruStatResponsePacket packet(payload);

        debug("Get Passthru Stat response type : {RESPONSE_TYPE} "
              "length : {RESPONSE_LEN} "
              "Response Code : {RESPONSE} Reason Code : {REASON}",
              "RESPONSE_TYPE", hex, packet.header.type, "RESPONSE_LEN", hex, packet.header.length,
              "RESPONSE", hex, packet.response, "REASON", hex, packet.reason);

        printNCSIPassthroughStats(packet);
    }

    return 0;
};

} // namespace internal

size_t getNCSIPassthroughStats(int ifindex, int package, int channel)
{
    constexpr auto ncsiCmdGetPassthruStat = 0x1a;

    debug(
        "Sending NCSI command {COMMAND} to package {PACKAGE} on channel {CHANNEL}"
        " for interface index {IFINDEX}",
        "COMMAND", hex, ncsiCmdGetPassthruStat, "PACKAGE", hex, package, "CHANNEL",
        hex, channel, "IFINDEX", ifindex);

    return internal::applyCmd(
        ifindex,
        internal::Command(ncsi_nl_commands::NCSI_CMD_SEND_CMD,
                          ncsiCmdGetPassthruStat),
        package, channel, NONE, internal::getPassthruStatCallBack);
}

} // namespace ncsi
} // namespace network
} // namespace phosphor
