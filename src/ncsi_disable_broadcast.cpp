#include "ncsi_disable_broadcast.hpp"

#include <linux/ncsi.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/genl.h>
#include <netlink/netlink.h>

#include <phosphor-logging/lg2.hpp>

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

CallBack disableBroadcastFilterCallBack = [](struct nl_msg* msg, void* arg) {
    auto payload = getNcsiCommandPayload(msg, arg);

    if (!payload.empty())
    {
        DisableBroadcastFilterResponsePacket packet;
        std::memcpy(&packet, payload.data(), sizeof(packet));

        auto type = packet.header.type;
        auto headerLength = ntohs(packet.header.length);
        auto response = ntohs(packet.response);
        auto reason = ntohs(packet.reason);

        debug("Disable VLAN response type : {RESPONSE_TYPE} "
              "length : {RESPONSE_LEN} "
              "Response Code : {RESPONSE} Reason Code : {REASON}",
              "RESPONSE_TYPE", hex, type, "RESPONSE_LEN", hex, headerLength,
              "RESPONSE", hex, response, "REASON", hex, reason);
    }

    return 0;
};

} // namespace internal

size_t disableBroadcastFilter(int ifindex, int package, int channel)
{
    constexpr auto ncsiCmdDisableBroadcastFilter = 0x11;

    debug(
        "Sending NCSI command {COMMAND} to package {PACKAGE} on channel {CHANNEL}"
        " for interface index {IFINDEX}",
        "COMMAND", hex, ncsiCmdDisableBroadcastFilter, "PACKAGE", hex, package, "CHANNEL",
        hex, channel, "IFINDEX", ifindex);

    return internal::applyCmd(
        ifindex,
        internal::Command(ncsi_nl_commands::NCSI_CMD_SEND_CMD,
                          ncsiCmdDisableBroadcastFilter),
        package, channel, NONE, internal::disableBroadcastFilterCallBack);
}

} // namespace ncsi
} // namespace network
} // namespace phosphor
