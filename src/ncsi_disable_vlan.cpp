#include <linux/ncsi.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/genl.h>
#include <netlink/netlink.h>

#include <cereal/archives/binary.hpp>
#include <cereal/types/vector.hpp>
#include <phosphor-logging/lg2.hpp>

#include <sstream>
#include <vector>

#include "ncsi_disable_vlan.hpp"

namespace phosphor
{
namespace network
{
namespace ncsi
{
namespace internal
{

CallBack disableVlanCallBack = [](struct nl_msg* msg, void* arg) {
    std::span<const unsigned char> payload;
    auto ret = getNcsiCommandPayload(msg, arg, payload);

    if (!ret)
    {
        std::vector<unsigned char> payloadVec(payload.begin(), payload.end());
        std::istringstream iss(
            std::string(payloadVec.begin(), payloadVec.end()));
        cereal::BinaryInputArchive ar(iss);
        DisableVlanResponsePacket packet;
        ar(packet);

        auto type = packet.header.type;
        lg2::debug("Disable Vlan Response type : {RESPONSE_TYPE}",
                   "RESPONSE_TYPE", lg2::hex, type);

        auto headerLength = htons(packet.header.length);
        lg2::debug("Disable Vlan Response length : {RESPONSE_LEN}",
                   "RESPONSE_LEN", lg2::hex, headerLength);

        auto response = ntohs(packet.response);
        auto reason = ntohs(packet.reason);

        lg2::debug("Disable Vlan Response : {RESPONSE} Reason : {REASON}",
                   "RESPONSE", lg2::hex, response, "REASON", lg2::hex, reason);
    }

    return ret;
};

} // namespace internal

int disableVlan(int ifindex, int package, int channel)
{
    constexpr auto ncsiCmdDisableVlan = 0x0D;

    lg2::debug("Send NCSI Command, CHANNEL : {CHANNEL} , PACKAGE : {PACKAGE}, "
               "INTERFACE_INDEX: {INTERFACE_INDEX}, NCSI_CMD : {NCSI_CMD}",
               "CHANNEL", lg2::hex, channel, "PACKAGE", lg2::hex, package,
               "INTERFACE_INDEX", lg2::hex, ifindex, "NCSI_CMD", lg2::hex,
               ncsiCmdDisableVlan);

    return internal::applyCmd(
        ifindex,
        internal::Command(ncsi_nl_commands::NCSI_CMD_SEND_CMD,
                          ncsiCmdDisableVlan),
        package, channel, NONE, internal::disableVlanCallBack);
}

} // namespace ncsi
} // namespace network
} // namespace phosphor
