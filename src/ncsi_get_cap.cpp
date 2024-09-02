#include "ncsi_get_cap.hpp"

#include <linux/ncsi.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/genl.h>
#include <netlink/netlink.h>

#include <phosphor-logging/lg2.hpp>

#include <cstring>
#include <sstream>
#include <string_view>
#include <map>
#include <utility>  // For std::to_underlying (C++23)

PHOSPHOR_LOG2_USING_WITH_FLAGS;

namespace phosphor
{
namespace network
{
namespace ncsi
{

// Get Capabilities Command (0x16)
// DSP0222 NCSI Spec 8.4.45

// Define an enum class for NCSI commands
enum class NCSICommand : int {
    getCapabilities = 0x16,  // Assigning a specific value (hexadecimal 0x16)
    // Other command constants can go here
};

namespace internal
{

const int operTypeMask = 0x7f;

// Initialize a std::map to associate enum values with strings
const std::map<NCSICommand, std::string_view> commandMap = {
    { NCSICommand::getCapabilities, "GET CAPABILITIES" }
};

// Function to get the string corresponding to an enum value
std::string_view NCSICommandToString(NCSICommand cmd) {
    auto it = commandMap.find(cmd);
    if (it != commandMap.end()) {
        return it->second;
    }
    return "Unknown NCSI cmd";  // Default for invalid values
}

/* -------Reason Code handler---------------- */

enum class NCSIReason : int {
    noError = 0x0000,
    intfInitReqd = 0x0001,
    paramInvalid = 0x0002,
    channelNotRdy = 0x0003,
    pkgNotRdy = 0x0004,
    invalidPayloadLen = 0x0005,
    infoNotAvail = 0x0006,
    unknownCmdType = 0x7FFF,
};

// Initialize a std::map to associate enum values with strings
const std::map<NCSIReason, std::string_view> reasonMap = {
    { NCSIReason::noError, "NO ERROR" },
    { NCSIReason::intfInitReqd, "INTF INIT REQD" },
    { NCSIReason::paramInvalid, "PARAM INVALID" },
    { NCSIReason::channelNotRdy, "CHANNEL NOT RDY" },
    { NCSIReason::pkgNotRdy, "PKG NOT RDY" },
    { NCSIReason::invalidPayloadLen, "INVALID PAYLOAD LEN" },
    { NCSIReason::infoNotAvail, "INFO NOT AVAIL" },
    { NCSIReason::unknownCmdType, "UNKNOWN CMD TYPE" }
};

// Function to get the string corresponding to an enum value
std::string_view NCSIReasonToString(NCSIReason reas) {
    auto it = reasonMap.find(reas);
    if (it != reasonMap.end()) {
        return it->second;
    }
    return "Unknown Reason";  // Default for invalid values
}

/* ---------Response code handler-------------- */

enum class NCSIResponse : int {
    commandCompleted = 0,
    commandFailed,
    commandUnavailable,
    commandUnSupported,
};

// Initialize a std::map to associate NCSI response code enum values with strings
const std::map<NCSIResponse, std::string_view> responseMap = {
    { NCSIResponse::commandCompleted, "COMMAND_COMPLETED" },
    { NCSIResponse::commandFailed, "COMMAND_FAILED" },
    { NCSIResponse::commandUnavailable, "COMMAND_UNAVAILABLE" },
    { NCSIResponse::commandUnSupported, "COMMAND_UNSUPPORTED" }
};

// Function to get the response string in C++23 style
std::string_view NCSIResponseToString(NCSIResponse resp) {
    auto it = responseMap.find(resp);
    if (it != responseMap.end()) {
        return it->second;
    }
    return "Unknown Response";  // Default for invalid values
}

/* ----------------------- */

GetCapabilitiesResponsePacket::GetCapabilitiesResponsePacket(
    std::span<const uint8_t> buffer)
{
    header.type = buffer[4];
    header.length = ((buffer[6] << 8) | buffer[7]);
    response = ((buffer[16] << 8) | buffer[17]);
    reason = ((buffer[18] << 8) | buffer[19]);

    capData.capabilitiesFlags = ((buffer[20] << 24) |
            (buffer[21] << 16) |
            (buffer[22] << 8)  |
            (buffer[23]));

    capData.broadcastPacketFilterCapabilities = ((buffer[24] << 24) |
            (buffer[25] << 16) |
            (buffer[26] << 8)  |
            (buffer[27]));

    capData.multicastPacketFilterCapabilities = ((buffer[28] << 24) |
            (buffer[29] << 16) |
            (buffer[30] << 8)  |
            (buffer[31]));

    capData.bufferingCapabilities = ((buffer[32] << 24) |
            (buffer[33] << 16) |
            (buffer[34] << 8)  |
            (buffer[35]));

    capData.aenControlSupport = ((buffer[36] << 24) |
            (buffer[37] << 16) |
            (buffer[38] << 8)  |
            (buffer[39]));

    capData.vlanFilterCnt = buffer[40];
    capData.mixedFilterCnt = buffer[41];
    capData.multicastFilterCnt = buffer[42];
    capData.unicastFilterCnt = buffer[43];
    capData.vlanModeSupport = buffer[46];
    capData.channelCnt = buffer[47];
}

static void printNCSICapabilities(const NCSIGetCapabilitiesInfo& capInfo)
{
    setlocale(LC_ALL, "");

    lg2::debug("Get Capabilities response:");

    lg2::info("  capabilities_flags = {CAP_FLAGS}",
              "CAP_FLAGS", lg2::hex, ntohl(capInfo.capabilitiesFlags));
    lg2::info("  broadcast_packet_filter_capabilities = {BROAD_PKT_FILTER}",
              "BROAD_PKT_FILTER", lg2::hex, ntohl(capInfo.broadcastPacketFilterCapabilities));
    lg2::info("  multicast_packet_filter_capabilities = {MULTICAST_PKT_FILTER}",
              "MULTICAST_PKT_FILTER", lg2::hex, ntohl(capInfo.multicastPacketFilterCapabilities));
    lg2::info("  buffering_capabilities = {BUFFERING}",
              "BUFFERING", lg2::hex, ntohl(capInfo.bufferingCapabilities));
    lg2::info("  aen_control_support = {AENCNTRL}",
              "AENCNTRL", lg2::hex, ntohl(capInfo.aenControlSupport));
    lg2::info("  unicast_filter_cnt = {UNICAST_FILTER}",
              "UNICAST_FILTER", static_cast<int>(capInfo.unicastFilterCnt));
    lg2::info("  multicast_filter_cnt = {MULTICAST_FILTER}",
              "MULTICAST_FILTER", static_cast<int>(capInfo.multicastFilterCnt));
    lg2::info("  mixed_filter_cnt = {MIXED_FILTER}",
              "MIXED_FILTER", static_cast<int>(capInfo.mixedFilterCnt));
    lg2::info("  vlan_filter_cnt = {VLAN_FILTER}",
              "VLAN_FILTER", static_cast<int>(capInfo.vlanFilterCnt));
    lg2::info("  channel_cnt = {CHANNEL_COUNT}",
              "CHANNEL_COUNT", static_cast<int>(capInfo.channelCnt));
    lg2::info("  vlan_mode_support = {VLAN_MODE}",
              "VLAN_MODE", static_cast<int>(capInfo.vlanModeSupport));
}

CallBack getCapabilitiesCallBack = [](struct nl_msg* msg, void* arg) {
    auto payload = getNcsiCommandPayload(msg, arg);

    if (!payload.empty())
    {
        GetCapabilitiesResponsePacket packet(payload);

        auto type = packet.header.type;
        auto headerLength = packet.header.length;
        auto response = packet.response;
        auto reason = packet.reason;

        auto cmdSent = (type & operTypeMask); // clear MSB and keep lower 7 bits
                                        // to know command sent.

        NCSICommand cmdNSent = static_cast<NCSICommand>(cmdSent);

        lg2::debug("cmd: {COMMAND_STR} ({COMMAND})", "COMMAND_STR",
                   NCSICommandToString(static_cast<NCSICommand>(cmdSent)), "COMMAND", lg2::hex, cmdSent);
        lg2::debug("NCSI Response packet type : {RESPONSE_PKT_TYPE}",
                   "RESPONSE_PKT_TYPE", lg2::hex, type);

        lg2::debug("NCSI Response length : {RESPONSE_LEN}", "RESPONSE_LEN",
                   lg2::hex, headerLength);

        lg2::debug("NC-SI Command Response:");

        NCSIResponse rspCode = static_cast<NCSIResponse>(response);
        NCSIReason resCode = static_cast<NCSIReason>(reason);

        lg2::debug("Response: {RESPONSE_STR} {RESPONSE}", "RESPONSE_STR",
                   NCSIResponseToString(rspCode), "RESPONSE", lg2::hex, response);
        lg2::debug("Reason: {REASON_STR} {REASON}", "REASON_STR",
                   NCSIReasonToString(resCode), "REASON", lg2::hex, reason);

        if(rspCode != NCSIResponse::commandCompleted)
        {
          return 0;
        }

        if (cmdNSent != NCSICommand::getCapabilities)
        {
           lg2::debug("Payload length = {RESP_HDR_LEN}","RESP_HDR_LEN", headerLength);
           std::span<const unsigned char> responseData =
            payload.subspan(sizeof(NCSIPacketHeader));

          // Dump the response to stdout. Enhancement: option to save response
          // data
           auto str = toHexStr(responseData);
           lg2::debug("Response {DATA_LEN} bytes: {DATA}", "DATA_LEN",
                      responseData.size(), "DATA", str);
        }

        printNCSICapabilities(packet.capData);

    }
    return 0;
};

} // namespace internal

size_t getCapabilitiesInfo(int ifindex, int package, int channel)
{
    debug(
        "Sending NCSI command {COMMAND} to package {PACKAGE} on channel {CHANNEL}"
        " for interface index {IFINDEX}",
        "COMMAND", hex, std::to_underlying(NCSICommand::getCapabilities), "PACKAGE", hex, package, "CHANNEL",
        hex, channel, "IFINDEX", ifindex);

    return internal::applyCmd(
        ifindex,
        internal::Command(ncsi_nl_commands::NCSI_CMD_SEND_CMD,
                          std::to_underlying(NCSICommand::getCapabilities)),
        package, channel, NONE, internal::getCapabilitiesCallBack);
}

} // namespace ncsi
} // namespace network
} // namespace phosphor
