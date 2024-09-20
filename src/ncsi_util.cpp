#include "ncsi_util.hpp"

#include <linux/ncsi.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/genl.h>
#include <netlink/netlink.h>

#include <phosphor-logging/lg2.hpp>
#include <stdplus/numeric/str.hpp>
#include <stdplus/str/buf.hpp>

#include <vector>

namespace phosphor
{
namespace network
{
namespace ncsi
{

using CallBack = int (*)(struct nl_msg* msg, void* arg);

static stdplus::StrBuf toHexStr(std::span<const uint8_t> c) noexcept
{
    stdplus::StrBuf ret;
    if (c.empty())
    {
        return ret;
    }
    stdplus::IntToStr<16, uint8_t> its;
    auto oit = ret.append(c.size() * 3);
    auto cit = c.begin();
    oit = its(oit, *cit++, 2);
    for (; cit != c.end(); ++cit)
    {
        *oit++ = ' ';
        oit = its(oit, *cit, 2);
    }
    *oit = 0;
    return ret;
}

namespace internal
{

struct NCSIPacketHeader
{
    uint8_t MCID;
    uint8_t revision;
    uint8_t reserved;
    uint8_t id;
    uint8_t type;
    uint8_t channel;
    uint16_t length;
    uint32_t rsvd[2];
};

struct NcsiNcDataResponsePacket
{
    NCSIPacketHeader header;
    uint16_t response;
    uint16_t reason;
    uint8_t reserved[3];
    uint8_t opcode;
    unsigned char data[1500];
};

constexpr uint32_t NCSI_CORE_DUMP_HANDLE = 0xFFFF0000;
constexpr uint32_t NCSI_CRASH_DUMP_HANDLE = 0xFFFF0001;

class NcsiDumpTransfer
{
  public:
    NcsiDumpTransfer(const std::string& fileName) :
        totalDataSize(0), abort(false)
    {
        outFile.open(fileName, std::ios::binary);
        if (!outFile.is_open())
        {
            throw std::runtime_error("Failed to open file: " + fileName);
        }
    }

    ~NcsiDumpTransfer()
    {
        if (outFile.is_open())
        {
            outFile.close();
        }
    }

    int callback(struct nl_msg* msg)
    {
        auto nlh = nlmsg_hdr(msg);
        struct nlattr* tb[NCSI_ATTR_MAX + 1] = {nullptr};
        static struct nla_policy ncsiPolicy[NCSI_ATTR_MAX + 1] = {
            {NLA_UNSPEC, 0, 0}, {NLA_U32, 0, 0}, {NLA_NESTED, 0, 0},
            {NLA_U32, 0, 0},    {NLA_U32, 0, 0}, {NLA_BINARY, 0, 0},
            {NLA_FLAG, 0, 0},   {NLA_U32, 0, 0}, {NLA_U32, 0, 0},
        };

        auto ret = genlmsg_parse(nlh, 0, tb, NCSI_ATTR_MAX, ncsiPolicy);
        if (ret)
        {
            lg2::error("Failed to parse response packet");
            return ret;
        }

        if (tb[NCSI_ATTR_DATA] == nullptr)
        {
            lg2::error("Response: No data");
            return -1;
        }

        struct NcsiNcDataResponsePacket* packet =
            (struct NcsiNcDataResponsePacket*)nla_data(tb[NCSI_ATTR_DATA]);

        uint16_t length = ntohs(packet->header.length);
        uint16_t response = ntohs(packet->response);
        uint16_t reason = ntohs(packet->reason);
        opcode = packet->opcode;

        std::string responseDesc = getDescForResponse(response);

        lg2::debug(
            "NcsiNcDataResponsePacket Info length: {LENGTH}, response: {RESPONSE} ({RESPONSE_DESC}), "
            "reason: {REASON}, opcode: {OPCODE}",
            "LENGTH", length, "RESPONSE", lg2::hex, response, "RESPONSE_DESC",
            responseDesc, "REASON", lg2::hex, reason, "OPCODE", lg2::hex,
            opcode);

        if (response != 0) // Check response code for errors
        {
            std::string reasonDesc = getDescForReason(reason);
            lg2::error(
                "Response error detected, response code: {RESPONSE} ({RESPONSE_DESC}), reason code: {REASON} ({REASON_DESC})",
                "RESPONSE", lg2::hex, response, "RESPONSE_DESC", responseDesc,
                "REASON", lg2::hex, reason, "REASON_DESC", reasonDesc);
            return -1;
        }

        if (length > 8)
        {
            // Ensure length is 4-byte aligned
            if (length % 4 != 0)
            {
                lg2::error("Packet length is not 4-byte aligned: {LENGTH}",
                           "LENGTH", length);
                return -1;
            }

            auto dataSize = length - 8;
            totalDataSize += dataSize;

            lg2::debug("Response {DATA_LEN} bytes", "DATA_LEN", dataSize);
            lg2::debug("Total Data Size So Far: {TOTAL_DATA_SIZE} bytes",
                       "TOTAL_DATA_SIZE", totalDataSize);

            if (outFile.is_open())
            {
                outFile.write(reinterpret_cast<const char*>(packet->data),
                              dataSize);
            }
            else
            {
                lg2::error("Failed to write to file. File is not open.");
                return -1;
            }
        }
        else
        {
            lg2::error(
                "Received response with insufficient data length: {LENGTH}. Expected more than 8 bytes.",
                "LENGTH", length);
            return -1;
        }

        return 0;
    }

    uint8_t getOpcode() const
    {
        return opcode;
    }

    void setAbort(bool value)
    {
        abort = value;
    }

    bool isAbort() const
    {
        return abort;
    }

  private:
    uint8_t opcode;
    uint32_t totalDataSize;
    std::ofstream outFile;
    bool abort;

    std::string getDescForResponse(uint16_t response) const
    {
        switch (response)
        {
            case 0x0000:
                return "Command Completed";
            case 0x0001:
                return "Command Failed";
            case 0x0002:
                return "Command Unavailable";
            case 0x0003:
                return "Command Unsupported";
            case 0x0004:
                return "Delayed Response";
            default:
                return "Unknown response code.";
        }
    }

    std::string getDescForReason(uint16_t reason) const
    {
        switch (reason)
        {
            case 0x0001:
                return "Interface Initialization Required";
            case 0x0002:
                return "Parameter Is Invalid, Unsupported, or Out-of-Range";
            case 0x0003:
                return "Channel Not Ready";
            case 0x0004:
                return "Package Not Ready";
            case 0x0005:
                return "Invalid Payload Length";
            case 0x0006:
                return "Information Not Available";
            case 0x0007:
                return "Intervention Required";
            case 0x0008:
                return "Link Command Failed - Hardware Access Error";
            case 0x0009:
                return "Command Timeout";
            case 0x000A:
                return "Secondary Device Not Powered";
            case 0x7FFF:
                return "Unknown/Unsupported Command Type";
            case 0x4D01:
                return "Abort Transfer: NC cannot proceed with transfer.";
            case 0x4D02:
                return "Invalid Handle Value: Data Handle is invalid or not supported.";
            case 0x4D03:
                return "Sequence Count Error: Chunk Number requested is not consecutive with the previous number transmitted.";
            default:
                if (reason >= 0x8000)
                {
                    return "OEM Reason Code";
                }
                else
                {
                    return "Unknown reason code.";
                }
        }
    }
};

class Command
{
  public:
    Command() = delete;
    ~Command() = default;
    Command(const Command&) = delete;
    Command& operator=(const Command&) = delete;
    Command(Command&&) = default;
    Command& operator=(Command&&) = default;
    Command(
        int ncsiCmd, int operation = DEFAULT_VALUE,
        std::span<const unsigned char> p = std::span<const unsigned char>()) :
        ncsi_cmd(ncsiCmd), operation(operation), payload(p)
    {}

    int ncsi_cmd;
    int operation;
    std::span<const unsigned char> payload;
};

using nlMsgPtr = std::unique_ptr<nl_msg, decltype(&::nlmsg_free)>;
using nlSocketPtr = std::unique_ptr<nl_sock, decltype(&::nl_socket_free)>;

CallBack infoCallBack = [](struct nl_msg* msg, void* arg) {
    using namespace phosphor::network::ncsi;
    auto nlh = nlmsg_hdr(msg);

    struct nlattr* tb[NCSI_ATTR_MAX + 1] = {nullptr};
    struct nla_policy ncsiPolicy[NCSI_ATTR_MAX + 1] = {
        {NLA_UNSPEC, 0, 0}, {NLA_U32, 0, 0}, {NLA_NESTED, 0, 0},
        {NLA_U32, 0, 0},    {NLA_U32, 0, 0},
    };

    struct nlattr* packagetb[NCSI_PKG_ATTR_MAX + 1] = {nullptr};
    struct nla_policy packagePolicy[NCSI_PKG_ATTR_MAX + 1] = {
        {NLA_UNSPEC, 0, 0}, {NLA_NESTED, 0, 0}, {NLA_U32, 0, 0},
        {NLA_FLAG, 0, 0},   {NLA_NESTED, 0, 0},
    };

    struct nlattr* channeltb[NCSI_CHANNEL_ATTR_MAX + 1] = {nullptr};
    struct nla_policy channelPolicy[NCSI_CHANNEL_ATTR_MAX + 1] = {
        {NLA_UNSPEC, 0, 0}, {NLA_NESTED, 0, 0}, {NLA_U32, 0, 0},
        {NLA_FLAG, 0, 0},   {NLA_NESTED, 0, 0}, {NLA_UNSPEC, 0, 0},
    };

    *(int*)arg = 0;

    auto ret = genlmsg_parse(nlh, 0, tb, NCSI_ATTR_MAX, ncsiPolicy);
    if (!tb[NCSI_ATTR_PACKAGE_LIST])
    {
        lg2::error("No Packages");
        return -1;
    }

    auto attrTgt = static_cast<nlattr*>(nla_data(tb[NCSI_ATTR_PACKAGE_LIST]));
    if (!attrTgt)
    {
        lg2::error("Package list attribute is null");
        return -1;
    }

    auto rem = nla_len(tb[NCSI_ATTR_PACKAGE_LIST]);
    nla_for_each_nested(attrTgt, tb[NCSI_ATTR_PACKAGE_LIST], rem)
    {
        ret = nla_parse_nested(packagetb, NCSI_PKG_ATTR_MAX, attrTgt,
                               packagePolicy);
        if (ret < 0)
        {
            lg2::error("Failed to parse package nested");
            return -1;
        }

        if (packagetb[NCSI_PKG_ATTR_ID])
        {
            auto attrID = nla_get_u32(packagetb[NCSI_PKG_ATTR_ID]);
            lg2::debug("Package has id : {ATTR_ID}", "ATTR_ID", lg2::hex,
                       attrID);
        }
        else
        {
            lg2::debug("Package with no id");
        }

        if (packagetb[NCSI_PKG_ATTR_FORCED])
        {
            lg2::debug("This package is forced");
        }

        auto channelListTarget = static_cast<nlattr*>(
            nla_data(packagetb[NCSI_PKG_ATTR_CHANNEL_LIST]));

        auto channelrem = nla_len(packagetb[NCSI_PKG_ATTR_CHANNEL_LIST]);
        nla_for_each_nested(channelListTarget,
                            packagetb[NCSI_PKG_ATTR_CHANNEL_LIST], channelrem)
        {
            ret = nla_parse_nested(channeltb, NCSI_CHANNEL_ATTR_MAX,
                                   channelListTarget, channelPolicy);
            if (ret < 0)
            {
                lg2::error("Failed to parse channel nested");
                return -1;
            }

            if (channeltb[NCSI_CHANNEL_ATTR_ID])
            {
                auto channel = nla_get_u32(channeltb[NCSI_CHANNEL_ATTR_ID]);
                if (channeltb[NCSI_CHANNEL_ATTR_ACTIVE])
                {
                    lg2::debug("Channel Active : {CHANNEL}", "CHANNEL",
                               lg2::hex, channel);
                }
                else
                {
                    lg2::debug("Channel Not Active : {CHANNEL}", "CHANNEL",
                               lg2::hex, channel);
                }

                if (channeltb[NCSI_CHANNEL_ATTR_FORCED])
                {
                    lg2::debug("Channel is forced");
                }
            }
            else
            {
                lg2::debug("Channel with no ID");
            }

            if (channeltb[NCSI_CHANNEL_ATTR_VERSION_MAJOR])
            {
                auto major =
                    nla_get_u32(channeltb[NCSI_CHANNEL_ATTR_VERSION_MAJOR]);
                lg2::debug("Channel Major Version : {CHANNEL_MAJOR_VERSION}",
                           "CHANNEL_MAJOR_VERSION", lg2::hex, major);
            }
            if (channeltb[NCSI_CHANNEL_ATTR_VERSION_MINOR])
            {
                auto minor =
                    nla_get_u32(channeltb[NCSI_CHANNEL_ATTR_VERSION_MINOR]);
                lg2::debug("Channel Minor Version : {CHANNEL_MINOR_VERSION}",
                           "CHANNEL_MINOR_VERSION", lg2::hex, minor);
            }
            if (channeltb[NCSI_CHANNEL_ATTR_VERSION_STR])
            {
                auto str =
                    nla_get_string(channeltb[NCSI_CHANNEL_ATTR_VERSION_STR]);
                lg2::debug("Channel Version Str : {CHANNEL_VERSION_STR}",
                           "CHANNEL_VERSION_STR", str);
            }
            if (channeltb[NCSI_CHANNEL_ATTR_LINK_STATE])
            {
                auto link =
                    nla_get_u32(channeltb[NCSI_CHANNEL_ATTR_LINK_STATE]);
                lg2::debug("Channel Link State : {LINK_STATE}", "LINK_STATE",
                           lg2::hex, link);
            }
            if (channeltb[NCSI_CHANNEL_ATTR_VLAN_LIST])
            {
                lg2::debug("Active Vlan ids");
                auto vids = channeltb[NCSI_CHANNEL_ATTR_VLAN_LIST];
                auto vid = static_cast<nlattr*>(nla_data(vids));
                auto len = nla_len(vids);
                while (nla_ok(vid, len))
                {
                    auto id = nla_get_u16(vid);
                    lg2::debug("VID : {VLAN_ID}", "VLAN_ID", id);
                    vid = nla_next(vid, &len);
                }
            }
        }
    }
    return (int)NL_SKIP;
};

CallBack sendCallBack = [](struct nl_msg* msg, void* arg) {
    using namespace phosphor::network::ncsi;
    auto nlh = nlmsg_hdr(msg);
    struct nlattr* tb[NCSI_ATTR_MAX + 1] = {nullptr};
    static struct nla_policy ncsiPolicy[NCSI_ATTR_MAX + 1] = {
        {NLA_UNSPEC, 0, 0}, {NLA_U32, 0, 0}, {NLA_NESTED, 0, 0},
        {NLA_U32, 0, 0},    {NLA_U32, 0, 0}, {NLA_BINARY, 0, 0},
        {NLA_FLAG, 0, 0},   {NLA_U32, 0, 0}, {NLA_U32, 0, 0},
    };

    *(int*)arg = 0;

    auto ret = genlmsg_parse(nlh, 0, tb, NCSI_ATTR_MAX, ncsiPolicy);
    if (ret)
    {
        lg2::error("Failed to parse package");
        return ret;
    }

    if (tb[NCSI_ATTR_DATA] == nullptr)
    {
        lg2::error("Response: No data");
        return -1;
    }

    auto data_len = nla_len(tb[NCSI_ATTR_DATA]) - sizeof(NCSIPacketHeader);
    unsigned char* data =
        (unsigned char*)nla_data(tb[NCSI_ATTR_DATA]) + sizeof(NCSIPacketHeader);

    // Dump the response to stdout. Enhancement: option to save response data
    auto str = toHexStr(std::span<const unsigned char>(data, data_len));
    lg2::debug("Response {DATA_LEN} bytes: {DATA}", "DATA_LEN", data_len,
               "DATA", str);

    return 0;
};

// Global variable to hold the current NcsiDumpTransfer instance
NcsiDumpTransfer* currentTransfer = nullptr;

CallBack NcsiDumpCallBack = [](struct nl_msg* msg, void* arg) {
    *(int*)arg = 0;
    if (currentTransfer == nullptr)
    {
        lg2::error("No active transfer instance");
        return -1;
    }
    return currentTransfer->callback(msg);
};

int applyCmd(int ifindex, const Command& cmd, int package = DEFAULT_VALUE,
             int channel = DEFAULT_VALUE, int flags = NONE,
             CallBack function = nullptr)
{
    int cb_ret = 0;
    nlSocketPtr socket(nl_socket_alloc(), &::nl_socket_free);
    if (socket == nullptr)
    {
        lg2::error("Unable to allocate memory for the socket");
        return -ENOMEM;
    }

    auto ret = genl_connect(socket.get());
    if (ret < 0)
    {
        lg2::error("Failed to open the socket , RC : {RC}", "RC", ret);
        return ret;
    }

    auto driverID = genl_ctrl_resolve(socket.get(), "NCSI");
    if (driverID < 0)
    {
        lg2::error("Failed to resolve, RC : {RC}", "RC", ret);
        return driverID;
    }

    nlMsgPtr msg(nlmsg_alloc(), &::nlmsg_free);
    if (msg == nullptr)
    {
        lg2::error("Unable to allocate memory for the message");
        return -ENOMEM;
    }

    auto msgHdr = genlmsg_put(msg.get(), NL_AUTO_PORT, NL_AUTO_SEQ, driverID, 0,
                              flags, cmd.ncsi_cmd, 0);
    if (!msgHdr)
    {
        lg2::error("Unable to add the netlink headers , COMMAND : {COMMAND}",
                   "COMMAND", cmd.ncsi_cmd);
        return -ENOMEM;
    }

    if (package != DEFAULT_VALUE)
    {
        ret = nla_put_u32(msg.get(), ncsi_nl_attrs::NCSI_ATTR_PACKAGE_ID,
                          package);
        if (ret < 0)
        {
            lg2::error("Failed to set the attribute , RC : {RC} PACKAGE "
                       "{PACKAGE}",
                       "RC", ret, "PACKAGE", lg2::hex, package);
            return ret;
        }
    }

    if (channel != DEFAULT_VALUE)
    {
        ret = nla_put_u32(msg.get(), ncsi_nl_attrs::NCSI_ATTR_CHANNEL_ID,
                          channel);
        if (ret < 0)
        {
            lg2::error("Failed to set the attribute , RC : {RC} CHANNEL : "
                       "{CHANNEL}",
                       "RC", ret, "CHANNEL", lg2::hex, channel);
            return ret;
        }
    }

    ret = nla_put_u32(msg.get(), ncsi_nl_attrs::NCSI_ATTR_IFINDEX, ifindex);
    if (ret < 0)
    {
        lg2::error("Failed to set the attribute , RC : {RC} INTERFACE : "
                   "{INTERFACE}",
                   "RC", ret, "INTERFACE", lg2::hex, ifindex);
        return ret;
    }

    if ((cmd.ncsi_cmd == ncsi_nl_commands::NCSI_CMD_SET_PACKAGE_MASK) ||
        (cmd.ncsi_cmd == ncsi_nl_commands::NCSI_CMD_SET_CHANNEL_MASK))
    {
        if (cmd.payload.size() != sizeof(unsigned int))
        {
            lg2::error("Package/Channel mask must be 32-bits");
            return -EINVAL;
        }
        int maskAttr =
            cmd.ncsi_cmd == ncsi_nl_commands::NCSI_CMD_SET_PACKAGE_MASK
                ? NCSI_ATTR_PACKAGE_MASK
                : NCSI_ATTR_CHANNEL_MASK;
        ret = nla_put_u32(
            msg.get(), maskAttr,
            *(reinterpret_cast<const unsigned int*>(cmd.payload.data())));
        if (ret < 0)
        {
            lg2::error("Failed to set the mask attribute, RC : {RC}", "RC",
                       ret);
            return ret;
        }
    }
    else if (cmd.ncsi_cmd == ncsi_nl_commands::NCSI_CMD_SEND_CMD)
    {
        std::vector<unsigned char> pl(
            sizeof(NCSIPacketHeader) + cmd.payload.size());
        NCSIPacketHeader* hdr = (NCSIPacketHeader*)pl.data();

        std::copy(cmd.payload.begin(), cmd.payload.end(),
                  pl.begin() + sizeof(NCSIPacketHeader));

        hdr->type = cmd.operation;
        hdr->length = htons(cmd.payload.size());

        ret = nla_put(msg.get(), ncsi_nl_attrs::NCSI_ATTR_DATA, pl.size(),
                      pl.data());
        if (ret < 0)
        {
            lg2::error("Failed to set the data attribute, RC : {RC}", "RC",
                       ret);
            return ret;
        }

        nl_socket_disable_seq_check(socket.get());
    }

    if (function)
    {
        cb_ret = 1;

        // Add a callback function to the socket
        nl_socket_modify_cb(socket.get(), NL_CB_VALID, NL_CB_CUSTOM, function,
                            &cb_ret);
    }

    ret = nl_send_auto(socket.get(), msg.get());
    if (ret < 0)
    {
        lg2::error("Failed to send the message , RC : {RC}", "RC", ret);
        return ret;
    }

    do
    {
        ret = nl_recvmsgs_default(socket.get());
        if (ret < 0)
        {
            lg2::error("Failed to receive the message , RC : {RC}", "RC", ret);
            break;
        }
    } while (cb_ret);

    return ret;
}

} // namespace internal

int sendOemCommand(int ifindex, int package, int channel, int operation,
                   std::span<const unsigned char> payload)
{
    lg2::debug("Send OEM Command, CHANNEL : {CHANNEL} , PACKAGE : {PACKAGE}, "
               "INTERFACE_INDEX: {INTERFACE_INDEX}",
               "CHANNEL", lg2::hex, channel, "PACKAGE", lg2::hex, package,
               "INTERFACE_INDEX", lg2::hex, ifindex);
    if (!payload.empty())
    {
        lg2::debug("Payload: {PAYLOAD}", "PAYLOAD", toHexStr(payload));
    }

    return internal::applyCmd(
        ifindex,
        internal::Command(ncsi_nl_commands::NCSI_CMD_SEND_CMD, operation,
                          payload),
        package, channel, NONE, internal::sendCallBack);
}

int setChannel(int ifindex, int package, int channel)
{
    lg2::debug(
        "Set CHANNEL : {CHANNEL} , PACKAGE : {PACKAGE}, INTERFACE_INDEX: "
        "{INTERFACE_INDEX}",
        "CHANNEL", lg2::hex, channel, "PACKAGE", lg2::hex, package,
        "INTERFACE_INDEX", lg2::hex, ifindex);
    return internal::applyCmd(
        ifindex, internal::Command(ncsi_nl_commands::NCSI_CMD_SET_INTERFACE),
        package, channel);
}

int clearInterface(int ifindex)
{
    lg2::debug("ClearInterface , INTERFACE_INDEX : {INTERFACE_INDEX}",
               "INTERFACE_INDEX", lg2::hex, ifindex);
    return internal::applyCmd(
        ifindex, internal::Command(ncsi_nl_commands::NCSI_CMD_CLEAR_INTERFACE));
}

int getInfo(int ifindex, int package)
{
    lg2::debug(
        "Get Info , PACKAGE : {PACKAGE}, INTERFACE_INDEX: {INTERFACE_INDEX}",
        "PACKAGE", lg2::hex, package, "INTERFACE_INDEX", lg2::hex, ifindex);
    if (package == DEFAULT_VALUE)
    {
        return internal::applyCmd(
            ifindex, internal::Command(ncsi_nl_commands::NCSI_CMD_PKG_INFO),
            package, DEFAULT_VALUE, NLM_F_DUMP, internal::infoCallBack);
    }
    else
    {
        return internal::applyCmd(ifindex, ncsi_nl_commands::NCSI_CMD_PKG_INFO,
                                  package, DEFAULT_VALUE, NONE,
                                  internal::infoCallBack);
    }
}

int setPackageMask(int ifindex, unsigned int mask)
{
    lg2::debug(
        "Set Package Mask , INTERFACE_INDEX: {INTERFACE_INDEX} MASK: {MASK}",
        "INTERFACE_INDEX", lg2::hex, ifindex, "MASK", lg2::hex, mask);
    auto payload = std::span<const unsigned char>(
        reinterpret_cast<const unsigned char*>(&mask),
        reinterpret_cast<const unsigned char*>(&mask) + sizeof(decltype(mask)));
    return internal::applyCmd(
        ifindex, internal::Command(ncsi_nl_commands::NCSI_CMD_SET_PACKAGE_MASK,
                                   0, payload));
}

int setChannelMask(int ifindex, int package, unsigned int mask)
{
    lg2::debug(
        "Set Channel Mask , INTERFACE_INDEX: {INTERFACE_INDEX}, PACKAGE : {PACKAGE} MASK: {MASK}",
        "INTERFACE_INDEX", lg2::hex, ifindex, "PACKAGE", lg2::hex, package,
        "MASK", lg2::hex, mask);
    auto payload = std::span<const unsigned char>(
        reinterpret_cast<const unsigned char*>(&mask),
        reinterpret_cast<const unsigned char*>(&mask) + sizeof(decltype(mask)));
    return internal::applyCmd(
        ifindex,
        internal::Command(ncsi_nl_commands::NCSI_CMD_SET_CHANNEL_MASK, 0,
                          payload),
        package);
    return 0;
}

std::array<unsigned char, 12>
    generateDumpCmdPayload(uint32_t chunkNum, uint32_t dataHandle, bool isAbort)
{
    std::array<unsigned char, 12> payload = {0x00};

    if (chunkNum == 1)
    {
        // First chunk: Data Handle for core dump
        payload[3] = 0; // Opcode for the first chunk
        payload[8] = (dataHandle >> 24) & 0xFF;
        payload[9] = (dataHandle >> 16) & 0xFF;
        payload[10] = (dataHandle >> 8) & 0xFF;
        payload[11] = dataHandle;
    }
    else
    {
        if (isAbort)
        {
            // For subsequent chunks after abort: Use opcode for abort message
            payload[3] = 3; // Opcode for abort chunk
            payload[8] = (chunkNum >> 24) & 0xFF;
            payload[9] = (chunkNum >> 16) & 0xFF;
            payload[10] = (chunkNum >> 8) & 0xFF;
            payload[11] = chunkNum & 0xFF;
        }
        else
        {
            // For subsequent chunks: Use chunk number instead of data handle
            payload[3] = 2; // Opcode for next chunk
            payload[8] = (chunkNum >> 24) & 0xFF;
            payload[9] = (chunkNum >> 16) & 0xFF;
            payload[10] = (chunkNum >> 8) & 0xFF;
            payload[11] = chunkNum & 0xFF;
        }
    }

    return payload;
}

int fileDump(int ifindex, int package, int channel, const std::string& fileName,
             const std::string& dataHandleStr)
{
    constexpr auto ncsiCmdCoreDump = 0x4D;
    size_t processedLength = 0;
    uint32_t dataHandle;

    try
    {
        dataHandle = std::stoul(dataHandleStr, &processedLength, 16);
        if (processedLength != dataHandleStr.length())
        {
            lg2::error("Invalid data handle string: {DATA_HANDLE_STR}",
                       "DATA_HANDLE_STR", dataHandleStr);
            return -1;
        }
        if (dataHandle > std::numeric_limits<uint32_t>::max())
        {
            lg2::error("Data handle out of range for uint32_t: {DATA_HANDLE}",
                       "DATA_HANDLE", dataHandle);
            return -1;
        }
        // Check if the data handle matches known valid values
        if (dataHandle != internal::NCSI_CORE_DUMP_HANDLE &&
            dataHandle != internal::NCSI_CRASH_DUMP_HANDLE)
        {
            lg2::error(
                "Invalid data handle value. Expected NCSI_CORE_DUMP_HANDLE (0xFFFF0000) or NCSI_CRASH_DUMP_HANDLE (0xFFFF0001), got: {DATA_HANDLE}",
                "DATA_HANDLE", lg2::hex, dataHandle);
            return -1;
        }
    }
    catch (const std::invalid_argument& e)
    {
        lg2::error(
            "Invalid argument for data handle conversion: {DATA_HANDLE_STR}",
            "DATA_HANDLE_STR", dataHandleStr);
        return -1;
    }
    catch (const std::out_of_range& e)
    {
        lg2::error("Data handle out of range: {DATA_HANDLE_STR}",
                   "DATA_HANDLE_STR", dataHandleStr);
        return -1;
    }

    uint32_t chunkNum = 1;
    bool isTransferComplete = false;

    internal::NcsiDumpTransfer transfer(fileName);
    internal::currentTransfer = &transfer;

    while (!isTransferComplete)
    {
        std::array<unsigned char, 12> payload =
            generateDumpCmdPayload(chunkNum, dataHandle, transfer.isAbort());

        lg2::debug(
            "Send NCSI Command, CHANNEL : {CHANNEL} , PACKAGE : {PACKAGE}, "
            "INTERFACE_INDEX: {INTERFACE_INDEX}, NCSI_CMD : {NCSI_CMD}, Chunk Number: {CHUNK_NUM}",
            "CHANNEL", lg2::hex, channel, "PACKAGE", lg2::hex, package,
            "INTERFACE_INDEX", lg2::hex, ifindex, "NCSI_CMD", lg2::hex,
            ncsiCmdCoreDump, "CHUNK_NUM", chunkNum);
        lg2::debug("Payload: {PAYLOAD}", "PAYLOAD", toHexStr(payload));

        int result = internal::applyCmd(
            ifindex,
            internal::Command(ncsi_nl_commands::NCSI_CMD_SEND_CMD,
                              ncsiCmdCoreDump, payload),
            package, channel, NONE, internal::NcsiDumpCallBack);

        if (result < 0)
        {
            lg2::error(
                "Error sending command for chunk number {CHUNK_NUM}, stopping",
                "CHUNK_NUM", chunkNum);
            break;
        }

        // Debug the opcode before deciding the next action
        lg2::debug("Received Opcode: {OPCODE}", "OPCODE", lg2::hex,
                   transfer.getOpcode());

        // Check the opcode to determine the next action
        switch (transfer.getOpcode())
        {
            case 0x1: // Initial chunk
                if (chunkNum != 1)
                {
                    lg2::error(
                        "Unexpected chunk number for initial chunk: {CHUNK_NUM}",
                        "CHUNK_NUM", chunkNum);
                    return -1;
                }
                chunkNum++; // Proceed to the next chunk
                break;
            case 0x2:       // Middle chunk
                if (chunkNum <= 1)
                {
                    lg2::error(
                        "Invalid chunk number for middle chunk: {CHUNK_NUM}",
                        "CHUNK_NUM", chunkNum);
                    return -1;
                }
                chunkNum++;                // Proceed to the next chunk
                break;
            case 0x4:                      // Final chunk
            case 0x5:                      // Initial and final chunk
                isTransferComplete = true; // Transfer complete
                break;
            case 0x8:                      // Abort transfer
                lg2::error("Transfer aborted by NIC");
                transfer.setAbort(true);
                isTransferComplete = true; // Stop fetching more chunks
                break;
            default:
                lg2::error("Unexpected opcode: {OPCODE}", "OPCODE",
                           transfer.getOpcode());
                transfer.setAbort(true);
        }
    }

    return 0;
}

} // namespace ncsi
} // namespace network
} // namespace phosphor
