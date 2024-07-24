#include "ncsi_util.hpp"

#include <linux/ncsi.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/genl.h>
#include <netlink/netlink.h>

#include <phosphor-logging/lg2.hpp>
#include <stdplus/numeric/str.hpp>
#include <stdplus/str/buf.hpp>

#include <iomanip>
#include <iostream>
#include <vector>

namespace phosphor
{
namespace network
{
namespace ncsi
{

// NCSI PACKET TYPE
// Control packet type for Get Link Status
static constexpr auto ncsiCmdGetLinkStatus = 0x0a;

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

// Link status bit fields
static constexpr auto useExt = 0xf;
static constexpr auto useNRZ = 1;
static constexpr auto usePAMFour = 2;
static constexpr auto useSym = 1;
static constexpr auto useAsym = 2;
static constexpr auto useSymAsym = 3;

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

struct ncsiCompletionCodes
{
    uint16_t completionCodeResponse;
    uint16_t completionCodeReason;
};

// Get Link Status Response
// DSP0222 NCSI Spec 8.4.24

// Link status bits mask
static constexpr auto linkFlagMask = 0x00000001;
static constexpr auto speedDuplexMask = 0x0000001E;
static constexpr auto autoNegotiateEnMask = 0x00000020;
static constexpr auto autoNegoationCompleteMask = 0x00000040;
static constexpr auto parallelDetectionMask = 0x00000080;
static constexpr auto linkPartner1000FullDuplexMask = 0x00000200;
static constexpr auto linkPartner1000HalfDuplexMask = 0x00000400;
static constexpr auto linkPartner100T4Mask = 0x00000800;
static constexpr auto linkPartner100FullDuplexMask = 0x00001000;
static constexpr auto linkPartner100HalfDuplexMask = 0x00002000;
static constexpr auto linkPartner10FullDuplexMask = 0x00004000;
static constexpr auto linkPartner10HalfDuplexMask = 0x00008000;
static constexpr auto txFlowControlMask = 0x00010000;
static constexpr auto rxFlowControlMask = 0x00020000;
static constexpr auto linkPartnerFlowControlMask = 0x000C0000;
static constexpr auto serdesMask = 0x00100000;
static constexpr auto oemLinkSpeedValidMask = 0x00200000;
static constexpr auto modulationSchemeMask = 0x00C00000;
static constexpr auto extSpeedDuplexMask = 0xFF000000;

// Link status bits position
static constexpr auto linkFlagBitPos = 0;
static constexpr auto speedDuplexBitPos = 1;
static constexpr auto autoNegotiateEnBitPos = 5;
static constexpr auto autoNegoationCompleteBitPos = 6;
static constexpr auto parallelDetectionBitPos = 7;
static constexpr auto linkPartner1000FullDuplexBitPos = 9;
static constexpr auto linkPartner1000HalfDuplexBitPos = 10;
static constexpr auto linkPartner100T4BitPos = 11;
static constexpr auto linkPartner100FullDuplexBitPos = 12;
static constexpr auto linkPartner100HalfDuplexBitPos = 13;
static constexpr auto linkPartner10FullDuplexBitPos = 14;
static constexpr auto linkPartner10HalfDuplexBitPos = 15;
static constexpr auto txFlowControlBitPos = 16;
static constexpr auto rxFlowControlBitPos = 17;
static constexpr auto linkPartnerFlowControlBitPos = 18;
static constexpr auto serdesBitPos = 20;
static constexpr auto oemLinkSpeedValidBitPos = 21;
static constexpr auto modulationSchemeBitPos = 22;
static constexpr auto extSpeedDuplexBitPos = 24;

struct getLinkStatusResponse
{
    NCSIPacketHeader linkRespHdr;
    ncsiCompletionCodes linkStatCodes;
    uint32_t linkStatus;
    uint32_t otherIndications;
    uint32_t oemLinkStatus;
};

constexpr std::array<const char*, 21> linkSpeedString = {
    "n/a",
    "10BASE-T half-duplex",
    "10BASE-T full-duplex",
    "100BASE-TX half-duplex",
    "100BASE-T4",
    "100BASE-TX full-duplex",
    "1000BASE-T half-duplex",
    "1000BASE-T full-duplex",
    "10Gbps",
    "20Gbps",
    "25Gbps",
    "40Gbps",
    "50Gbps",
    "100Gbps",
    "2.5Gbps",
    "5Gbps",
    "1Gbps (non BASE-T)",
    "200Gbps",
    "400Gbps",
    "800Gbps",
    "reserved",
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

void printLinkStatus(const getLinkStatusResponse* linkRcv)
{
    unsigned int speed_duplex;

    lg2::debug("NCSI Response Code : {RESPONSE_CODE}", "RESPONSE_CODE",
               lg2::hex, linkRcv->linkStatCodes.completionCodeResponse);
    lg2::debug("NCSI Reason Code : {REASON_CODE}", "REASON_CODE", lg2::hex,
               linkRcv->linkStatCodes.completionCodeReason);

    lg2::debug(
        "Link Status : Link is {UP_DOWN}", "UP_DOWN",
        (linkRcv->linkStatus & linkFlagMask) >> linkFlagBitPos ? "Up" : "Down");

    speed_duplex =
        (((linkRcv->linkStatus & speedDuplexMask) >> speedDuplexBitPos) ==
         useExt)
            ? (linkRcv->linkStatus & extSpeedDuplexMask) >> extSpeedDuplexBitPos
            : (linkRcv->linkStatus & speedDuplexMask) >> speedDuplexBitPos;

    auto speedInd =
        std::find_if(linkSpeedString.begin(), linkSpeedString.end(),
                     [speed_duplex](const char*) {
                         return speed_duplex < linkSpeedString.size();
                     });

    lg2::debug("Speed and duplex : {SPEED_DUPLEX_STR}", "SPEED_DUPLEX_STR",
               (speedInd == linkSpeedString.end())
                   ? "Unknown"
                   : linkSpeedString[speed_duplex]);

    if ((linkRcv->linkStatus & autoNegotiateEnMask) >> autoNegotiateEnBitPos)
    {
        lg2::debug("Auto-negotiation : Enabled");
        lg2::debug("Auto-negotiation completed : {YES_NO}", "YES_NO",
                   (linkRcv->linkStatus & autoNegoationCompleteMask) >>
                           autoNegoationCompleteBitPos
                       ? "Yes"
                       : "No");
    }
    else
    {
        lg2::debug("Auto-negotiation : Disabled");
    }

    lg2::debug("Parallel Detection : {USED_NOTUSED}", "USED_NOTUSED",
               (linkRcv->linkStatus & parallelDetectionMask) >>
                       parallelDetectionBitPos
                   ? "Used"
                   : "Not used");

    lg2::debug("TX Flow Control : {ENABLE_DISABLE}", "ENABLE_DISABLE",
               (linkRcv->linkStatus & txFlowControlMask) >> txFlowControlBitPos
                   ? "Enabled"
                   : "Disabled");

    lg2::debug("RX Flow Control : {ENABLE_DISABLE}", "ENABLE_DISABLE",
               (linkRcv->linkStatus & rxFlowControlMask) >> rxFlowControlBitPos
                   ? "Enabled"
                   : "Disabled");

    lg2::debug("SerDes Status : {USED_NOTUSED}", "USED_NOTUSED",
               (linkRcv->linkStatus & serdesMask) >> serdesBitPos
                   ? "Used as Direct attach interface"
                   : "Not used/used to connect ext PHY");

    lg2::debug("OEM Link Speed setting : {VALID_INVALID}", "VALID_INVALID",
               (linkRcv->linkStatus & oemLinkSpeedValidMask) >>
                       oemLinkSpeedValidBitPos
                   ? "Valid"
                   : "Invalid");

    if (((linkRcv->linkStatus & modulationSchemeMask) >>
         modulationSchemeBitPos) == useNRZ)
    {
        lg2::debug("Modulation Scheme : NRZ");
    }
    else if (((linkRcv->linkStatus & modulationSchemeMask) >>
              modulationSchemeBitPos) == usePAMFour)
    {
        lg2::debug("Modulation Scheme : PAM4");
    }
    else
    {
        lg2::debug("Modulation Scheme : Unknown");
    }

    if (!((linkRcv->linkStatus & serdesMask) >> serdesBitPos) &&
        ((linkRcv->linkStatus & autoNegotiateEnMask) >>
         autoNegotiateEnBitPos) &&
        (linkRcv->linkStatus & autoNegoationCompleteMask) >>
            autoNegoationCompleteBitPos)
    {
        lg2::debug("Link Partner Advertised Settings :");
        lg2::debug("    Speed and Duplex 1000TFD : {CAPABILITY}", "CAPABILITY",
                   (linkRcv->linkStatus & linkPartner1000FullDuplexMask) >>
                           linkPartner1000FullDuplexBitPos
                       ? "Capable"
                       : "Not capable");

        lg2::debug("    Speed and Duplex 1000THD : {CAPABILITY}", "CAPABILITY",
                   (linkRcv->linkStatus & linkPartner1000HalfDuplexMask) >>
                           linkPartner1000HalfDuplexBitPos
                       ? "Capable"
                       : "Not capable");

        lg2::debug("    Speed and Duplex 100T4 : {CAPABILITY}", "CAPABILITY",
                   (linkRcv->linkStatus & linkPartner100T4Mask) >>
                           linkPartner100T4BitPos
                       ? "Capable"
                       : "Not capable");

        lg2::debug("    Speed and Duplex 100TXFD : {CAPABILITY}", "CAPABILITY",
                   (linkRcv->linkStatus & linkPartner100FullDuplexMask) >>
                           linkPartner100FullDuplexBitPos
                       ? "Capable"
                       : "Not capable");

        lg2::debug("    Speed and Duplex 100TXHD : {CAPABILITY}", "CAPABILITY",
                   (linkRcv->linkStatus & linkPartner100HalfDuplexMask) >>
                           linkPartner100HalfDuplexBitPos
                       ? "Capable"
                       : "Not capable");

        lg2::debug("    Speed and Duplex 10TFD : {CAPABILITY}", "CAPABILITY",
                   (linkRcv->linkStatus & linkPartner10FullDuplexMask) >>
                           linkPartner10FullDuplexBitPos
                       ? "Capable"
                       : "Not capable");

        lg2::debug("    Speed and Duplex 10THD : {CAPABILITY}", "CAPABILITY",
                   (linkRcv->linkStatus & linkPartner10HalfDuplexMask) >>
                           linkPartner10HalfDuplexBitPos
                       ? "Capable"
                       : "Not capable");

        if (((linkRcv->linkStatus & linkPartnerFlowControlMask) >>
             linkPartnerFlowControlBitPos) == useSym)
        {
            lg2::debug("    LinkPartner FlowControl : Symmetric");
        }
        else if (((linkRcv->linkStatus & linkPartnerFlowControlMask) >>
                  linkPartnerFlowControlBitPos) == useAsym)
        {
            lg2::debug("    LinkPartner FlowControl : Asymmetric");
        }
        else if (((linkRcv->linkStatus & linkPartnerFlowControlMask) >>
                  linkPartnerFlowControlBitPos) == useSymAsym)
        {
            lg2::debug("    LinkPartner FlowControl : Symmetric/Asymmetric");
        }
        else
        {
            lg2::debug("    LinkPartner FlowControl : Not capable");
        }
    }
    return;
}

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

CallBack linkStatusCallBack = [](struct nl_msg* msg, void* arg) {
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

    getLinkStatusResponse* linkResp =
        (getLinkStatusResponse*)nla_data(tb[NCSI_ATTR_DATA]);
    lg2::debug("NCSI Response packet type : {RESPONSE_PKT_TYPE}",
               "RESPONSE_PKT_TYPE", lg2::hex, linkResp->linkRespHdr.type);

    auto respHdrLen = htons(linkResp->linkRespHdr.length);
    lg2::debug("NCSI Response length : {RESPONSE_LEN}", "RESPONSE_LEN",
               lg2::hex, respHdrLen);

    // Convert link status response to Host Endianess
    linkResp->linkStatCodes.completionCodeResponse =
        ntohl(linkResp->linkStatCodes.completionCodeResponse);
    linkResp->linkStatCodes.completionCodeReason =
        ntohl(linkResp->linkStatCodes.completionCodeReason);
    linkResp->linkStatus = ntohl(linkResp->linkStatus);

    printLinkStatus(static_cast<const getLinkStatusResponse*>(linkResp));
    return 0;
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

    if (cmd.operation != DEFAULT_VALUE)
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

int getLinkStatus(int ifindex, int package, int channel)
{
    lg2::debug("Send NCSI Command, CHANNEL : {CHANNEL} , PACKAGE : {PACKAGE}, "
               "INTERFACE_INDEX: {INTERFACE_INDEX}",
               "CHANNEL", lg2::hex, channel, "PACKAGE", lg2::hex, package,
               "INTERFACE_INDEX", lg2::hex, ifindex);
    return internal::applyCmd(
        ifindex,
        internal::Command(ncsi_nl_commands::NCSI_CMD_SEND_CMD,
                          ncsiCmdGetLinkStatus),
        package, channel, NONE, internal::linkStatusCallBack);
}

} // namespace ncsi
} // namespace network
} // namespace phosphor
