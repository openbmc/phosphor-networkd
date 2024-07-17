#include "ncsi_util.hpp"

#include "ncsi_stats.hpp"

#include <linux/ncsi.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/genl.h>
#include <netlink/netlink.h>

#include <phosphor-logging/lg2.hpp>
#include <stdplus/numeric/str.hpp>
#include <stdplus/str/buf.hpp>

#include <cstring>
#include <iostream>
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

// converts a 64-bit/32-bit big-endian integer to a host-endian integer
static NCSIControllerPacketStatsResponse
    convertStatsToHostEndianess(std::span<uint8_t> inVar)
{
    NCSIControllerPacketStatsResponse localVar{};
    localVar.header.MCID = inVar[0];
    localVar.header.revision = inVar[1];
    localVar.header.reserved = inVar[2];
    localVar.header.id = inVar[3];
    localVar.header.type = inVar[4];
    localVar.header.channel = inVar[5];
    std::memmove(&localVar.header.length, &inVar[6], 2);
    std::memmove(&localVar.header.rsvd[0], &inVar[8], 4);
    std::memmove(&localVar.header.rsvd[1], &inVar[12], 4);
    std::memmove(&localVar.response, &inVar[16], 2);
    std::memmove(&localVar.reason, &inVar[18], 2);
    std::memmove(&localVar.countersClearedFromLastReadMSB, &inVar[20], 4);
    std::memmove(&localVar.countersClearedFromLastReadLSB, &inVar[24], 4);
    std::memmove(&localVar.totalBytesRcvd, &inVar[28], 8);
    std::memmove(&localVar.totalBytesTx, &inVar[36], 8);
    std::memmove(&localVar.totalUnicastPktsRcvd, &inVar[44], 8);
    std::memmove(&localVar.totalMulticastPktsRcvd, &inVar[52], 8);
    std::memmove(&localVar.totalBroadcastPktsRcvd, &inVar[60], 8);
    std::memmove(&localVar.totalUnicastPktsTx, &inVar[68], 8);
    std::memmove(&localVar.totalMulticastPktsTx, &inVar[76], 8);
    std::memmove(&localVar.totalBroadcastPktsTx, &inVar[84], 8);
    std::memmove(&localVar.fcsReceiveErrs, &inVar[92], 4);
    std::memmove(&localVar.alignmentErrs, &inVar[96], 4);
    std::memmove(&localVar.falseCarrierDetections, &inVar[100], 4);
    std::memmove(&localVar.runtPktsRcvd, &inVar[104], 4);
    std::memmove(&localVar.jabberPktsRcvd, &inVar[108], 4);
    std::memmove(&localVar.pauseXOnFramesRcvd, &inVar[112], 4);
    std::memmove(&localVar.pauseXOffFramesRcvd, &inVar[116], 4);
    std::memmove(&localVar.pauseXOnFramesTx, &inVar[120], 4);
    std::memmove(&localVar.pauseXOffFramesTx, &inVar[124], 4);
    std::memmove(&localVar.singleCollisionTxFrames, &inVar[128], 4);
    std::memmove(&localVar.multipleCollisionTxFrames, &inVar[132], 4);
    std::memmove(&localVar.lateCollisionFrames, &inVar[136], 4);
    std::memmove(&localVar.excessiveCollisionFrames, &inVar[140], 4);
    std::memmove(&localVar.controlFramesRcvd, &inVar[144], 4);
    std::memmove(&localVar.rxFrame_64, &inVar[148], 4);
    std::memmove(&localVar.rxFrame_65_127, &inVar[152], 4);
    std::memmove(&localVar.rxFrame_128_255, &inVar[156], 4);
    std::memmove(&localVar.rxFrame_256_511, &inVar[160], 4);
    std::memmove(&localVar.rxFrame_512_1023, &inVar[164], 4);
    std::memmove(&localVar.rxFrame_1024_1522, &inVar[168], 4);
    std::memmove(&localVar.rxFrame_1523_9022, &inVar[172], 4);
    std::memmove(&localVar.txFrame_64, &inVar[176], 4);
    std::memmove(&localVar.txFrame_65_127, &inVar[180], 4);
    std::memmove(&localVar.txFrame_128_255, &inVar[184], 4);
    std::memmove(&localVar.txFrame_256_511, &inVar[188], 4);
    std::memmove(&localVar.txFrame_512_1023, &inVar[192], 4);
    std::memmove(&localVar.txFrame_1024_1522, &inVar[196], 4);
    std::memmove(&localVar.txFrame_1523_9022, &inVar[200], 4);
    std::memmove(&localVar.validBytesRcvd, &inVar[204], 8);
    std::memmove(&localVar.errRuntPacketsRcvd, &inVar[212], 4);
    std::memmove(&localVar.errJabberPacketsRcvd, &inVar[216], 4);
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

    return localVar;
}

// print the NCSI controller packet stats
static void
    printNCSIControllerPacketStats(NCSIControllerPacketStatsResponse& pResp)
{
    setlocale(LC_ALL, "");
    std::cout
        << "\nNIC statistics: " << "\nResponse: " << pResp.response
        << "\nReason: " << pResp.reason
        << "\nCounters cleared last read (MSB): "
        << pResp.countersClearedFromLastReadMSB
        << "\nCounters cleared last read (LSB): "
        << pResp.countersClearedFromLastReadLSB
        << "\nTotal Bytes Received: " << pResp.totalBytesRcvd
        << "\nTotal Bytes Transmitted: " << pResp.totalBytesTx
        << "\nTotal Unicast Packet Received: " << pResp.totalUnicastPktsRcvd
        << "\nTotal Multicast Packet Received: " << pResp.totalMulticastPktsRcvd
        << "\nTotal Broadcast Packet Received: " << pResp.totalBroadcastPktsRcvd
        << "\nTotal Unicast Packet Transmitted: " << pResp.totalUnicastPktsTx
        << "\nTotal Multicast Packet Transmitted: "
        << pResp.totalMulticastPktsTx
        << "\nTotal Broadcast Packet Transmitted: "
        << pResp.totalBroadcastPktsTx << "\nFCS Receive Errors: "
        << pResp.fcsReceiveErrs << "\nAlignment Errors: " << pResp.alignmentErrs
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

CallBack statsCallback = [](struct nl_msg* msg, void* arg) {
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

    auto data_len = nla_len(tb[NCSI_ATTR_DATA]) + sizeof(NCSIPacketHeader);

    uint8_t* data = (uint8_t*)nla_data(tb[NCSI_ATTR_DATA]);

    auto endianCorrect =
        convertStatsToHostEndianess(std::span<uint8_t>(data, data_len));

    std::cout << endianCorrect;

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

int getStats(int ifindex, int package)
{
    return internal::applyCmd(
        ifindex,
        internal::Command(ncsi_nl_commands::NCSI_CMD_SEND_CMD,
                          ncsiCmdGetStatistics),
        package, NONE, NONE, internal::statsCallback);
}

} // namespace ncsi
} // namespace network
} // namespace phosphor
