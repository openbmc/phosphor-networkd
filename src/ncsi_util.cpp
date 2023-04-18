#include "ncsi_util.hpp"

#include <fmt/format.h>
#include <linux/ncsi.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/genl.h>
#include <netlink/netlink.h>

#include <iomanip>
#include <iostream>
#include <phosphor-logging/lg2.hpp>
#include <vector>

namespace phosphor
{
namespace network
{
namespace ncsi
{

PHOSPHOR_LOG2_USING_WITH_FLAGS;
using CallBack = int (*)(struct nl_msg* msg, void* arg);

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
        int c, int nc = DEFAULT_VALUE,
        std::span<const unsigned char> p = std::span<const unsigned char>()) :
        cmd(c),
        ncsi_cmd(nc), payload(p)
    {
    }

    int cmd;
    int ncsi_cmd;
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
        error("No Packages");
        return -1;
    }

    auto attrTgt = static_cast<nlattr*>(nla_data(tb[NCSI_ATTR_PACKAGE_LIST]));
    if (!attrTgt)
    {
        error("Package list attribute is null");
        return -1;
    }

    auto rem = nla_len(tb[NCSI_ATTR_PACKAGE_LIST]);
    nla_for_each_nested(attrTgt, tb[NCSI_ATTR_PACKAGE_LIST], rem)
    {
        ret = nla_parse_nested(packagetb, NCSI_PKG_ATTR_MAX, attrTgt,
                               packagePolicy);
        if (ret < 0)
        {
            error("Failed to parse package nested");
            return -1;
        }

        if (packagetb[NCSI_PKG_ATTR_ID])
        {
            auto attrID = nla_get_u32(packagetb[NCSI_PKG_ATTR_ID]);
            debug("Package has id : {ATTRID}", "ATTRID",
                  fmt::format("{:x}", attrID));
        }
        else
        {
            debug("Package with no id");
        }

        if (packagetb[NCSI_PKG_ATTR_FORCED])
        {
            debug("This package is forced");
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
                error("Failed to parse channel nested");
                return -1;
            }

            if (channeltb[NCSI_CHANNEL_ATTR_ID])
            {
                auto channel = nla_get_u32(channeltb[NCSI_CHANNEL_ATTR_ID]);
                if (channeltb[NCSI_CHANNEL_ATTR_ACTIVE])
                {
                    debug("Channel Active : {CHANNEL}", "CHANNEL",
                          fmt::format("{:x}", channel));
                }
                else
                {
                    debug("Channel Not Active : {CHANNEL}", "CHANNEL",
                          fmt::format("{:x}", channel));
                }

                if (channeltb[NCSI_CHANNEL_ATTR_FORCED])
                {
                    debug("Channel is forced");
                }
            }
            else
            {
                debug("Channel with no ID");
            }

            if (channeltb[NCSI_CHANNEL_ATTR_VERSION_MAJOR])
            {
                auto major =
                    nla_get_u32(channeltb[NCSI_CHANNEL_ATTR_VERSION_MAJOR]);
                debug("Channel Major Version : {CHANNEL_MAJOR_VERSION}",
                      "CHANNEL_MAJOR_VERSION", fmt::format("{:x}", major));
            }
            if (channeltb[NCSI_CHANNEL_ATTR_VERSION_MINOR])
            {
                auto minor =
                    nla_get_u32(channeltb[NCSI_CHANNEL_ATTR_VERSION_MINOR]);
                debug("Channel Minor Version : {CHANNEL_MINOR_VERSION}",
                      "CHANNEL_MINOR_VERSION", fmt::format("{:x}", minor));
            }
            if (channeltb[NCSI_CHANNEL_ATTR_VERSION_STR])
            {
                auto str =
                    nla_get_string(channeltb[NCSI_CHANNEL_ATTR_VERSION_STR]);
                debug("Channel Version Str : {CHANNEL_VERSION_STR}",
                      "CHANNEL_VERSION_STR", str);
            }
            if (channeltb[NCSI_CHANNEL_ATTR_LINK_STATE])
            {

                auto link =
                    nla_get_u32(channeltb[NCSI_CHANNEL_ATTR_LINK_STATE]);
                debug("Channel Link State : {LINK_STATE}", "LINK_STATE",
                      fmt::format("{:x}", link));
            }
            if (channeltb[NCSI_CHANNEL_ATTR_VLAN_LIST])
            {
                debug("Active Vlan ids");
                auto vids = channeltb[NCSI_CHANNEL_ATTR_VLAN_LIST];
                auto vid = static_cast<nlattr*>(nla_data(vids));
                auto len = nla_len(vids);
                while (nla_ok(vid, len))
                {
                    auto id = nla_get_u16(vid);
                    debug("VID : {VLAN_ID}", "VLAN_ID", id);
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
        error("Failed to parse package");
        return ret;
    }

    if (tb[NCSI_ATTR_DATA] == nullptr)
    {
        error("Response: No data");
        return -1;
    }

    auto data_len = nla_len(tb[NCSI_ATTR_DATA]) - sizeof(NCSIPacketHeader);
    unsigned char* data =
        (unsigned char*)nla_data(tb[NCSI_ATTR_DATA]) + sizeof(NCSIPacketHeader);
    auto s = std::span<const unsigned char>(data, data_len);

    // Dump the response to stdout. Enhancement: option to save response data
    debug("Response : {DATA_LEN} bytes", "DATA_LEN",
          fmt::format("{:d}", data_len));
    debug("{DATA}", "DATA",
          fmt::format("{:02x}", fmt::join(s.begin(), s.end(), " ")));

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
        error("Unable to allocate memory for the socket");
        return -ENOMEM;
    }

    auto ret = genl_connect(socket.get());
    if (ret < 0)
    {
        error("Failed to open the socket , RC : {RETURN_CODE}", "RETURN_CODE",
              ret);
        return ret;
    }

    auto driverID = genl_ctrl_resolve(socket.get(), "NCSI");
    if (driverID < 0)
    {
        error("Failed to resolve, RC : {RETURN_CODE}", "RETURN_CODE", ret);
        return driverID;
    }

    nlMsgPtr msg(nlmsg_alloc(), &::nlmsg_free);
    if (msg == nullptr)
    {
        error("Unable to allocate memory for the message");
        return -ENOMEM;
    }

    auto msgHdr = genlmsg_put(msg.get(), 0, 0, driverID, 0, flags, cmd.cmd, 0);
    if (!msgHdr)
    {
        error("Unable to add the netlink headers , COMMAND : {COMMAND}",
              "COMMAND", cmd.cmd);
        return -ENOMEM;
    }

    if (package != DEFAULT_VALUE)
    {
        ret = nla_put_u32(msg.get(), ncsi_nl_attrs::NCSI_ATTR_PACKAGE_ID,
                          package);
        if (ret < 0)
        {
            error("Failed to set the attribute , RC : {RETURN_CODE} PACKAGE "
                  "{PACKAGE}",
                  "RETURN_CODE", ret, "PACKAGE", fmt::format("{:x}", package));
            return ret;
        }
    }

    if (channel != DEFAULT_VALUE)
    {
        ret = nla_put_u32(msg.get(), ncsi_nl_attrs::NCSI_ATTR_CHANNEL_ID,
                          channel);
        if (ret < 0)
        {
            error("Failed to set the attribute , RC : {RETURN_CODE} CHANNEL : "
                  "{CHANNEL}",
                  "RETURN_CODE", ret, "CHANNEL", fmt::format("{:x}", channel));
            return ret;
        }
    }

    ret = nla_put_u32(msg.get(), ncsi_nl_attrs::NCSI_ATTR_IFINDEX, ifindex);
    if (ret < 0)
    {
        error("Failed to set the attribute , RC : {RETURN_CODE} INTERFACE : "
              "{INTERFACE}",
              "RETURN_CODE", ret, "INTERFACE", fmt::format("{:x}", ifindex));
        return ret;
    }

    if (cmd.ncsi_cmd != DEFAULT_VALUE)
    {
        std::vector<unsigned char> pl(sizeof(NCSIPacketHeader) +
                                      cmd.payload.size());
        NCSIPacketHeader* hdr = (NCSIPacketHeader*)pl.data();

        std::copy(cmd.payload.begin(), cmd.payload.end(),
                  pl.begin() + sizeof(NCSIPacketHeader));

        hdr->type = cmd.ncsi_cmd;
        hdr->length = htons(cmd.payload.size());

        ret = nla_put(msg.get(), ncsi_nl_attrs::NCSI_ATTR_DATA, pl.size(),
                      pl.data());
        if (ret < 0)
        {
            error("Failed to set the data attribute, RC : {RETURN_CODE}",
                  "RETURN_CODE", ret);
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
        error("Failed to send the message , RC : {RETURN_CODE}", "RETURN_CODE",
              ret);
        return ret;
    }

    do
    {
        ret = nl_recvmsgs_default(socket.get());
        if (ret < 0)
        {
            error("Failed to receive the message , RC : {RETURN_CODE}",
                  "RETURN_CODE", ret);
            break;
        }
    } while (cb_ret);

    return ret;
}

} // namespace internal

int sendOemCommand(int ifindex, int package, int channel,
                   std::span<const unsigned char> payload)
{
    constexpr auto cmd = 0x50;

    debug("Send OEM Command, CHANNEL : {CHANNEL} , PACKAGE : {PACKAGE}, "
          "IFINDEX: {IFINDEX}",
          "CHANNEL", fmt::format("{:x}", channel), "PACKAGE",
          fmt::format("{:x}", package), "IFINDEX",
          fmt::format("{:x}", ifindex));
    if (!payload.empty())
    {
        std::string payloadStr;
        for (auto& i : payload)
        {
            payloadStr += fmt::format(" {:02x}", (int)i);
        }
        debug("Payload :{PAYLOAD}", "PAYLOAD", payloadStr);
    }

    return internal::applyCmd(
        ifindex,
        internal::Command(ncsi_nl_commands::NCSI_CMD_SEND_CMD, cmd, payload),
        package, channel, NONE, internal::sendCallBack);
}

int setChannel(int ifindex, int package, int channel)
{
    debug("Set CHANNEL : {CHANNEL} , PACKAGE : {PACKAGE}, IFINDEX: {IFINDEX}",
          "CHANNEL", fmt::format("{:x}", channel), "PACKAGE",
          fmt::format("{:x}", package), "IFINDEX",
          fmt::format("{:x}", ifindex));
    return internal::applyCmd(
        ifindex, internal::Command(ncsi_nl_commands::NCSI_CMD_SET_INTERFACE),
        package, channel);
}

int clearInterface(int ifindex)
{
    debug("ClearInterface , IFINDEX : {IFINDEX}", "IFINDEX",
          fmt::format("{:x}", ifindex));
    return internal::applyCmd(
        ifindex, internal::Command(ncsi_nl_commands::NCSI_CMD_CLEAR_INTERFACE));
}

int getInfo(int ifindex, int package)
{
    debug("Get Info , PACKAGE : {PACKAGE}, IFINDEX: {IFINDEX}", "PACKAGE",
          fmt::format("{:x}", package), "IFINDEX",
          fmt::format("{:x}", ifindex));
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

} // namespace ncsi
} // namespace network
} // namespace phosphor
