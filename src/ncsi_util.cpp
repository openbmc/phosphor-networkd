#include "ncsi_util.hpp"

#include <linux/ncsi.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/genl.h>
#include <netlink/netlink.h>

#include <phosphor-logging/lg2.hpp>

#include <optional>
#include <span>
#include <vector>

namespace phosphor
{
namespace network
{
namespace ncsi
{

NCSICommand::NCSICommand(uint8_t opcode, uint8_t package,
                         std::optional<uint8_t> channel,
                         std::span<unsigned char> payload) :
    opcode(opcode), package(package), channel(channel)
{
    this->payload.assign(payload.begin(), payload.end());
}

uint8_t NCSICommand::getChannel()
{
    return channel.value_or(CHANNEL_ID_NONE);
}

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

class NetlinkCommand
{
  public:
    NetlinkCommand() = delete;
    ~NetlinkCommand() = default;
    NetlinkCommand(const NetlinkCommand&) = delete;
    NetlinkCommand& operator=(const NetlinkCommand&) = delete;
    NetlinkCommand(NetlinkCommand&&) = default;
    NetlinkCommand& operator=(NetlinkCommand&&) = default;
    NetlinkCommand(
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

struct infoCallBackContext
{
    InterfaceInfo* info;
};

CallBack infoCallBack = [](struct nl_msg* msg, void* arg) {
    if (arg == nullptr)
    {
        lg2::error("Internal error: invalid info callback context");
        return -1;
    }

    struct infoCallBackContext* info = (struct infoCallBackContext*)arg;
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

        PackageInfo pkg;

        if (packagetb[NCSI_PKG_ATTR_ID])
        {
            auto attrID = nla_get_u32(packagetb[NCSI_PKG_ATTR_ID]);
            pkg.id = attrID;
        }
        else
        {
            lg2::debug("Package with no id");
        }

        if (packagetb[NCSI_PKG_ATTR_FORCED])
        {
            pkg.forced = true;
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
                continue;
            }

            ChannelInfo chan;

            if (channeltb[NCSI_CHANNEL_ATTR_ID])
            {
                chan.id = nla_get_u32(channeltb[NCSI_CHANNEL_ATTR_ID]);
                chan.active = !!channeltb[NCSI_CHANNEL_ATTR_ACTIVE];
                chan.forced = !!channeltb[NCSI_CHANNEL_ATTR_FORCED];
            }
            else
            {
                lg2::debug("Channel with no ID");
                continue;
            }

            if (channeltb[NCSI_CHANNEL_ATTR_VERSION_MAJOR])
            {
                chan.version_major =
                    nla_get_u32(channeltb[NCSI_CHANNEL_ATTR_VERSION_MAJOR]);
            }
            if (channeltb[NCSI_CHANNEL_ATTR_VERSION_MINOR])
            {
                chan.version_minor =
                    nla_get_u32(channeltb[NCSI_CHANNEL_ATTR_VERSION_MINOR]);
            }
            if (channeltb[NCSI_CHANNEL_ATTR_VERSION_STR])
            {
                chan.version =
                    nla_get_string(channeltb[NCSI_CHANNEL_ATTR_VERSION_STR]);
            }
            if (channeltb[NCSI_CHANNEL_ATTR_LINK_STATE])
            {
                chan.link_state =
                    nla_get_u32(channeltb[NCSI_CHANNEL_ATTR_LINK_STATE]);
            }
            if (channeltb[NCSI_CHANNEL_ATTR_VLAN_LIST])
            {
                auto vids = channeltb[NCSI_CHANNEL_ATTR_VLAN_LIST];
                auto vid = static_cast<nlattr*>(nla_data(vids));
                auto len = nla_len(vids);
                while (nla_ok(vid, len))
                {
                    auto id = nla_get_u16(vid);
                    chan.vlan_ids.push_back(id);
                    vid = nla_next(vid, &len);
                }
            }
            pkg.channels.push_back(chan);
        }

        info->info->packages.push_back(pkg);
    }
    return static_cast<int>(NL_STOP);
};

struct sendCallBackContext
{
    NCSIResponse resp;
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

    if (arg == nullptr)
    {
        lg2::error("Internal error: invalid send callback context");
        return -1;
    }

    struct sendCallBackContext* ctx = (struct sendCallBackContext*)arg;

    auto ret = genlmsg_parse(nlh, 0, tb, NCSI_ATTR_MAX, ncsiPolicy);
    if (ret)
    {
        lg2::error("Failed to parse message");
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

    /* todo: remaining members */
    ctx->resp.full_payload.assign(data, data + data_len);

    return 0;
};

int applyCmd(Interface& interface, const NetlinkCommand& cmd,
             int package = DEFAULT_VALUE, int channel = DEFAULT_VALUE,
             int flags = NONE, CallBack function = nullptr, void* arg = nullptr)
{
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

    ret = nla_put_u32(msg.get(), ncsi_nl_attrs::NCSI_ATTR_IFINDEX,
                      interface.ifindex);
    if (ret < 0)
    {
        lg2::error("Failed to set the attribute , RC : {RC} INTERFACE : "
                   "{INTERFACE}",
                   "RC", ret, "INTERFACE", interface);
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

    // Add a callback function to the socket
    enum nl_cb_kind cb_kind = function ? NL_CB_CUSTOM : NL_CB_DEFAULT;
    nl_socket_modify_cb(socket.get(), NL_CB_VALID, cb_kind, function, arg);

    ret = nl_send_auto(socket.get(), msg.get());
    if (ret < 0)
    {
        lg2::error("Failed to send the message , RC : {RC}", "RC", ret);
        return ret;
    }

    ret = nl_recvmsgs_default(socket.get());
    if (ret < 0)
    {
        lg2::error("Failed to receive the message , RC : {RC}", "RC", ret);
        return ret;
    }

    return static_cast<int>(NL_STOP);
}

} // namespace internal

std::string to_string(Interface& interface)
{
    return std::to_string(interface.ifindex);
}

std::optional<NCSIResponse> Interface::sendCommand(NCSICommand& cmd)
{
    lg2::debug("Send Command, CHANNEL : {CHANNEL} , PACKAGE : {PACKAGE}, "
               "INTERFACE: {INTERFACE}",
               "CHANNEL", lg2::hex, cmd.getChannel(), "PACKAGE", lg2::hex,
               cmd.package, "INTERFACE", this);

    internal::sendCallBackContext ctx{};

    internal::NetlinkCommand nl_cmd(ncsi_nl_commands::NCSI_CMD_SEND_CMD,
                                    cmd.opcode, cmd.payload);

    int rc = internal::applyCmd(*this, nl_cmd, cmd.package, cmd.getChannel(),
                                NONE, internal::sendCallBack, &ctx);

    if (rc < 0)
    {
        return {};
    }

    return ctx.resp;
}

int Interface::setChannel(int package, int channel)
{
    lg2::debug("Set CHANNEL : {CHANNEL} , PACKAGE : {PACKAGE}, INTERFACE : "
               "{INTERFACE}",
               "CHANNEL", lg2::hex, channel, "PACKAGE", lg2::hex, package,
               "INTERFACE", this);

    internal::NetlinkCommand cmd(ncsi_nl_commands::NCSI_CMD_SET_INTERFACE);

    return internal::applyCmd(*this, cmd, package, channel);
}

int Interface::clearInterface()
{
    lg2::debug("ClearInterface , INTERFACE : {INTERFACE}", "INTERFACE", this);

    internal::NetlinkCommand cmd(ncsi_nl_commands::NCSI_CMD_CLEAR_INTERFACE);
    return internal::applyCmd(*this, cmd);
}

std::optional<InterfaceInfo> Interface::getInfo(int package)
{
    int rc, flags = package == DEFAULT_VALUE ? NLM_F_DUMP : NONE;
    InterfaceInfo info;

    lg2::debug("Get Info , PACKAGE : {PACKAGE}, INTERFACE: {INTERFACE}",
               "PACKAGE", lg2::hex, package, "INTERFACE", this);

    struct internal::infoCallBackContext ctx = {
        .info = &info,
    };

    internal::NetlinkCommand cmd(ncsi_nl_commands::NCSI_CMD_PKG_INFO);

    rc = internal::applyCmd(*this, cmd, package, DEFAULT_VALUE, flags,
                            internal::infoCallBack, &ctx);

    if (rc < 0)
    {
        return {};
    }

    return info;
}

int Interface::setPackageMask(unsigned int mask)
{
    lg2::debug("Set Package Mask , INTERFACE: {INTERFACE} MASK: {MASK}",
               "INTERFACE", this, "MASK", lg2::hex, mask);
    auto payload = std::span<const unsigned char>(
        reinterpret_cast<const unsigned char*>(&mask),
        reinterpret_cast<const unsigned char*>(&mask) + sizeof(decltype(mask)));

    internal::NetlinkCommand cmd(ncsi_nl_commands::NCSI_CMD_SET_PACKAGE_MASK, 0,
                                 payload);
    return internal::applyCmd(*this, cmd);
}

int Interface::setChannelMask(int package, unsigned int mask)
{
    lg2::debug(
        "Set Channel Mask , INTERFACE: {INTERFACE}, PACKAGE : {PACKAGE} MASK: {MASK}",
        "INTERFACE", this, "PACKAGE", lg2::hex, package, "MASK", lg2::hex,
        mask);
    auto payload = std::span<const unsigned char>(
        reinterpret_cast<const unsigned char*>(&mask),
        reinterpret_cast<const unsigned char*>(&mask) + sizeof(decltype(mask)));

    internal::NetlinkCommand cmd(ncsi_nl_commands::NCSI_CMD_SET_CHANNEL_MASK, 0,
                                 payload);
    return internal::applyCmd(*this, cmd);
}

} // namespace ncsi
} // namespace network
} // namespace phosphor
