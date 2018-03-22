#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>

#include "ncsi_util.hpp"
#include "xyz/openbmc_project/Common/error.hpp"

#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/log.hpp>

namespace phosphor
{
namespace network
{
namespace ncsi
{

using nlMsgPtr = std::unique_ptr<nl_msg, decltype(&::nlmsg_free)>;
using nlSocketPtr = std::unique_ptr<nl_sock, decltype(&::nl_socket_free)>;

using namespace phosphor::logging;
using namespace sdbusplus::xyz::openbmc_project::Common::Error;

namespace internal
{

// Dummy callback
// TODO:- will remove this but just confirm with
// sam on this.
static int dumpCallback(struct nl_msg *msg, void *arg)
{
    using namespace phosphor::network::ncsi;
    auto gnlh = static_cast<struct genlmsghdr*>(nlmsg_data(nlmsg_hdr(msg)));
    struct nlattr *tb[attribute::MAX + 1] = { nullptr };
    nla_parse(tb, attribute::MAX, genlmsg_attrdata(gnlh, 0),
              genlmsg_attrlen(gnlh, 0), nullptr);

    //print(tb);
    return NL_SKIP;
}

static int infoCallback(struct nl_msg *msg, void *arg)
{
    using namespace phosphor::network::ncsi;
    auto nlh = nlmsg_hdr(msg);

    struct nlattr* tb[attribute::MAX + 1] = { nullptr };
    struct nla_policy ncsiPolicy[attribute::MAX + 1] =
    {
        { type: NLA_UNSPEC },
        { type: NLA_U32 },
        { type: NLA_NESTED },
        { type: NLA_U32 },
        { type: NLA_U32 },
    };

    struct nlattr *packagetb[package::ATTR_MAX + 1] = { nullptr };
    struct nla_policy packagePolicy[package::ATTR_MAX + 1] =
    {
        { type: NLA_UNSPEC },
        { type: NLA_NESTED },
        { type: NLA_U32 },
        { type: NLA_FLAG },
        { type: NLA_NESTED },
        { type: NLA_UNSPEC},
    };
    struct nlattr *channeltb[channel::ATTR_MAX + 1] = { nullptr };
    struct nla_policy channelPolicy[channel::ATTR_MAX + 1] =
    {
        { type: NLA_UNSPEC },
        { type: NLA_NESTED },
        { type: NLA_U32 },
        { type: NLA_FLAG },
        { type: NLA_NESTED },
        { type: NLA_UNSPEC},
    };

    auto ret = genlmsg_parse(nlh, 0, tb, attribute::MAX, ncsiPolicy);
    if (!tb[attribute::PACKAGE_LIST])
    {
        log<level::ERR>("No Packages");
        printf("No Packages\n");
        return -1;
    }

    auto attrTgt = static_cast<nlattr*>(nla_data(tb[attribute::PACKAGE_LIST]));
    if (!attrTgt)
    {
        printf("Attribute Target is null\n");
        return -1;
    }
    auto rem = nla_len(tb[attribute::PACKAGE_LIST]);
    nla_for_each_nested(attrTgt, tb[attribute::PACKAGE_LIST], rem)
    {
        ret = nla_parse_nested(packagetb, package::ATTR_MAX, attrTgt,
                               packagePolicy);
        if (ret < 0)
        {
            log<level::ERR>("Failed to parse package nested");
            printf("Failed to parse package nested\n");
            return -1;
        }

        if (packagetb[package::ATTR_ID])
        {
            auto attrID = nla_get_u32(packagetb[package::ATTR_ID]);
            log<level::DEBUG>("Package having id",
                              entry("ID=%d", attrID));
            printf("Package ID=[%d]\n", attrID);
        }
        else
        {
            log<level::DEBUG>("Package with no id\n");
            printf("Package with no id\n");
        }

        if (packagetb[package::ATTR_FORCED])
        {
            log<level::DEBUG>("This package is forced\n");
            printf("This package is forced\n");
        }
        printf("===================\n");
        auto channelListTarget = static_cast<nlattr*>(
                nla_data(packagetb[package::ATTR_CHANNEL_LIST]));

        auto channelrem = nla_len(packagetb[package::ATTR_CHANNEL_LIST]);
        nla_for_each_nested(channelListTarget,
                            packagetb[package::ATTR_CHANNEL_LIST], channelrem)
        {
            ret = nla_parse_nested(channeltb, channel::ATTR_MAX,
                                   channelListTarget, channelPolicy);
            if (ret < 0)
            {
                log<level::ERR>("Failed to parse channel nested");
                printf("Failed to parse channel nested\n");
                return -1;
            }
            if (channeltb[channel::ATTR_ID])
            {
                auto channel = nla_get_u32(channeltb[channel::ATTR_ID]);
                if (channeltb[channel::ATTR_ACTIVE])
                {
                    log<level::DEBUG>("Channel Active",
                                      entry("CHANNEL=%d", channel));
                    printf("Channel=[%d] active\n",channel);
                }

            }
            else
            {
                log<level::DEBUG>("Channel with no ID");
                printf("Channel with no id\n");
            }
            if (channeltb[channel::ATTR_VERSION_MAJOR])
            {
                auto major = nla_get_u32(channeltb[channel::ATTR_VERSION_MAJOR]);
                log<level::DEBUG>("Channel Major Version",
                                  entry("VERSION=%d", major));
                printf("Channel Major Version=[%d]\n", major);
            }
            if (channeltb[channel::ATTR_VERSION_MINOR])
            {
                auto minor = nla_get_u32(channeltb[channel::ATTR_VERSION_MINOR]);
                log<level::DEBUG>("Channel Minor Version",
                                  entry("VERSION=%d", minor));
                printf("Channel Minor Version=[%d]\n", minor);
            }
            if (channeltb[channel::ATTR_VERSION_STR])
            {
                auto str = nla_get_string(channeltb[channel::ATTR_VERSION_STR]);
                log<level::DEBUG>("Channel Version Str",
                                  entry("VERSION=%s", str));
                printf("Channel Version Str=[%s]\n", str);
            }
            if (channeltb[channel::ATTR_LINK_STATE])
            {
                auto link = nla_get_u32(channeltb[channel::ATTR_LINK_STATE]);
                log<level::DEBUG>("Channel Link State",
                                  entry("STATE=%d", link));
                printf("Channel Link State=[%d]\n", link);
            }
            if (channeltb[channel::ATTR_VLAN_LIST])
            {
                printf("Active Vlan ids:\n");
                log<level::DEBUG>("Active Vlan ids");
                auto vids = channeltb[channel::ATTR_VLAN_LIST];
                auto vid = static_cast<nlattr*>(nla_data(vids));
                auto len = nla_len(vids);
                while (nla_ok(vid, len))
                {
                    auto id = nla_get_u16(vid);
                    printf("VID=%d", id);
                    log<level::DEBUG>("VID",
                                      entry("VID=%d", id));

                    vid = nla_next(vid, &len);
                }
            }

        }

    }
    return NL_SKIP;
}

}// namespace internal

int getInfo(int ifindex, int package)
{
    // Open socket to kernel
    nlSocketPtr socket(nl_socket_alloc(),&::nl_socket_free);

    auto ret = genl_connect(socket.get());
    if (ret < 0)
    {
        log<level::ERR>("Failed to open the socket",
                        entry("RC=%d", ret));
        printf("Failed to open socket: rc=[%d]", ret);
        return -1;
    }

    // Find NCSI
    auto driverID = genl_ctrl_resolve(socket.get() , "NCSI");
    if (driverID < 0)
    {
        log<level::ERR>("Could not resolve NCSI",
                        entry("RC=%d", ret));
        printf("Could not resolve NCSI");
        return -1;
    }

    // Setup up a Generic Netlink message
    nlMsgPtr msg(nlmsg_alloc(), &::nlmsg_free);
    if (package < 0)
    {
        genlmsg_put(msg.get(), 0, 0, driverID, 0, NLM_F_DUMP,
                    command::PKG_INFO, 0);
    }
    else
    {
        genlmsg_put(msg.get(), 0, 0, driverID, 0, 0, command::PKG_INFO, 0);

        nla_put_u32(msg.get(), attribute::PACKAGE_ID, package);
    }

    nla_put_u32(msg.get(), attribute::IFINDEX, ifindex);

    // Add a callback function to the socket
    nl_socket_modify_cb(socket.get(), NL_CB_VALID, NL_CB_CUSTOM,
                        phosphor::network::ncsi::internal::infoCallback,
                        nullptr);

    ret = nl_send_auto(socket.get(), msg.get());
    if (ret < 0)
    {
        log<level::ERR>("Failed to send the message",
                        entry("RC=%d", ret));
        printf("Failed to send message: ret=[%d]", ret);
        return ret;
    }

    ret = nl_recvmsgs_default(socket.get()); // # blocks
    if (ret < 0)
    {
        log<level::ERR>("Failed to recieve message",
                        entry("RC=%d", ret));
        printf("recvmsg returned: ret=[%d]", ret);
    }

    return ret;
}

int setChannel( int ifindex, int package, int channel)
{
    nlSocketPtr socket(nl_socket_alloc(),&::nl_socket_free);
    auto ret = genl_connect(socket.get());
    if (ret < 0)
    {
        log<level::ERR>("Failed to open the socket",
                        entry("RC=%d", ret));
        printf("Failed to open the socket: ret=[%d]\n", ret);

        return ret;
    }

    auto driverID = genl_ctrl_resolve(socket.get(), "NCSI");
    if (driverID < 0)
    {
        log<level::ERR>("Failed to resolve",
                        entry("RC=%d", ret));
        printf("Failed to Resolve: rc=[%d]\n", ret);
        return driverID;
    }

    nlMsgPtr msg(nlmsg_alloc(), &::nlmsg_free);
    printf("Package=%d,Channel=%d\n", package, channel);

    if (package < 0 && channel < 0)
    {
        auto msgHdr = genlmsg_put(msg.get(), 0, 0, driverID, 0, 0,
                                  command::CLEAR_INTERFACE, 0);
        if (!msgHdr)
        {
            log<level::ERR>("Unable to add the netlink headers",
                             entry("COMMAND=%d", command::CLEAR_INTERFACE));
            printf("Unable to add the netlink headers\n");
            return -1;
        }

    }
    if (package >= 0 )
    {
        auto msgHdr = genlmsg_put(msg.get(), 0, 0, driverID, 0, 0,
                                  command::SET_INTERFACE, 0);
        if (!msgHdr)
        {
            log<level::ERR>("Unable to add the netlink headers",
                    entry("COMMAND=%d", command::SET_INTERFACE));
            printf("Unable to add the netlink headers\n");
            return -1;
        }

        ret = nla_put_u32(msg.get(), attribute::PACKAGE_ID, package);
    }
    if (channel >= 0)
    {
        ret = nla_put_u32(msg.get(), attribute::CHANNEL_ID, channel);

    }

    ret = nla_put_u32(msg.get(), attribute::IFINDEX, ifindex);

    nl_socket_modify_cb(socket.get(), NL_CB_VALID, NL_CB_CUSTOM,
                        phosphor::network::ncsi::internal::dumpCallback,
                        nullptr);

    ret = nl_send_auto(socket.get(), msg.get());
    if (ret < 0)
    {
        log<level::ERR>("Failed to send the message",
                        entry("RC=%d", ret));
        return ret;
    }

    ret = nl_recvmsgs_default(socket.get()); // blocks
    if (ret < 0)
    {
        log<level::ERR>("Failed to recieve the message",
                        entry("RC=%d", ret));
    }
    return ret;
}

}//namespace ncsi
}//namespace network
}//namespace phosphor
