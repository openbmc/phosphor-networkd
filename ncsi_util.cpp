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

using namespace phosphor::logging;
using namespace sdbusplus::xyz::openbmc_project::Common::Error;

using CallBack = int(*)(struct nl_msg* msg, void* arg);

namespace internal
{

using nlMsgPtr = std::unique_ptr<nl_msg, decltype(&::nlmsg_free)>;
using nlSocketPtr = std::unique_ptr<nl_sock, decltype(&::nl_socket_free)>;

CallBack infoCallBack =  [](struct nl_msg* msg, void* arg)
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

    struct nlattr* packagetb[package::ATTR_MAX + 1] = { nullptr };
    struct nla_policy packagePolicy[package::ATTR_MAX + 1] =
    {
        { type: NLA_UNSPEC },
        { type: NLA_NESTED },
        { type: NLA_U32 },
        { type: NLA_FLAG },
        { type: NLA_NESTED },
        { type: NLA_UNSPEC},
    };

    struct nlattr* channeltb[channel::ATTR_MAX + 1] = { nullptr };
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
        return -1;
    }

    auto attrTgt = static_cast<nlattr*>(nla_data(tb[attribute::PACKAGE_LIST]));
    if (!attrTgt)
    {
        log<level::ERR>("Package list attribute is null");
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
            return -1;
        }

        if (packagetb[package::ATTR_ID])
        {
            auto attrID = nla_get_u32(packagetb[package::ATTR_ID]);
            log<level::DEBUG>("Package having id",
                              entry("ID=%x", attrID));
        }
        else
        {
            log<level::DEBUG>("Package with no id\n");
        }

        if (packagetb[package::ATTR_FORCED])
        {
            log<level::DEBUG>("This package is forced\n");
        }

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
                return -1;
            }
            if (channeltb[channel::ATTR_ID])
            {
                auto channel = nla_get_u32(channeltb[channel::ATTR_ID]);
                if (channeltb[channel::ATTR_ACTIVE])
                {
                    log<level::DEBUG>("Channel Active",
                                      entry("CHANNEL=%x", channel));
                }
                else
                {
                    log<level::DEBUG>("Channel Not Active",
                                      entry("CHANNEL=%x", channel));
                }

            }
            else
            {
                log<level::DEBUG>("Channel with no ID");
            }

            if (channeltb[channel::ATTR_FORCED])
            {
                log<level::DEBUG>("Channel is forced");
            }

            if (channeltb[channel::ATTR_VERSION_MAJOR])
            {
                auto major = nla_get_u32(channeltb[channel::ATTR_VERSION_MAJOR]);
                log<level::DEBUG>("Channel Major Version",
                                  entry("VERSION=%x", major));
            }
            if (channeltb[channel::ATTR_VERSION_MINOR])
            {
                auto minor = nla_get_u32(channeltb[channel::ATTR_VERSION_MINOR]);
                log<level::DEBUG>("Channel Minor Version",
                                  entry("VERSION=%x", minor));
            }
            if (channeltb[channel::ATTR_VERSION_STR])
            {
                auto str = nla_get_string(channeltb[channel::ATTR_VERSION_STR]);
                log<level::DEBUG>("Channel Version Str",
                                  entry("VERSION=%s", str));
            }
            if (channeltb[channel::ATTR_LINK_STATE])
            {
                auto link = nla_get_u32(channeltb[channel::ATTR_LINK_STATE]);
                log<level::DEBUG>("Channel Link State",
                                  entry("STATE=%x", link));
            }
            if (channeltb[channel::ATTR_VLAN_LIST])
            {
                log<level::DEBUG>("Active Vlan ids");
                auto vids = channeltb[channel::ATTR_VLAN_LIST];
                auto vid = static_cast<nlattr*>(nla_data(vids));
                auto len = nla_len(vids);
                while (nla_ok(vid, len))
                {
                    auto id = nla_get_u16(vid);
                    log<level::DEBUG>("VID",
                                      entry("VID=%d", id));

                    vid = nla_next(vid, &len);
                }
            }

        }

    }
    return (int)NL_SKIP;
};

int applyCmd(int ifindex, int cmd, int package = DEFAULT_VALUE,
             int channel = DEFAULT_VALUE, int flags = NONE,
             CallBack function = nullptr)
{
    using namespace phosphor::network::ncsi;

    nlSocketPtr socket(nl_socket_alloc(),&::nl_socket_free);
    auto ret = genl_connect(socket.get());
    if (ret < 0)
    {
        log<level::ERR>("Failed to open the socket",
                        entry("RC=%d", ret));
        return ret;
    }

    auto driverID = genl_ctrl_resolve(socket.get(), "NCSI");
    if (driverID < 0)
    {
        log<level::ERR>("Failed to resolve",
                        entry("RC=%d", ret));
        return driverID;
    }

    nlMsgPtr msg(nlmsg_alloc(), &::nlmsg_free);

    if (package != DEFAULT_VALUE)
    {
        auto msgHdr = genlmsg_put(msg.get(), 0, 0, driverID, 0, flags,
                                  cmd, 0);
        if (!msgHdr)
        {
            log<level::ERR>("Unable to add the netlink headers",
                            entry("COMMAND=%d", cmd));
            return -1;
        }

        ret = nla_put_u32(msg.get(), attribute::PACKAGE_ID, package);
        if (ret < 0)
        {
            log<level::ERR>("Failed to set the attribute",
                            entry("RC=%d", ret),
                            entry("PACKAGE=%x", package));
            return ret;
        }
    }

    if (channel != DEFAULT_VALUE)
    {
        ret = nla_put_u32(msg.get(), attribute::CHANNEL_ID, channel);
        if (ret < 0)
        {
            log<level::ERR>("Failed to set the attribute",
                            entry("RC=%d", ret),
                            entry("CHANNEL=%x", channel));
            return ret;
        }
    }

    ret = nla_put_u32(msg.get(), attribute::IFINDEX, ifindex);
    if (ret < 0)
    {
        log<level::ERR>("Failed to set the attribute",
                        entry("RC=%d", ret),
                        entry("INTERFACE=%x", ifindex));
        return ret;
    }

    if (function)
    {
        // Add a callback function to the socket
        nl_socket_modify_cb(socket.get(), NL_CB_VALID, NL_CB_CUSTOM,
                            function, nullptr);
    }

    ret = nl_send_auto(socket.get(), msg.get());
    if (ret < 0)
    {
        log<level::ERR>("Failed to send the message",
                        entry("RC=%d", ret));
        return ret;
    }

    ret = nl_recvmsgs_default(socket.get());
    if (ret < 0)
    {
        log<level::ERR>("Failed to recieve the message",
                        entry("RC=%d", ret));
    }
    return ret;
}

}//namespace internal

int setChannel(int ifindex, int package, int channel)
{
    return internal::applyCmd(ifindex, command::SET_INTERFACE,
                              package, channel);
}

int clearInterface(int ifindex)
{
    return internal::applyCmd(ifindex,command::CLEAR_INTERFACE);
}

int getInfo(int ifindex, int package)
{
    if (package == DEFAULT_VALUE)
    {
        return internal::applyCmd(ifindex, command::PKG_INFO, package,
                                  DEFAULT_VALUE, NLM_F_DUMP,
                                  internal::infoCallBack);
    }
    else
    {
        return internal::applyCmd(ifindex, command::PKG_INFO, package,
                                  DEFAULT_VALUE, NONE,
                                  internal::infoCallBack);
    }
}

}//namespace ncsi
}//namespace network
}//namespace phosphor
