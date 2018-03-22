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

}// namespace internal

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
