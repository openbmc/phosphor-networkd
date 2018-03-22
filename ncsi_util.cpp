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

namespace internal
{

constexpr auto DEFAULT_VALUE = -1;
constexpr auto NONE = 0;

using nlMsgPtr = std::unique_ptr<nl_msg, decltype(&::nlmsg_free)>;
using nlSocketPtr = std::unique_ptr<nl_sock, decltype(&::nl_socket_free)>;

int applyCmd(int ifindex, int cmd, int package = DEFAULT_VALUE,
             int channel = DEFAULT_VALUE, int flags = NONE)
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

}//namespace ncsi
}//namespace network
}//namespace phosphor
