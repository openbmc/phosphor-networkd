#include "routing_table.hpp"

#include "netlink.hpp"
#include "util.hpp"

#include <net/if.h>

#include <optional>
#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/log.hpp>
#include <stdexcept>
#include <stdplus/raw.hpp>
#include <string_view>
#include <xyz/openbmc_project/Common/error.hpp>

namespace phosphor
{
namespace network
{
namespace route
{

using namespace phosphor::logging;
using namespace sdbusplus::xyz::openbmc_project::Common::Error;

void Table::refresh()
{
    try
    {
        rtmsg msg{};
        netlink::performRequest(NETLINK_ROUTE, RTM_GETROUTE, NLM_F_DUMP, msg,
                                [&](const nlmsghdr& hdr, std::string_view msg) {
                                    this->parseRoutes(hdr, msg);
                                });
    }
    catch (const std::exception& e)
    {
        log<level::ERR>("Reading routes failed", entry("ERROR=%s", e.what()));
        commit<InternalFailure>();
    }
}

void Table::parseRoutes(const nlmsghdr& hdr, std::string_view msg)
{
    std::optional<InAddrAny> dstAddr;
    std::optional<InAddrAny> gateWayAddr;
    char ifName[IF_NAMESIZE] = {};

    if (hdr.nlmsg_type != RTM_NEWROUTE)
    {
        throw std::runtime_error("Not a route msg");
    }
    auto rtm = stdplus::raw::extract<rtmsg>(msg);

    if ((rtm.rtm_family != AF_INET && rtm.rtm_family != AF_INET6) ||
        rtm.rtm_table != RT_TABLE_MAIN)
    {
        return;
    }

    while (!msg.empty())
    {
        auto [hdr, data] = netlink::extractRtAttr(msg);
        switch (hdr.rta_type)
        {
            case RTA_OIF:
                if_indextoname(stdplus::raw::copyFrom<int>(data), ifName);
                break;
            case RTA_GATEWAY:
                gateWayAddr = addrFromBuf(rtm.rtm_family, data);
                break;
            case RTA_DST:
                dstAddr = addrFromBuf(rtm.rtm_family, data);
                break;
        }
    }

    std::string dstStr;
    if (dstAddr)
    {
        dstStr = toString(*dstAddr);
    }
    std::string gatewayStr;
    if (gateWayAddr)
    {
        gatewayStr = toString(*gateWayAddr);
    }
    if (rtm.rtm_dst_len == 0 && gateWayAddr)
    {
        std::string ifNameStr(ifName);
        if (rtm.rtm_family == AF_INET)
        {
            defaultGateway[ifNameStr] = gatewayStr;
        }
        else if (rtm.rtm_family == AF_INET6)
        {
            defaultGateway6[ifNameStr] = gatewayStr;
        }
    }
    Entry route(dstStr, gatewayStr, ifName);
    // if there is already existing route for this network
    // then ignore the next one as it would not be used by the
    // routing policy
    // So don't update the route entry for the network for which
    // there is already a route exist.
    if (routeList.find(dstStr) == routeList.end())
    {
        routeList.emplace(std::make_pair(dstStr, std::move(route)));
    }
}

} // namespace route
} // namespace network
} // namespace phosphor
