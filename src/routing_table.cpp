#include "routing_table.hpp"

#include "netlink.hpp"
#include "util.hpp"

#include <net/if.h>

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
    defaultGateway.clear();
    defaultGateway6.clear();
    try
    {
        rtmsg msg{};
        netlink::performRequest(NETLINK_ROUTE, RTM_GETROUTE, NLM_F_DUMP, msg,
                                [&](const nlmsghdr& hdr, std::string_view msg) {
                                    this->handleRtmGetRoute(hdr, msg);
                                });
    }
    catch (const std::exception& e)
    {
        log<level::ERR>("Reading routes failed", entry("ERROR=%s", e.what()));
        commit<InternalFailure>();
    }
}

void Table::handleRtmGetRoute(const nlmsghdr& hdr, std::string_view msg)
{
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

    parseRtAttrs(msg, rtm.rtm_family);
}

void Table::parseRtaMultipath(std::string_view msg, int family)
{
    while (!msg.empty())
    {
        auto [hdr, data] = netlink::extractRtNextHop(msg);
        parseRtAttrs(data, family, hdr.rtnh_ifindex);
    }
}

// Parse routes from Routing Atrributes (RTA)
void Table::parseRtAttrs(std::string_view msg, int family,
                         std::optional<int> ifindex)
{
    std::optional<InAddrAny> dstAddr;
    std::optional<InAddrAny> gatewayAddr;

    while (!msg.empty())
    {
        auto [hdr, data] = netlink::extractRtAttr(msg);
        switch (hdr.rta_type)
        {
            case RTA_OIF:
                ifindex = stdplus::raw::copyFrom<int>(data);
                break;
            case RTA_GATEWAY:
                gatewayAddr = addrFromBuf(family, data);
                break;
            case RTA_DST:
                dstAddr = addrFromBuf(family, data);
                break;
            case RTA_MULTIPATH:
                parseRtaMultipath(data, family);
                break;
        }
    }
    ::putchar('\n');
    if (ifindex && gatewayAddr && !dstAddr)
    {
        updateGateway(family, ifnameFromIndex(*ifindex),
                      toString(*gatewayAddr));
    }
}

void Table::updateGateway(int family, const std::string& ifname,
                          const std::string& gateway)
{
    if (family == AF_INET)
    {
        defaultGateway[ifname] = gateway;
    }
    else if (family == AF_INET6)
    {
        defaultGateway6[ifname] = gateway;
    }
}

} // namespace route
} // namespace network
} // namespace phosphor
