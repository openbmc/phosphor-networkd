#include "routing_table.hpp"

#include "netlink.hpp"

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

template <typename Addr>
static void parse(auto& gws, std::string_view msg)
{
    std::optional<unsigned> ifIdx;
    std::optional<Addr> gw;
    while (!msg.empty())
    {
        auto [hdr, data] = netlink::extractRtAttr(msg);
        switch (hdr.rta_type)
        {
            case RTA_OIF:
                ifIdx.emplace(stdplus::raw::copyFrom<int>(data));
                break;
            case RTA_GATEWAY:
                gw.emplace(stdplus::raw::copyFrom<Addr>(data));
                break;
        }
    }
    if (ifIdx && gw)
    {
        gws.emplace(*ifIdx, *gw);
    }
}

static void parseRoute(auto& gws4, auto& gws6, const nlmsghdr& hdr,
                       std::string_view msg)
{
    if (hdr.nlmsg_type != RTM_NEWROUTE)
    {
        throw std::runtime_error("Not a route msg");
    }
    const auto& rtm = netlink::extractRtData<rtmsg>(msg);

    if (rtm.rtm_table != RT_TABLE_MAIN || rtm.rtm_dst_len != 0)
    {
        return;
    }

    switch (rtm.rtm_family)
    {
        case AF_INET:
            return parse<in_addr>(gws4, msg);
        case AF_INET6:
            return parse<in6_addr>(gws6, msg);
    }
}

void Table::refresh()
{
    gws4.clear();
    gws6.clear();
    try
    {
        rtmsg msg{};
        netlink::performRequest(NETLINK_ROUTE, RTM_GETROUTE, NLM_F_DUMP, msg,
                                [&](const nlmsghdr& hdr, std::string_view msg) {
                                    parseRoute(gws4, gws6, hdr, msg);
                                });
    }
    catch (const std::exception& e)
    {
        log<level::ERR>("Reading routes failed", entry("ERROR=%s", e.what()));
        commit<InternalFailure>();
    }
}
} // namespace route
} // namespace network
} // namespace phosphor
