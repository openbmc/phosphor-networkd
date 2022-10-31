#include "routing_table.hpp"

#include "netlink.hpp"
#include "rtnetlink.hpp"

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

static void parseRoute(auto& gws4, auto& gws6, const nlmsghdr& hdr,
                       std::string_view msg)
{
    if (hdr.nlmsg_type != RTM_NEWROUTE)
    {
        throw std::runtime_error("Not a route msg");
    }

    if (auto ret = netlink::gatewayFromRtm(msg); ret)
    {
        std::visit(
            [&](auto addr) {
                if constexpr (std::is_same_v<in_addr, decltype(addr)>)
                {
                    gws4.emplace(std::get<unsigned>(*ret), addr);
                }
                else if constexpr (std::is_same_v<in6_addr, decltype(addr)>)
                {
                    gws6.emplace(std::get<unsigned>(*ret), addr);
                }
                else
                {
                    static_assert(!std::is_same_v<void, decltype(addr)>);
                }
            },
            std::get<InAddrAny>(*ret));
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
