#include "static_route.hpp"

#include "ethernet_interface.hpp"
#include "network_manager.hpp"

#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/elog.hpp>
#include <xyz/openbmc_project/Common/error.hpp>

#include <string>

namespace phosphor
{
namespace network
{

static auto makeObjPath(std::string_view root, std::string addr)
{
    auto ret = sdbusplus::message::object_path(std::string(root));
    ret /= addr;
    return ret;
}

StaticRoute::StaticRoute(sdbusplus::bus_t& bus, std::string_view objRoot,
                         stdplus::PinnedRef<EthernetInterface> parent,
                         std::string destination, std::string gateway,
                         size_t prefixLength, IP::Protocol protocolType) :
    StaticRoute(bus, makeObjPath(objRoot, gateway), parent, destination,
                gateway, prefixLength, protocolType)
{}

StaticRoute::StaticRoute(sdbusplus::bus_t& bus,
                         sdbusplus::message::object_path objPath,
                         stdplus::PinnedRef<EthernetInterface> parent,
                         std::string destination, std::string gateway,
                         size_t prefixLength, IP::Protocol protocolType) :
    StaticRouteObj(bus, objPath.str.c_str(),
                   StaticRouteObj::action::defer_emit),
    parent(parent), objPath(std::move(objPath))
{
    StaticRouteObj::destination(destination, true);
    StaticRouteObj::gateway(gateway, true);
    StaticRouteObj::prefixLength(prefixLength, true);
    StaticRouteObj::protocolType(protocolType, true);
    emit_object_added();
}

void StaticRoute::delete_()
{
    auto& staticRoutes = parent.get().staticRoutes;
    std::unique_ptr<StaticRoute> ptr;
    for (auto it = staticRoutes.begin(); it != staticRoutes.end(); ++it)
    {
        if (it->second.get() == this)
        {
            ptr = std::move(it->second);
            staticRoutes.erase(it);
            break;
        }
    }

    parent.get().writeConfigurationFile();
    parent.get().manager.get().reloadConfigs();
}

using sdbusplus::xyz::openbmc_project::Common::Error::NotAllowed;
using REASON =
    phosphor::logging::xyz::openbmc_project::Common::NotAllowed::REASON;
using phosphor::logging::elog;

std::string StaticRoute::destination(std::string /*Destination Address*/)
{
    elog<NotAllowed>(REASON("Property update is not allowed"));
}

std::string StaticRoute::gateway(std::string /*gateway*/)
{
    elog<NotAllowed>(REASON("Property update is not allowed"));
}

size_t StaticRoute::prefixLength(size_t /*prefixLength*/)
{
    elog<NotAllowed>(REASON("Property update is not allowed"));
}
IP::Protocol StaticRoute::protocolType(IP::Protocol /*protocolType*/)
{
    elog<NotAllowed>(REASON("Property update is not allowed"));
}
} // namespace network
} // namespace phosphor
