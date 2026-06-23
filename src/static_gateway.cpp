#include "static_gateway.hpp"

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

static auto makeObjPath(std::string_view root, const std::string& addr)
{
    auto ret = sdbusplus::object_path(std::string(root));
    ret /= addr;
    return ret;
}

StaticGateway::StaticGateway(
    sdbusplus::bus_t& bus, const sdbusplus::object_path& objRoot,
    stdplus::PinnedRef<EthernetInterface> parent, const std::string& gateway,
    IP::Protocol protocolType) :
    StaticGateway(bus, makeObjPath(objRoot.string(), gateway), parent, gateway,
                  protocolType, std::monostate())
{}

StaticGateway::StaticGateway(
    sdbusplus::bus_t& bus, sdbusplus::object_path objPath,
    stdplus::PinnedRef<EthernetInterface> parent, const std::string& gateway,
    IP::Protocol protocolType, std::monostate /*unused*/) :
    StaticGatewayObj(bus, objPath, StaticGatewayObj::action::defer_emit),
    parent(parent), objPath(std::move(objPath))
{
    StaticGatewayObj::gateway(gateway, true);
    StaticGatewayObj::protocolType(protocolType, true);
    emit_object_added();
}

void StaticGateway::delete_()
{
    auto& staticGateways = parent.get().staticGateways;
    std::unique_ptr<StaticGateway> ptr;
    for (auto it = staticGateways.begin(); it != staticGateways.end(); ++it)
    {
        if (it->second.get() == this)
        {
            ptr = std::move(it->second);
            staticGateways.erase(it);
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

std::string StaticGateway::gateway(std::string /*gateway*/)
{
    elog<NotAllowed>(REASON("Property update is not allowed"));
}

IP::Protocol StaticGateway::protocolType(IP::Protocol /*protocolType*/)
{
    elog<NotAllowed>(REASON("Property update is not allowed"));
}
} // namespace network
} // namespace phosphor
