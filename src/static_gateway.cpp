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

static auto makeObjPath(std::string_view root, std::string addr)
{
    auto ret = sdbusplus::message::object_path(std::string(root));
    ret /= addr;
    return ret;
}

StaticGateway::StaticGateway(sdbusplus::bus_t& bus, std::string_view objRoot,
                             stdplus::PinnedRef<EthernetInterface> parent,
                             std::string gateway, size_t prefixLength,
                             IP::Protocol protocolType) :
    StaticGateway(bus, makeObjPath(objRoot, gateway), parent,
                  gateway, prefixLength, protocolType)
{}

StaticGateway::StaticGateway(sdbusplus::bus_t& bus,
                             sdbusplus::message::object_path objPath,
                             stdplus::PinnedRef<EthernetInterface> parent,
                             std::string gateway, size_t prefixLength,
                             IP::Protocol protocolType) :
    StaticGatewayObj(bus, objPath.str.c_str(),
                     StaticGatewayObj::action::defer_emit),
    parent(parent), objPath(std::move(objPath))
{
    StaticGatewayObj::gateway(gateway, true);
    StaticGatewayObj::prefixLength(prefixLength, true);
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

size_t StaticGateway::prefixLength(size_t /*prefixLength*/)
{
    elog<NotAllowed>(REASON("Property update is not allowed"));
}
IP::Protocol StaticGateway::protocolType(IP::Protocol /*protocolType*/)
{
    elog<NotAllowed>(REASON("Property update is not allowed"));
}
} // namespace network
} // namespace phosphor
