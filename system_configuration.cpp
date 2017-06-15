#include "config.h"
#include "system_configuration.hpp"
#include "network_manager.hpp"
#include "routing_table.hpp"
#include "xyz/openbmc_project/Common/error.hpp"

#include <phosphor-logging/log.hpp>
#include <phosphor-logging/elog-errors.hpp>

namespace phosphor
{
namespace network
{

// systemd service to kick start a target.
constexpr auto HOSTNAMED_SERVICE    = "org.freedesktop.hostname1";
constexpr auto HOSTNAMED_SERVICE_PATH  = "/org/freedesktop/hostname1";
constexpr auto HOSTNAMED_INTERFACE  = "org.freedesktop.hostname1";
constexpr auto PROPERTY_INTERFACE = "org.freedesktop.DBus.Properties";
constexpr auto METHOD_GET = "Get";
constexpr auto METHOD_SET = "SetStaticHostname";

using namespace phosphor::logging;
using namespace sdbusplus::xyz::openbmc_project::Common::Error;

using SystemConfigIntf =
    sdbusplus::xyz::openbmc_project::Network::server::SystemConfiguration;

SystemConfiguration::SystemConfiguration(sdbusplus::bus::bus& bus,
                                         const std::string& objPath,
                                         Manager& parent) :
                                         Iface(bus, objPath.c_str(), true),
                                         bus(bus),
                                         manager(parent)
{
    auto name = getHostNamefromSystem();
    route::Table routingTable;

    SystemConfigIntf::hostName(name);
    SystemConfigIntf::defaultGateway(routingTable.getDefaultGateway());

    this->emit_object_added();
}

std::string SystemConfiguration::hostName(std::string name)
{
    auto method = bus.new_method_call(
                      HOSTNAMED_SERVICE,
                      HOSTNAMED_SERVICE_PATH,
                      HOSTNAMED_INTERFACE,
                      METHOD_SET);

    method.append(name, true);

    if (!bus.call(method))
    {
        log<level::ERR>("Failed to set the hostname");
        report<InternalFailure>();
        return SystemConfigIntf::hostName();
    }

    SystemConfigIntf::hostName(name);
    return name;

}

std::string SystemConfiguration::getHostNamefromSystem() const
{
    sdbusplus::message::variant<std::string> name;
    auto method = bus.new_method_call(
                      HOSTNAMED_SERVICE,
                      HOSTNAMED_SERVICE_PATH,
                      PROPERTY_INTERFACE,
                      METHOD_GET);

    method.append(HOSTNAMED_INTERFACE, "Hostname");

    auto reply = bus.call(method);

    if (reply)
    {
        reply.read(name);
    }
    else
    {
        log<level::ERR>("Failed to get hostname");
        report<InternalFailure>();
        return "";
    }
    return name.get<std::string>();
}


std::string SystemConfiguration::defaultGateway(std::string gateway)
{
    SystemConfigIntf::defaultGateway(gateway);
    manager.writeToConfigurationFile();
    return gateway;
}

std::string SystemConfiguration::defaultGateway() const
{
    return SystemConfigIntf::defaultGateway();
}

}// namespace network
}// namespace phosphor
