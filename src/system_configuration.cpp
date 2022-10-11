#include "system_configuration.hpp"

#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/log.hpp>
#include <xyz/openbmc_project/Common/error.hpp>

namespace phosphor
{
namespace network
{

// systemd service to kick start a target.
constexpr auto HOSTNAMED_SERVICE = "org.freedesktop.hostname1";
constexpr auto HOSTNAMED_SERVICE_PATH = "/org/freedesktop/hostname1";
constexpr auto HOSTNAMED_INTERFACE = "org.freedesktop.hostname1";
constexpr auto PROPERTY_INTERFACE = "org.freedesktop.DBus.Properties";
constexpr auto METHOD_GET = "Get";
constexpr auto METHOD_SET = "SetStaticHostname";

using namespace phosphor::logging;
using namespace sdbusplus::xyz::openbmc_project::Common::Error;

using SystemConfigIntf =
    sdbusplus::xyz::openbmc_project::Network::server::SystemConfiguration;

SystemConfiguration::SystemConfiguration(sdbusplus::bus_t& bus,
                                         stdplus::const_zstring objPath) :
    Iface(bus, objPath.c_str(), Iface::action::defer_emit),
    bus(bus)
{
    SystemConfigIntf::hostName(getHostNameFromSystem());

    this->emit_object_added();
}

std::string SystemConfiguration::hostName(std::string name)
{
    if (SystemConfigIntf::hostName() == name)
    {
        return name;
    }
    auto method = bus.new_method_call(HOSTNAMED_SERVICE, HOSTNAMED_SERVICE_PATH,
                                      HOSTNAMED_INTERFACE, METHOD_SET);

    method.append(name, true);

    if (!bus.call(method))
    {
        log<level::ERR>("Failed to set the hostname");
        report<InternalFailure>();
        return SystemConfigIntf::hostName();
    }

    return SystemConfigIntf::hostName(name);
}

std::string SystemConfiguration::getHostNameFromSystem() const
{
    try
    {
        std::variant<std::string> name;
        auto method =
            bus.new_method_call(HOSTNAMED_SERVICE, HOSTNAMED_SERVICE_PATH,
                                PROPERTY_INTERFACE, METHOD_GET);

        method.append(HOSTNAMED_INTERFACE, "Hostname");

        auto reply = bus.call(method);

        reply.read(name);
        return std::get<std::string>(name);
    }
    catch (const sdbusplus::exception_t& ex)
    {
        log<level::ERR>(
            "Failed to get the hostname from systemd-hostnamed service",
            entry("ERR=%s", ex.what()));
    }
    return "";
}

} // namespace network
} // namespace phosphor
