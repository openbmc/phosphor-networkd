#include "dhcp_configuration.hpp"

#include "config_parser.hpp"
#include "network_manager.hpp"
#include "system_queries.hpp"
#include "util.hpp"

#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/log.hpp>
#include <xyz/openbmc_project/Common/error.hpp>

namespace phosphor
{
namespace network
{
namespace dhcp
{

using namespace phosphor::network;
using namespace phosphor::logging;
using namespace sdbusplus::xyz::openbmc_project::Common::Error;

Configuration::Configuration(sdbusplus::bus_t& bus,
                             stdplus::const_zstring objPath, Manager& parent) :
    Iface(bus, objPath.c_str(), Iface::action::defer_emit),
    bus(bus), manager(parent)
{
    config::Parser conf;
    {
        auto interfaces = system::getInterfaces();
        if (!interfaces.empty())
        {
            conf.setFile(config::pathForIntfConf(manager.getConfDir(),
                                                 *interfaces[0].name));
        }
    }

    ConfigIntf::dnsEnabled(getDHCPProp(conf, "UseDNS"));
    ConfigIntf::ntpEnabled(getDHCPProp(conf, "UseNTP"));
    ConfigIntf::hostNameEnabled(getDHCPProp(conf, "UseHostname"));
    ConfigIntf::sendHostNameEnabled(getDHCPProp(conf, "SendHostname"));
    emit_object_added();
}

bool Configuration::sendHostNameEnabled(bool value)
{
    if (value == sendHostNameEnabled())
    {
        return value;
    }

    auto name = ConfigIntf::sendHostNameEnabled(value);

    manager.writeToConfigurationFile();
    manager.reloadConfigsNoRefresh();

    return name;
}

bool Configuration::hostNameEnabled(bool value)
{
    if (value == hostNameEnabled())
    {
        return value;
    }

    auto name = ConfigIntf::hostNameEnabled(value);
    manager.writeToConfigurationFile();
    manager.reloadConfigsNoRefresh();

    return name;
}

bool Configuration::ntpEnabled(bool value)
{
    if (value == ntpEnabled())
    {
        return value;
    }

    auto ntp = ConfigIntf::ntpEnabled(value);
    manager.writeToConfigurationFile();
    manager.reloadConfigsNoRefresh();

    return ntp;
}

bool Configuration::dnsEnabled(bool value)
{
    if (value == dnsEnabled())
    {
        return value;
    }

    auto dns = ConfigIntf::dnsEnabled(value);
    manager.writeToConfigurationFile();
    manager.reloadConfigsNoRefresh();

    return dns;
}

} // namespace dhcp
} // namespace network
} // namespace phosphor
