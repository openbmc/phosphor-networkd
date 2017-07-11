#include "config.h"
#include "dhcp_configuration.hpp"
#include "network_manager.hpp"

namespace phosphor
{
namespace network
{
namespace dhcp
{

bool Configuration::hostNameEnabled(bool value)
{
    if (value == hostNameEnabled())
    {
        return value;
    }

    auto name = ConfigIntf::hostNameEnabled(value);
    manager.writeToConfigurationFile();
    restartSystemdUnit(phosphor::network::networkdService);

    return name;
}

bool Configuration::nTPEnabled(bool value)
{
    if (value == nTPEnabled())
    {
        return value;
    }

    auto ntp = ConfigIntf::nTPEnabled(value);
    manager.writeToConfigurationFile();
    restartSystemdUnit(phosphor::network::networkdService);
    restartSystemdUnit(phosphor::network::timeSynchdService);

    return ntp;
}


bool Configuration::dNSEnabled(bool value)
{
    if (value == dNSEnabled())
    {
        return value;
    }

    auto dns = ConfigIntf::dNSEnabled(value);
    manager.writeToConfigurationFile();
    restartSystemdUnit(phosphor::network::networkdService);

    return dns;
}

}// namespace dhcp
}// namespace network
}// namespace phosphor
