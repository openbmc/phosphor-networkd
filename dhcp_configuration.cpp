#include "config.h"
#include "dhcp_configuration.hpp"
#include "network_manager.hpp"


namespace phosphor
{
namespace network
{
namespace dhcp
{

bool Configuration::hostName(bool value)
{
    if (value == hostName())
    {
        return value;
    }

    auto name = ConfigIntf::hostName(value);
    manager.writeToConfigurationFile();
    manager.restartSystemdUnit("systemd-networkd.service");

    return name;
}

bool Configuration::nTP(bool value)
{
    if (value == nTP())
    {
        return value;
    }

    auto ntp = ConfigIntf::nTP(value);
    manager.writeToConfigurationFile();
    manager.restartSystemdUnit("systemd-networkd.service");
    manager.restartSystemdUnit("systemd-timesynchd.service");

    return ntp;
}


bool Configuration::dNS(bool value)
{
    if (value == dNS())
    {
        return value;
    }

    auto dns = ConfigIntf::dNS(value);
    manager.writeToConfigurationFile();
    manager.restartSystemdUnit("systemd-networkd.service");

    return dns;
}

}// namespace dhcp
}// namespace network
}// namespace phosphor
