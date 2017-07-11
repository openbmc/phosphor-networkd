#include "config.h"
#include "dhcp_configuration.hpp"
#include "network_manager.hpp"


namespace phosphor
{
namespace network
{
namespace dhcp
{

Configuration::Configuration(sdbusplus::bus::bus& bus,
                             const std::string& objPath,
                             phosphor::network::Manager& parent) :
        Iface(bus, objPath.c_str(), true),
        bus(bus),
        manager(parent)
{
    this->emit_object_added();
}

bool Configuration::hostName(bool value)
{
    auto isName = ConfigIntf::hostName(value);
    manager.restartSystemdUnit("systemd-networkd.service");
    return isName;
}

bool Configuration::nTP(bool value)
{
    auto isNTP = ConfigIntf::nTP(value);
    manager.restartSystemdUnit("systemd-networkd.service");
    manager.restartSystemdUnit("systemd-timesynchd.service");
    return isNTP;
}


bool Configuration::dNS(bool value)
{
    auto isDNS = ConfigIntf::dNS(value);
    manager.restartSystemdUnit("systemd-networkd.service");
    return isDNS;
}

}// namespace dhcp
}// namespace network
}// namespace phosphor
