#include "dhcp_configuration.hpp"

#include "config_parser.hpp"
#include "network_manager.hpp"

#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/lg2.hpp>
#include <phosphor-logging/log.hpp>
#include <xyz/openbmc_project/Common/error.hpp>

namespace phosphor
{
namespace network
{
using namespace phosphor::logging;
namespace dhcp
{

using namespace phosphor::network;
using namespace sdbusplus::xyz::openbmc_project::Common::Error;
using NotAllowed = sdbusplus::xyz::openbmc_project::Common::Error::NotAllowed;
using NotAllowedArgument = xyz::openbmc_project::Common::NotAllowed;

Configuration::Configuration(
    sdbusplus::bus_t& bus, stdplus::const_zstring objPath,
    stdplus::PinnedRef<EthernetInterface> parent, DHCPType type) :
    Iface(bus, objPath.c_str(), Iface::action::defer_emit), parent(parent)
{
    config::Parser conf(config::pathForIntfConf(
        parent.get().manager.get().getConfDir(), parent.get().interfaceName()));
    ConfigIntf::domainEnabled(getDHCPProp(conf, type, "UseDomains"), true);
    ConfigIntf::dnsEnabled(getDHCPProp(conf, type, "UseDNS"), true);
    ConfigIntf::ntpEnabled(getDHCPProp(conf, type, "UseNTP"), true);
    ConfigIntf::hostNameEnabled(getDHCPProp(conf, type, "UseHostname"), true);
    ConfigIntf::sendHostNameEnabled(getDHCPProp(conf, type, "SendHostname"),
                                    true);
    ConfigIntf::vendorClassIdentifier(getDHCPVendorClassIdentifier(conf));
    vendorOptionList = getDHCPVendorOption(conf, type);
    this->type = type;
    emit_object_added();
}

bool Configuration::sendHostNameEnabled(bool value)
{
    if (value == sendHostNameEnabled())
    {
        return value;
    }

    auto name = ConfigIntf::sendHostNameEnabled(value);
    parent.get().writeConfigurationFile();
    parent.get().reloadConfigs();
    return name;
}

bool Configuration::hostNameEnabled(bool value)
{
    if (value == hostNameEnabled())
    {
        return value;
    }

    auto name = ConfigIntf::hostNameEnabled(value);
    parent.get().writeConfigurationFile();
    parent.get().reloadConfigs();

    return name;
}

bool Configuration::ntpEnabled(bool value)
{
    if (value == ntpEnabled())
    {
        return value;
    }

    auto ntp = ConfigIntf::ntpEnabled(value);
    parent.get().writeConfigurationFile();
    parent.get().reloadConfigs();

    return ntp;
}

bool Configuration::dnsEnabled(bool value)
{
    if (value == dnsEnabled())
    {
        return value;
    }

    auto dns = ConfigIntf::dnsEnabled(value);
    parent.get().writeConfigurationFile();
    parent.get().reloadConfigs();

    return dns;
}

bool Configuration::domainEnabled(bool value)
{
    if (value == domainEnabled())
    {
        return value;
    }

    auto domain = ConfigIntf::domainEnabled(value);
    parent.get().writeConfigurationFile();
    parent.get().reloadConfigs();

    return domain;
}

std::string Configuration::vendorClassIdentifier(std::string value)
{
    if (this->type != DHCPType::v4)
    {
        log<level::ERR>("Vendor Class Identifier only supports in DHCPv4.\n");
        elog<NotAllowed>(NotAllowedArgument::REASON(
            "Vendor Class Identifier only supports in DHCPv4.\n"));
    }
    if (value == Configuration::vendorClassIdentifier())
    {
        return value;
    }

    ConfigIntf::vendorClassIdentifier(value);
    parent.get().writeConfigurationFile();
    parent.get().reloadConfigs();
    return value;
}

int16_t Configuration::setVendorOption(uint32_t option, std::string value)
{
    if (auto it = vendorOptionList.find(option);
        it != vendorOptionList.end() && it->second == value)
    {
        return 0;
    }

    vendorOptionList[option] = value;
    parent.get().writeConfigurationFile();
    parent.get().reloadConfigs();
    return 0;
}

std::string Configuration::getVendorOption(uint32_t option)
{
    if (vendorOptionList.find(option) == vendorOptionList.end())
    {
        return "";
    }

    return vendorOptionList[option];
}

int16_t Configuration::delVendorOption(uint32_t option)
{
    if (vendorOptionList.find(option) == vendorOptionList.end())
    {
        return -1;
    }

    vendorOptionList.erase(option);
    parent.get().writeConfigurationFile();
    parent.get().reloadConfigs();
    return 0;
}

} // namespace dhcp
} // namespace network
} // namespace phosphor
