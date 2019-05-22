#include "config.h"

#include "dhcp_configuration.hpp"

#include "network_manager.hpp"

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

ConfigIntf::ClientIdentifier
    Configuration::clientIdentifier(ClientIdentifier value)
{
    if (value == clientIdentifier())
    {
        return value;
    }

    auto clientId = ConfigIntf::clientIdentifier(value);
    manager.writeToConfigurationFile();
    manager.restartSystemdUnit(phosphor::network::networkdService);

    return clientId;
}

ConfigIntf::DUIDType Configuration::dUIDType(DUIDType value)
{
    if (value == dUIDType())
    {
        return value;
    }

    if (value == DHCPConfiguration::DUIDType::vendor)
    {
        log<level::ERR>("DUID type "
                        "xyz.openbmc_project.Network.DHCPConfiguration."
                        "DUIDType.vendor is not supported...");
        elog<NotSupported>();
        return dUIDType();
    }
    else if (value == DHCPConfiguration::DUIDType::uuid)
    {
        log<level::ERR>("DUID type "
                        "xyz.openbmc_project.Network.DHCPConfiguration."
                        "DUIDType.uuid is not supported...");
        elog<NotSupported>();
        return dUIDType();
    }

    auto dUIDType = ConfigIntf::dUIDType(value);
    manager.writeToConfigurationFile();
    manager.restartSystemdUnit(phosphor::network::networkdService);

    return dUIDType;
}

bool Configuration::sendHostNameEnabled(bool value)
{
    if (value == sendHostNameEnabled())
    {
        return value;
    }

    auto name = ConfigIntf::sendHostNameEnabled(value);
    manager.writeToConfigurationFile();

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
    manager.restartSystemdUnit(phosphor::network::networkdService);

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
    manager.restartSystemdUnit(phosphor::network::networkdService);
    manager.restartSystemdUnit(phosphor::network::timeSynchdService);

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
    manager.restartSystemdUnit(phosphor::network::networkdService);

    return dns;
}

std::string Configuration::getDHCPPropFromConf(const std::string& prop)
{
    fs::path confPath = manager.getConfDir();
    auto interfaceStrList = getInterfaces();
    // get the first interface name, we need it to know config file name.
    auto interface = *interfaceStrList.begin();
    auto fileName = systemd::config::networkFilePrefix + interface +
                    systemd::config::networkFileSuffix;

    confPath /= fileName;
    // systemd default behaviour is all DHCP fields should be enabled by
    // default.
    config::Parser parser(confPath);

    auto rc = config::ReturnCode::SUCCESS;
    config::ValueList values{};
    std::tie(rc, values) = parser.getValues("DHCP", prop);

    if (rc != config::ReturnCode::SUCCESS)
    {
        log<level::DEBUG>("Unable to get the value from section DHCP",
                          entry("PROP=%s", prop.c_str()), entry("RC=%d", rc));
        return "";
    }

    return values[0];
}

std::string Configuration::getClientIdentifierAsString(
    const ConfigIntf::ClientIdentifier&& clientId)
{
    if (clientId == ConfigIntf::ClientIdentifier::mac)
    {
        return "mac";
    }
    else if (clientId == ConfigIntf::ClientIdentifier::duid)
    {
        return "duid";
    }
    else if (clientId == ConfigIntf::ClientIdentifier::duid_only)
    {
        return "duid-only";
    }
    return "";
}

ConfigIntf::ClientIdentifier
    Configuration::getClientIdentifierAsEnum(const std::string&& clientId)
{
    if (clientId == "mac")
    {
        return ConfigIntf::ClientIdentifier::mac;
    }
    else if (clientId == "duid")
    {
        return ConfigIntf::ClientIdentifier::duid;
    }
    else if (clientId == "duid-only")
    {
        return ConfigIntf::ClientIdentifier::duid_only;
    }
    else
    {
        // This is the case when the file
        // /etc/systemd/network/00-bmc-eth0.network has been manually edited to
        // specify a clientId which is not supported by the code.
        log<level::ERR>("Unknown ClientId found in the config file.Setting it "
                        "to the default \"mac\"",
                        entry("ClientId=%s", clientId.c_str()));
        auto clientId =
            ConfigIntf::clientIdentifier(ConfigIntf::ClientIdentifier::mac);
        // manager.writeToConfigurationFile();
        return clientId;
    }
}

std::string Configuration::getDUIDTypeAsString(
    const DHCPConfiguration::DUIDType&& dUIDType)
{
    if (dUIDType == ConfigIntf::DUIDType::vendor)
    {
        return "vendor";
    }
    else if (dUIDType == ConfigIntf::DUIDType::uuid)
    {
        return "uuid";
    }
    else if (dUIDType == ConfigIntf::DUIDType::link_layer_time)
    {
        return "link-layer-time";
    }
    else if (dUIDType == ConfigIntf::DUIDType::link_layer)
    {
        return "link-layer";
    }
    return "";
}

ConfigIntf::DUIDType
    Configuration::getDUIDTypeAsEnum(const std::string&& dUIDType)
{
    if (dUIDType == "vendor")
    {
        return ConfigIntf::DUIDType::vendor;
    }
    else if (dUIDType == "uuid")
    {
        return ConfigIntf::DUIDType::uuid;
    }
    else if (dUIDType == "link-layer-time")
    {
        return ConfigIntf::DUIDType::link_layer_time;
    }
    else if (dUIDType == "link-layer")
    {
        return ConfigIntf::DUIDType::link_layer;
    }
    else
    {
        // This is the case when the file
        // /etc/systemd/network/00-bmc-eth0.network has been manually edited to
        // specify a DUIDType which is not supported by the code.
        log<level::ERR>("Unknown DUIDType found in the config file.Setting it "
                        "to the default \"link_layer\"",
                        entry("DUIDType=%s", dUIDType.c_str()));
        auto dUIDType = ConfigIntf::dUIDType(ConfigIntf::DUIDType::link_layer);
        // manager.writeToConfigurationFile();
        return dUIDType;
    }
}
} // namespace dhcp
} // namespace network
} // namespace phosphor
