#include "config.h"
#include "dhcp_configuration.hpp"
#include "network_manager.hpp"
#include "xyz/openbmc_project/Common/error.hpp"
#include <phosphor-logging/log.hpp>
#include <phosphor-logging/elog-errors.hpp>

namespace phosphor
{
namespace network
{
namespace dhcp
{

using namespace phosphor::network;
using namespace phosphor::logging;
using namespace sdbusplus::xyz::openbmc_project::Common::Error;
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

bool Configuration::getDHCPPropFromConf(const std::string& prop)
{
    fs::path confPath = manager.getConfDir();
    auto interfaceStrList = getInterfaces();
    std::string fileName{};
    // get the first interface name, we need it to know config file name.
    auto interface = *interfaceStrList.begin();
    fileName = systemd::config::networkFilePrefix + interface +
            systemd::config::networkFileSuffix;

    confPath /= fileName;
    // systemd default behaviour is all DHCP fields should be enabled by
    // default.
    auto propValue = true;
    try
    {
        config::Parser parser(confPath);
        auto values = parser.getValues("DHCP", prop);
        if (values[0] == "false")
        {
            propValue = false;
        }
    }
    catch (InternalFailure& e)
    {
        log<level::INFO>(
            "Exception occurred while getting DHCP property from config file");
    }
    return propValue;
}
}// namespace dhcp
}// namespace network
}// namespace phosphor
