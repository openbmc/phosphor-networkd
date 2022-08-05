#include "config.h"

#include "dhcp_configuration.hpp"

#include "network_manager.hpp"

#include <fmt/format.h>

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
bool Configuration::sendHostNameEnabled(bool value)
{
    if (value == sendHostNameEnabled())
    {
        return value;
    }

    auto name = ConfigIntf::sendHostNameEnabled(value);

    manager.writeToConfigurationFile();
    manager.reloadConfigs();

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
    manager.reloadConfigs();

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
    manager.reloadConfigs();

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
    manager.reloadConfigs();

    return dns;
}

bool Configuration::getDHCPPropFromConf(const std::string& prop)
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

    const auto& values = parser.getValues("DHCP", prop);
    if (values.empty())
    {
        auto msg = fmt::format("Missing config section DHCP[{}]", prop);
        log<level::NOTICE>(msg.c_str(), entry("PROP=%s", prop.c_str()));
        return true;
    }
    auto ret = config::parseBool(values.back());
    if (!ret.has_value())
    {
        auto msg = fmt::format("Failed to parse section DHCP[{}]: `{}`", prop,
                               values.back());
        log<level::NOTICE>(msg.c_str(), entry("PROP=%s", prop.c_str()));
    }
    return ret.value_or(true);
}
} // namespace dhcp
} // namespace network
} // namespace phosphor
