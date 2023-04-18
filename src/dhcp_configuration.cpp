#include "dhcp_configuration.hpp"

#include "config_parser.hpp"
#include "network_manager.hpp"
#include "util.hpp"

#include <sys/stat.h>

#include <filesystem>
#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/lg2.hpp>
#include <xyz/openbmc_project/Common/error.hpp>

namespace phosphor
{
namespace network
{
namespace dhcp
{

using namespace phosphor::network;
using namespace sdbusplus::xyz::openbmc_project::Common::Error;

Configuration::Configuration(sdbusplus::bus_t& bus,
                             stdplus::const_zstring objPath,
                             stdplus::PinnedRef<Manager> parent) :
    Iface(bus, objPath.c_str(), Iface::action::defer_emit),
    manager(parent)
{
    config::Parser conf;
    std::filesystem::directory_entry newest_file;
    time_t newest_time = 0;
    for (const auto& dirent :
         std::filesystem::directory_iterator(manager.get().getConfDir()))
    {
        struct stat st = {};
        stat(dirent.path().native().c_str(), &st);
        if (st.st_mtime > newest_time)
        {
            newest_file = dirent;
            newest_time = st.st_mtime;
        }
    }
    if (newest_file != std::filesystem::directory_entry{})
    {
        lg2::info("Using DHCP options from {FILE}", "FILE",
                  newest_file.path().native());
        conf.setFile(newest_file.path());
    }

    ConfigIntf::dnsEnabled(getDHCPProp(conf, "UseDNS"), true);
    ConfigIntf::ntpEnabled(getDHCPProp(conf, "UseNTP"), true);
    ConfigIntf::hostNameEnabled(getDHCPProp(conf, "UseHostname"), true);
    ConfigIntf::sendHostNameEnabled(getDHCPProp(conf, "SendHostname"), true);
    emit_object_added();
}

bool Configuration::sendHostNameEnabled(bool value)
{
    if (value == sendHostNameEnabled())
    {
        return value;
    }

    auto name = ConfigIntf::sendHostNameEnabled(value);

    manager.get().writeToConfigurationFile();
    manager.get().reloadConfigs();

    return name;
}

bool Configuration::hostNameEnabled(bool value)
{
    if (value == hostNameEnabled())
    {
        return value;
    }

    auto name = ConfigIntf::hostNameEnabled(value);
    manager.get().writeToConfigurationFile();
    manager.get().reloadConfigs();

    return name;
}

bool Configuration::ntpEnabled(bool value)
{
    if (value == ntpEnabled())
    {
        return value;
    }

    auto ntp = ConfigIntf::ntpEnabled(value);
    manager.get().writeToConfigurationFile();
    manager.get().reloadConfigs();

    return ntp;
}

bool Configuration::dnsEnabled(bool value)
{
    if (value == dnsEnabled())
    {
        return value;
    }

    auto dns = ConfigIntf::dnsEnabled(value);
    manager.get().writeToConfigurationFile();
    manager.get().reloadConfigs();

    return dns;
}

} // namespace dhcp
} // namespace network
} // namespace phosphor
