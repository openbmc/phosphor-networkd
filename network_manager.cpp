#include "config.h"
#include "util.hpp"
#include "network_manager.hpp"
#include "network_config.hpp"
#include "ipaddress.hpp"
#include "timer.hpp"
#include "xyz/openbmc_project/Common/error.hpp"

#include <phosphor-logging/log.hpp>
#include <phosphor-logging/elog-errors.hpp>

#include <algorithm>
#include <bitset>
#include <map>
#include <fstream>

#include <arpa/inet.h>
#include <dirent.h>
#include <net/if.h>

#include <string>

namespace phosphor
{
namespace network
{

extern std::unique_ptr<phosphor::network::Timer> refreshTimer;
using namespace phosphor::logging;
using namespace sdbusplus::xyz::openbmc_project::Common::Error;

Manager::Manager(sdbusplus::bus::bus& bus, const char* objPath,
                 const std::string& path):
    details::VLANCreateIface(bus, objPath, true),
    bus(bus),
    objectPath(objPath)
{
    fs::path confDir(path);
    setConfDir(confDir);
}

bool Manager::createDefaultNetworkFiles(bool force)
{
    auto isCreated = false;
    try
    {
        // Directory would have created before with
        // setConfDir function.
        if (force)
        {
            // Factory Reset case
            // we need to forcefully write the files
            // so delete the existing ones.
            if (fs::is_directory(confDir))
            {
                for (const auto& file : fs::directory_iterator(confDir))
                {
                    fs::remove(file.path());
                }
            }
        }

        auto interfaceStrList = getInterfaces();
        for (const auto& interface : interfaceStrList)
        {
            auto fileName = systemd::config::networkFilePrefix + interface +
                systemd::config::networkFileSuffix;

            fs::path  filePath = confDir;
            filePath /= fileName;

            // create the interface specific network file
            // if not exist or we forcefully wants to write
            // the network file.

            if (force || !fs::is_regular_file(filePath.string()))
            {
                bmc::writeDHCPDefault(filePath.string(), interface);
                log<level::INFO>("Created the default network file.",
                        entry("INTERFACE=%s", interface.c_str()));
                isCreated = true;
            }
        }
    }
    catch (std::exception& e)
    {
        log<level::ERR>("Unable to create the default network file");
        elog<InternalFailure>();
    }
    return isCreated;
}

void Manager::setConfDir(const fs::path& dir)
{
    confDir = dir;

    if (!fs::exists(confDir))
    {
        if (!fs::create_directories(confDir))
        {
            log<level::ERR>("Unable to create the network conf dir",
                            entry("DIR=%s", confDir.c_str()));
            elog<InternalFailure>();
        }
    }

}

void Manager::createInterfaces()
{
    //clear all the interfaces first
    interfaces.clear();

    auto interfaceStrList = getInterfaces();

    for (auto& interface : interfaceStrList)
    {
        fs::path objPath = objectPath;
        auto index = interface.find(".");

        // interface can be of vlan type or normal ethernet interface.
        // vlan interface looks like "interface.vlanid",so here by looking
        // at the interface name we decide that we need
        // to create the vlaninterface or normal physical interface.
        if (index != std::string::npos)
        {
            //it is vlan interface
            auto interfaceName = interface.substr(0, index);
            auto vlanid = interface.substr(index + 1);
            uint32_t vlanInt = std::stoul(vlanid);

            interfaces[interfaceName]->loadVLAN(vlanInt);
            continue;
        }
        // normal ethernet inetrface
        objPath /= interface;

        auto dhcp = getDHCPValue(confDir, interface);

        auto intf =  std::make_shared<phosphor::network::EthernetInterface>(
                         bus,
                         objPath.string(),
                         dhcp,
                         *this);


        intf->createIPAddressObjects();

        this->interfaces.emplace(std::make_pair(
                                     std::move(interface), std::move(intf)));

    }

}

void Manager::createChildObjects()
{
    // creates the ethernet interface dbus object.
    createInterfaces();

    systemConf.reset(nullptr);
    dhcpConf.reset(nullptr);

    fs::path objPath = objectPath;
    objPath /= "config";

    // create the system conf object.
    systemConf = std::make_unique<phosphor::network::SystemConfiguration>(
                        bus, objPath.string(), *this);
    // create the dhcp conf object.
    objPath /= "dhcp";
    dhcpConf = std::make_unique<phosphor::network::dhcp::Configuration>(
                        bus, objPath.string(), *this);

}

void Manager::vLAN(IntfName interfaceName, uint32_t id)
{
    interfaces[interfaceName]->createVLAN(id);
}

void Manager::reset()
{
    try
    {
        createDefaultNetworkFiles(true);
    }
    catch (InternalFailure& e)
    {
        log<level::ERR>("Network Factory Reset failed.");
        // TODO: openbmc/openbmc#1721 - Log ResetFailed error here.
    }
}

// Need to merge the below function with the code which writes the
// config file during factory reset.
//TODO openbmc/openbmc#1751
void Manager::writeToConfigurationFile()
{
    // write all the static ip address in the systemd-network conf file
    for (const auto& intf : interfaces)
    {
        intf.second->writeConfigurationFile();

    }
    restartNetwork();
}

void Manager::restartNetwork()
{
    using namespace std::chrono;

    if (refreshTimer && !refreshTimer->isExpired())
    {
        auto time =  duration_cast<microseconds>(
                        phosphor::network::networkChangeTimeout);
        refreshTimer->startTimer(time);
    }
    restartSystemdUnit("systemd-networkd.service");
}

}//namespace network
}//namespace phosphor
