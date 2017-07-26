#include "config.h"
#include "config_parser.hpp"
#include "util.hpp"
#include "network_manager.hpp"
#include "network_config.hpp"
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

using namespace phosphor::logging;
using namespace sdbusplus::xyz::openbmc_project::Common::Error;

Manager::Manager(sdbusplus::bus::bus& bus, const char* objPath):
    details::VLANCreateIface(bus, objPath, true),
    bus(bus),
    objectPath(objPath)
{
    confDir = NETWORK_CONF_DIR;
}

void Manager::setConfDir(const fs::path& dir)
{
    confDir = dir;
}

void Manager::createInterfaces()
{
    //clear all the interfaces first
    interfaces.clear();

    auto interfaceInfoList = getInterfaceAddrs();

    for (const auto& intfInfo : interfaceInfoList)
    {
        fs::path objPath = objectPath;
        auto index = intfInfo.first.find(".");
        std::string interface;
        std::string vlanid;

        uint32_t vlanInt;
        // interface can be of vlan type or normal ethernet interface.
        // vlan interface looks like "interface.vlanid",so here by looking
        // at the interface name we decide that we need
        // to create the vlaninterface or normal physical interface.
        if (index != std::string::npos)
        {
            //it is vlan interface
            interface = intfInfo.first.substr(0, index);
            vlanid = intfInfo.first.substr(index + 1);
            vlanInt = static_cast<uint32_t>(atoi(vlanid.c_str()));

            auto& intf = interfaces[interface];
            intf->loadVLAN(vlanInt);
            return;
        }
        // normal ethernet inetrface
        objPath /= intfInfo.first;

        auto dhcp = getDHCPValue(intfInfo.first);

        auto intf =  std::make_shared<phosphor::network::EthernetInterface>(
                         bus,
                         objPath.string(),
                         dhcp,
                         *this);


        intf->createIPAddressObjects();

        this->interfaces.emplace(std::make_pair(
                                     intfInfo.first, intf));

    }

}

void Manager::createChildObjects()
{
    // creates the ethernet interface dbus object.
    createInterfaces();
    // create the system conf object.
    fs::path objPath = objectPath;
    objPath /= "config";
    systemConf = std::make_shared<phosphor::network::SystemConfiguration>(
                        bus, objPath.string(), *this);
    // create the dhcp conf object.
    objPath /= "dhcp";
    dhcpConf = std::make_shared<phosphor::network::dhcp::Configuration>(
                        bus, objPath.string(), *this);

}

void Manager::vLAN(IntfName interfaceName, uint32_t id)
{
    auto& intf = interfaces[interfaceName];
    intf->createVLAN(id);
}

void Manager::reset()
{
    const std::string networkConfig = "/etc/systemd/network/";
    bool filesExist, interfacesMapped = false;

    if(fs::is_directory(networkConfig))
    {
        for(auto& file : fs::directory_iterator(networkConfig))
        {
            std::string filename = file.path().filename().c_str();

            if(filename.substr(filename.find_last_of(".") + 1) == "network")
            {
                fs::remove(file.path());
                filesExist = true;
            }
        }

        if(!filesExist)
        {
            log<level::INFO>("No existing network configuration was found.");
        }

        for (auto& intf : interfaces)
        {
            std::string filename = networkConfig + "00-bmc-" + intf.first +
                    ".network";

            bmc::writeDHCPDefault(filename, intf.first);
            interfacesMapped = true;
        }

        if(interfacesMapped)
        {
            log<level::INFO>("Network configuration reset to DHCP.");
        }
        else
        {
            log<level::ERR>("No network interfaces are mapped.");
            // TODO: openbmc/openbmc#1721 - Log ResetFailed error here.
        }
    }
    else
    {
        log<level::ERR>("Network configuration directory not found!");
        // TODO: openbmc/openbmc#1721 - Log ResetFailed error here.
    }

    return;
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
}

bool Manager::getDHCPValue(const std::string& intf)
{
    bool dhcp = false;
    // Get the interface mode value from systemd conf
    using namespace std::string_literals;
    fs::path confPath = confDir;
    std::string fileName = "00-bmc-"s + intf + ".network"s;
    confPath /= fileName;

    try
    {
        config::Parser parser(confPath.string());
        auto values = parser.getValues("Network","DHCP");
        // There will be only single value for DHCP key.
        if (values[0] == "true")
        {
            dhcp = true;
        }
    }
    catch (InternalFailure& e)
    {
        commit<InternalFailure>();
    }
    return dhcp;
}

}//namespace network
}//namespace phosphor
