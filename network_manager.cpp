#include "config.h"
#include "config_parser.hpp"
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
        objPath /= intfInfo.first;

        auto dhcp = getDHCPValue(intfInfo.first);

        this->interfaces.emplace(std::make_pair(
                                     intfInfo.first,
                                     std::make_unique<
                                     phosphor::network::EthernetInterface>
                                     (bus,
                                      objPath.string(),
                                      dhcp,
                                      *this)));

        interfaces[intfInfo.first]->setAddressList(intfInfo.second);
    }
}

void Manager::createChildObjects()
{
    // creates the ethernet interface dbus object.
    createInterfaces();
    // create the system conf object.
    fs::path objPath = objectPath;
    objPath /= "conf";
    systemConfPtr = std::make_unique<phosphor::network::SystemConfiguration>(
                        bus, objPath.string(), *this);

}

void Manager::vLAN(IntfName interfaceName, uint16_t id)
{
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

IntfAddrMap Manager::getInterfaceAddrs() const
{
    IntfAddrMap intfMap{};
    AddrList addrList{};
    struct ifaddrs* ifaddr = nullptr;

    // attempt to fill struct with ifaddrs
    if (getifaddrs(&ifaddr) == -1)
    {
        auto error = errno;
        log<level::ERR>("Error occurred during the getifaddrs call",
                        entry("ERRNO=%s", strerror(error)));
        elog<InternalFailure>();
    }

    details::AddrPtr ifaddrPtr(ifaddr);
    ifaddr = nullptr;

    std::string intfName{};

    for (ifaddrs* ifa = ifaddrPtr.get(); ifa != nullptr; ifa = ifa->ifa_next)
    {
        // walk interfaces
        if (ifa->ifa_addr == nullptr)
        {
            continue;
        }

        // get only INET interfaces not ipv6
        if (ifa->ifa_addr->sa_family == AF_INET ||
            ifa->ifa_addr->sa_family == AF_INET6)
        {
            // if loopback, or not running ignore
            if ((ifa->ifa_flags & IFF_LOOPBACK) ||
                !(ifa->ifa_flags & IFF_RUNNING))
            {
                continue;
            }
            // if the interface name is  not same as the  previous
            // iteration then add the addr list into
            // the map.
            if (intfName != "" && intfName != std::string(ifa->ifa_name))
            {
                intfMap.emplace(intfName, addrList);
                addrList.clear();
            }
            intfName = ifa->ifa_name;
            AddrInfo info{};
            char ip[INET6_ADDRSTRLEN] = { 0 };
            char subnetMask[INET6_ADDRSTRLEN] = { 0 };

            if (ifa->ifa_addr->sa_family == AF_INET)
            {

                inet_ntop(ifa->ifa_addr->sa_family,
                          &(((struct sockaddr_in*)(ifa->ifa_addr))->sin_addr),
                          ip,
                          sizeof(ip));

                inet_ntop(ifa->ifa_addr->sa_family,
                          &(((struct sockaddr_in*)(ifa->ifa_netmask))->sin_addr),
                          subnetMask,
                          sizeof(subnetMask));

            }
            else
            {
                inet_ntop(ifa->ifa_addr->sa_family,
                          &(((struct sockaddr_in6*)(ifa->ifa_addr))->sin6_addr),
                          ip,
                          sizeof(ip));

                inet_ntop(ifa->ifa_addr->sa_family,
                          &(((struct sockaddr_in6*)(ifa->ifa_netmask))->sin6_addr),
                          subnetMask,
                          sizeof(subnetMask));

            }

            info.addrType = ifa->ifa_addr->sa_family;
            info.ipaddress = ip;
            info.prefix = toCidr(info.addrType, std::string(subnetMask));
            addrList.emplace_back(info);
        }
    }
    intfMap.emplace(intfName, addrList);
    return intfMap;
}

// Need to merge the below function with the code which writes the
// config file during factory reset.
//TODO openbmc/openbmc#1751
void Manager::writeToConfigurationFile()
{
    // write all the static ip address in the systemd-network conf file

    using namespace std::string_literals;
    using AddressOrigin =
        sdbusplus::xyz::openbmc_project::Network::server::IP::AddressOrigin;
    namespace fs = std::experimental::filesystem;

    for (const auto& intf : interfaces)
    {

        fs::path confPath = confDir;
        std::string fileName = "00-bmc-"s + intf.first + ".network"s;
        confPath /= fileName;
        std::fstream stream;
        stream.open(confPath.c_str(), std::fstream::out);

        // Write the device
        stream << "[" << "Match" << "]\n";
        stream << "Name=" << intf.first << "\n";

        auto addrs = intf.second->getAddresses();

        // write the network section
        stream << "[" << "Network" << "]\n";
        // DHCP
        if (intf.second->dHCPEnabled() == true)
        {
            stream << "DHCP=true\n";
            // write the dhcp section
            stream << "[DHCP]\n";
            stream << "ClientIdentifier=mac\n";
            stream.close();
            continue;
        }
        // Static
        for (const auto& addr : addrs)
        {
            if (addr.second->origin() == AddressOrigin::Static)
            {
                std::string address = addr.second->address() + "/" + std::to_string(
                                          addr.second->prefixLength());

                stream << "Address=" << address << "\n";
                if (addr.second->gateway() != "0.0.0.0" &&
                    addr.second->gateway() != "")
                {
                    stream << "Gateway=" << addr.second->gateway() << "\n";
                }

            }
        }
        stream << "Gateway=" << systemConfPtr->defaultGateway() << "\n";
        // write the route section
        stream << "[" << "Route" << "]\n";
        for(const auto& addr : addrs)
        {
            if (addr.second->origin() == AddressOrigin::Static)
            {
                int addressFamily = addr.second->type() == IP::Protocol::IPv4 ? AF_INET : AF_INET6;
                std::string destination = getNetworkID(
                                            addressFamily,
                                            addr.second->address(),
                                            addr.second->prefixLength());

                if (addr.second->gateway() != "0.0.0.0" &&
                    addr.second->gateway() != "" &&
                    destination != "0.0.0.0" &&
                    destination != "")
                {

                    stream << "Gateway=" << addr.second->gateway() << "\n";
                    stream << "Destination=" << destination << "\n";
                }

            }
        }

        stream.close();
    }
    restartSystemdNetworkd();
}

void  Manager::restartSystemdNetworkd()
{
    constexpr auto systemdNetworkdService = "systemd-networkd.service";

    auto method = bus.new_method_call(
                      SYSTEMD_BUSNAME,
                      SYSTEMD_PATH,
                      SYSTEMD_INTERFACE,
                      "RestartUnit");

    method.append(systemdNetworkdService,
                  "replace");

    bus.call_noreply(method);
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
