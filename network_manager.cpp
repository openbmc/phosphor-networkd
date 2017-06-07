#include "config.h"
#include "network_manager.hpp"
#include "network_config.hpp"
#include "xyz/openbmc_project/Common/error.hpp"

#include <phosphor-logging/log.hpp>
#include <phosphor-logging/elog-errors.hpp>

#include <algorithm>
#include <bitset>
#include <experimental/filesystem>
#include <map>

#include <arpa/inet.h>
#include <dirent.h>
#include <net/if.h>

#include <string>

namespace phosphor
{
namespace network
{

using namespace phosphor::logging;
namespace fs = std::experimental::filesystem;

Manager::Manager(sdbusplus::bus::bus& bus, const char* objPath):
    details::VLANCreateIface(bus, objPath, true)
{
    auto interfaceInfoList = getInterfaceAddrs();

    for (const auto& intfInfo : interfaceInfoList)

    {

        fs::path objectPath = std::string(OBJ_NETWORK);
        objectPath /= intfInfo.first;

        this->interfaces.emplace(std::make_pair(
                                     intfInfo.first,
                                     std::make_unique<
                                     phosphor::network::EthernetInterface>
                                     (bus,
                                      objectPath.string(),
                                      false,
                                      intfInfo.second)));
    }
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

    using namespace sdbusplus::xyz::openbmc_project::Common::Error;
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

}//namespace network
}//namespace phosphor
