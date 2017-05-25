#include "config.h"
#include "network_manager.hpp"
#include "elog-errors.hpp"

#include <phosphor-logging/log.hpp>

#include <algorithm>
#include <bitset>
#include <experimental/filesystem>
#include <map>

#include <arpa/inet.h>
#include <dirent.h>
#include <net/if.h>


namespace phosphor
{
namespace network
{

using namespace phosphor::logging;
namespace fs = std::experimental::filesystem;

Manager::Manager(sdbusplus::bus::bus& bus, const char* objPath):
    details::VLANCreateIface(bus, objPath, true),
    bus(bus),
    objectPath(objPath)
{
}

void Manager::createInterfaces()
{

    auto interfaceInfoList = getInterfaceAddrs();

    for (const auto& intfInfo : interfaceInfoList)
    {
        fs::path objPath = objectPath;
        objPath /= intfInfo.first;

        this->interfaces.emplace(std::make_pair(
                                     intfInfo.first,
                                     std::make_unique<
                                     phosphor::network::EthernetInterface>
                                     (bus,
                                      objPath.string(),
                                      false)));

        interfaces[intfInfo.first]->setAddressList(intfInfo.second);
    }
}

void Manager::vLAN(IntfName interfaceName, uint16_t id)
{
}

IntfAddrMap Manager::getInterfaceAddrs() const
{
    IntfAddrMap intfMap{};
    AddrList addrList{};
    struct ifaddrs* ifaddr = nullptr;

    using namespace phosphor::logging::xyz::openbmc_project::Network::Common;

    // attempt to fill struct with ifaddrs
    if (getifaddrs(&ifaddr) == -1)
    {
        elog<SystemCallFailure>(
            SystemCallFailure::API("getifaddrs"),
            SystemCallFailure::ERRNO(errno));
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
