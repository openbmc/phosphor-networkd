#include "config.h"
#include "network_manager.hpp"

#include <phosphor-logging/log.hpp>

#include <algorithm>

#include <arpa/inet.h>
#include <dirent.h>
#include <net/if.h>


namespace phosphor
{
namespace network
{
using namespace phosphor::logging;

Manager::Manager(sdbusplus::bus::bus& bus, const char* objPath):
    details::VLANCreateIface(bus, objPath, true)
{
    auto interfaceInfoList = getInterfaceAddrs();

    for( const auto& intfInfo : interfaceInfoList )
    {
        std::string  objectPath = std::string(OBJ_NETWORK) + "/" + intfInfo.first;

        this->interfaces.emplace(std::make_pair(
                                 intfInfo.first,
                                 std::make_unique<
                                 phosphor::network::EthernetInterface >
                                 (bus, objectPath,
                                 false,intfInfo.second)));
    }
}

void Manager::vLAN(IntfName interfaceName, uint16_t id)
{
}

IntfAddrMap Manager::getInterfaceAddrs() const
{
    IntfAddrMap intfMap;
    AddrList addrList;
    struct ifaddrs* ifaddr;
    // attempt to fill struct with ifaddrs
    if (getifaddrs(&ifaddr) == -1)
    {
        log<level::ERR>("getifaddrs failed:",
                         entry("ERRNO=%s", strerror(errno)));

        //TODO: openbmc/openbmc#1462 <create the error log>

        return intfMap;
    }

    details::AddrPtr ifaddrPtr(ifaddr);
    ifaddr = nullptr;

    std::string intfName;

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
            AddrInfo info;
            char ip[INET6_ADDRSTRLEN] = { 0 };
            char subnetMask[INET6_ADDRSTRLEN] = { 0 };
            uint16_t prefix = { 0 };

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

                prefix = toCidr(subnetMask);
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

                //TODO: convert v6 mask into cidr

            }

            info.addrType = ifa->ifa_addr->sa_family;
            info.ipaddress = ip;
            info.prefix = prefix;
            addrList.emplace_back(info);
        }
    }
    intfMap.emplace(intfName, addrList);
    return intfMap;
}

uint8_t Manager::toCidr(char* subnetMask) const
{
    uint8_t netmask_cidr;
    int ipbytes[4];

    netmask_cidr = 0;
    sscanf(subnetMask, "%d.%d.%d.%d", &ipbytes[0], &ipbytes[1], &ipbytes[2],
           &ipbytes[3]);

    for (int i = 0; i < 4; i++)
    {
        switch (ipbytes[i])
        {
            case 0x80:
                netmask_cidr += 1;
                break;

            case 0xC0:
                netmask_cidr += 2;
                break;

            case 0xE0:
                netmask_cidr += 3;
                break;

            case 0xF0:
                netmask_cidr += 4;
                break;

            case 0xF8:
                netmask_cidr += 5;
                break;

            case 0xFC:
                netmask_cidr += 6;
                break;

            case 0xFE:
                netmask_cidr += 7;
                break;

            case 0xFF:
                netmask_cidr += 8;
                break;

            default:
                return netmask_cidr;
                break;
        }
    }

    return netmask_cidr;
}
}//namespace network
}//namespace phosphor
