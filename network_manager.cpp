#include "config.h"
#include "network_manager.hpp"

#include <phosphor-logging/log.hpp>

#include <algorithm>
#include <memory>

#include <arpa/inet.h>
#include <dirent.h>
#include <ifaddrs.h>
#include <net/if.h>


namespace phosphor
{
namespace network
{
using namespace phosphor::logging;

template<typename T>
using CustomUniquePtr = std::unique_ptr<T, std::function<void(T*)>>;

Manager::Manager(sdbusplus::bus::bus& bus, const char* objPath):
    details::VLANCreateIface(bus, objPath, true), busLog(bus)
{
    auto interfaceInfoList = getInterfaceAndaddrs();


    std::for_each(interfaceInfoList.cbegin(), interfaceInfoList.cend(),
                  [this, &bus](const auto & intfInfo)
    {
        std::string  objectPath = std::string(OBJ_NETWORK) + "/" + intfInfo.first;

        this->interfaces.emplace(std::make_pair(
                                 intfInfo.first,
                                 std::make_unique<
                                 phosphor::network::EthernetInterface >
                                 (bus, objectPath.c_str(), intfInfo.first,
                                 false)));

    });

}

void Manager::vLAN(IntfName interfaceName, uint16_t id)
{
}

details::IntfAddrMap Manager::getInterfaceAndaddrs() const
{
    details::IntfAddrMap intfMap;
    details::AddrList addrList;
    struct ifaddrs* ifaddr;
    // attempt to fill struct with ifaddrs
    if (getifaddrs(&ifaddr) == -1)
    {
        log<level::ERR>("getifaddrs failed:",
                         entry("ERRNO=%s", strerror(errno));

        //TODO: https://github.com/openbmc/openbmc/issues/1490

        return intfMap;
    }

    CustomUniquePtr<ifaddrs> ifaddrPtr(ifaddr, [](ifaddrs * addr)
    {
        freeifaddrs(addr);
    });

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
            details::AddrInfo info;
            char tmp[INET6_ADDRSTRLEN] = { 0 };

            if (ifa->ifa_addr->sa_family == AF_INET)
            {

                inet_ntop(ifa->ifa_addr->sa_family,
                          &(((struct sockaddr_in*)(ifa->ifa_addr))->sin_addr),
                          tmp,
                          sizeof(tmp));
            }
            else
            {
                inet_ntop(ifa->ifa_addr->sa_family,
                          &(((struct sockaddr_in6*)(ifa->ifa_addr))->sin6_addr),
                          tmp,
                          sizeof(tmp));

            }

            info.addrType = ifa->ifa_addr->sa_family;
            info.ipaddress = tmp;
            addrList.emplace_back(info);
        }
    }
    intfMap.emplace(intfName, addrList);
    return intfMap;
}
}//namespace network
}//namespace phosphor
