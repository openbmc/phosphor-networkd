#include "config.h"
#include "network_manager.hpp"

#include <phosphor-logging/log.hpp>

#include <algorithm>
#include <experimental/filesystem>
#include <arpa/inet.h>
#include <dirent.h>
#include <net/if.h>

#include <regex>
#include <string>
#include <fstream>

namespace phosphor
{
namespace network
{

using namespace phosphor::logging;
namespace fs = std::experimental::filesystem;

Manager::Manager(sdbusplus::bus::bus& bus, const char* objPath):
    details::VLANCreateIface(bus, objPath, true),
    ResetInherit(bus, objPath)
{
    auto interfaceInfoList = getInterfaceAddrs();

    for( const auto& intfInfo : interfaceInfoList )
    {

        fs::path objectPath = std::string(OBJ_NETWORK);
        objectPath /= intfInfo.first;

        this->interfaces.emplace(std::make_pair(
                                 intfInfo.first,
                                 std::make_unique<
                                 phosphor::network::EthernetInterface >
                                 (bus, objectPath.c_str(),
                                 false,intfInfo.second)));
    }
}

void Manager::vLAN(IntfName interfaceName, uint16_t id)
{
}

void Manager::reset()
{
    const std::string networkConfig = "/tmp/mtritz";
    const std::regex extension("\\.network$");
    std::ofstream filestream;

    if(fs::is_directory(networkConfig))
    {
        for(auto& file : fs::directory_iterator(networkConfig))
        {
            std::cmatch match;
            auto path = file.path();
            std::regex_search(path.c_str(), match, extension);

            if(!match.empty())
            {
                filestream.open(path);
                std::string intfName = path.filename().c_str();

                filestream << "[Match]\n" << "Name=" <<
                        intfName.substr(0, intfName.size() - 8).c_str() <<
                        "\n[Network]\n" << "DHCP=true";

                filestream.close();
            }
        }

        log<level::INFO>("Network factory reset completed.");
    }
    else
    {
        log<level::ERR>("Network configuration directory not found!");
    }

    return;
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

            if (ifa->ifa_addr->sa_family == AF_INET)
            {

                inet_ntop(ifa->ifa_addr->sa_family,
                          &(((struct sockaddr_in*)(ifa->ifa_addr))->sin_addr),
                          ip,
                          sizeof(ip));
            }
            else
            {
                inet_ntop(ifa->ifa_addr->sa_family,
                          &(((struct sockaddr_in6*)(ifa->ifa_addr))->sin6_addr),
                          ip,
                          sizeof(ip));

            }

            info.addrType = ifa->ifa_addr->sa_family;
            info.ipaddress = ip;
            addrList.emplace_back(info);
        }
    }
    intfMap.emplace(intfName, addrList);
    return intfMap;
}
}//namespace network
}//namespace phosphor
