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
    IntfAddrMap intfMap;
    AddrList addrList;
    struct ifaddrs* ifaddr;

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

            info.prefix = toCidr(info.addrType, subnetMask);

            addrList.emplace_back(info);
        }
    }
    intfMap.emplace(intfName, addrList);
    return intfMap;
}

uint8_t Manager::toCidr(int addressFamily, const std::string& subnetMask) const
{
    uint32_t buff = 0;

    if (addressFamily == AF_INET6)
    {
        return toV6Cidr(std::string(subnetMask));
    }

    auto rc = inet_pton(addressFamily, subnetMask.c_str(), &buff);
    if (rc <= 0)
    {
        log<level::ERR>("inet_pton failed:",
                         entry("SUBNETMASK=%s", subnetMask.c_str()));
    }

    buff = be32toh(buff);
    // total no of bits - total no of leading zero == total no of ones
    if (((sizeof(buff) * 8) - (__builtin_ctz(buff))) == __builtin_popcount(buff))
    {
        return __builtin_popcount(buff);
    }
    else
    {
        log<level::ERR>("Invalid Mask",
                         entry("SUBNETMASK=%s", subnetMask.c_str()));
        return 0;
    }
}

uint8_t Manager::toV6Cidr(const std::string& subnetMask) const
{
    uint8_t pos {};
    uint8_t prevPos {};
    uint8_t cidr {};
    uint16_t buff {};

    log<level::INFO>("toV6Cidr called with",
                     entry("SUBNETMASK=%s", subnetMask));
    do
    {
        //subnet mask look like ffff:ffff::
        // or ffff:c000::
        pos =  subnetMask.find(":", prevPos);
        if (pos == std::string::npos)
        {
            return cidr;
        }

        auto str = subnetMask.substr(prevPos, (pos - prevPos));
        prevPos = pos + 1;

        // String length is 0
        if (!str.length())
        {
            return cidr;
        }
        //converts it into number.
        if (sscanf(str.c_str(), "%hx", &buff) <= 0)
        {
            log<level::ERR>("Invalid SubnetMask",
                             entry("SUBNETMASK=%s", subnetMask));

            return 0;
        }

        // convert the number into bitset
        // and check for how many ones are there.
        // if we don't have all the ones then make
        // sure that all the ones should be left justify.

        if (__builtin_popcount(buff) != 16)
        {
            if (((sizeof(buff) * 8) - (__builtin_ctz(buff))) != __builtin_popcount(buff))
            {
                log<level::ERR>("Invalid SubnetMask",
                                 entry("SUBNETMASK=%s", subnetMask));

                return 0;
            }
            cidr += __builtin_popcount(buff);
            return cidr;
        }
        cidr += 16;

    }
    while (1);

    return cidr;
}

}//namespace network
}//namespace phosphor
