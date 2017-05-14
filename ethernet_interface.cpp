#include "config.h"
#include "config_parser.hpp"
#include "ipaddress.hpp"
#include "ethernet_interface.hpp"

#include <phosphor-logging/log.hpp>

#include <arpa/inet.h>
#include <linux/ethtool.h>
#include <net/if.h>
#include <linux/sockios.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <string>
#include <algorithm>
#include <experimental/filesystem>

namespace phosphor
{
namespace network
{

using namespace phosphor::logging;
constexpr auto MAC_ADDRESS_FORMAT = "%02X:%02X:%02X:%02X:%02X:%02X";
constexpr size_t SIZE_MAC = 18;
constexpr size_t SIZE_BUFF = 512;

EthernetInterface::EthernetInterface(sdbusplus::bus::bus& bus,
                                     const std::string& objPath,
                                     bool dhcpEnabled,
                                     const AddrList& addrs) :
                                     Ifaces(bus, objPath.c_str(), true),
                                     bus(bus)
{
    auto intfName = objPath.substr(objPath.rfind("/") + 1);
    interfaceName(intfName);
    dHCPEnabled(dhcpEnabled);
    mACAddress(getMACAddress());
    std::string gateway;

    IP::Protocol addressType = IP::Protocol::IPv4;

    for (auto addr : addrs)
    {
        if (addr.addrType == AF_INET6)
        {
            addressType = IP::Protocol::IPv6;
        }

        std::string ipAddressObjectPath = getAddressObjectPath(addressType);

        this->addrs.emplace(std::make_pair(addr.ipaddress, std::make_unique<
                                           phosphor::network::IPAddress>(
                                           bus,
                                           ipAddressObjectPath.c_str(),
                                           *this,
                                           addressType,
                                           addr.ipaddress,
                                           addr.prefix,
                                           gateway)));
    }
    // Emit deferred signal.
    this->emit_object_added();
}

void EthernetInterface::iP(IP::Protocol protType,
                           std::string ipaddress,
                           uint8_t prefixLength,
                           std::string gateway)
{

    IP::Protocol protocolType  = protType;
    std::string objectPath = getAddressObjectPath(protocolType);

    this->addrs.emplace(std::make_pair(ipaddress, std::make_unique<
                                       phosphor::network::IPAddress>(
                                       bus,
                                       objectPath.c_str(),
                                       *this,
                                       protocolType,
                                       ipaddress,
                                       prefixLength,
                                       gateway)));

}


/*
Note: We don't have support for  ethtool now
will enable this code once we bring the ethtool
in the image.
TODO: https://github.com/openbmc/openbmc/issues/1484
*/

InterfaceInfo EthernetInterface::getInterfaceInfo() const
{
    int sock{-1};
    struct ifreq ifr{0};
    struct ethtool_cmd edata{0};
    LinkSpeed speed {0};
    Autoneg autoneg {0};
    DuplexMode duplex {0};
    do
    {
        sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
        if (sock < 0)
        {
            log<level::ERR>("socket creation  failed:",
                            entry("ERROR=%s", strerror(errno)));
            break;
        }

        strncpy(ifr.ifr_name, interfaceName().c_str(), sizeof(ifr.ifr_name));
        ifr.ifr_data = reinterpret_cast<char*>(&edata);

        edata.cmd = ETHTOOL_GSET;

        if (ioctl(sock, SIOCETHTOOL, &ifr) < 0)
        {
            log<level::ERR>("ioctl failed for SIOCETHTOOL:",
                            entry("ERROR=%s", strerror(errno)));
            break;

        }
        speed = edata.speed;
        duplex = edata.duplex;
        autoneg = edata.autoneg;
    }
    while (0);

    if (sock)
    {
        close(sock);
    }
    return std::make_tuple(speed, duplex, autoneg);
}

/** @brief get the mac address of the interface.
 *  @return macaddress on success
 */

std::string EthernetInterface::getMACAddress() const
{
    struct ifreq ifr;
    struct ifconf ifc;
    char buf[SIZE_BUFF];
    char macAddress[SIZE_MAC] = "";

    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (sock < 0)
    {
        log<level::ERR>("socket creation  failed:",
                        entry("ERROR=%s", strerror(errno)));
        return macAddress;
    }

    ifc.ifc_len = sizeof(buf);
    ifc.ifc_buf = buf;
    if (ioctl(sock, SIOCGIFCONF, &ifc) < 0)
    {
        log<level::ERR>("ioctl failed for SIOCGIFCONF:",
                        entry("ERROR=%s", strerror(errno)));
        return macAddress;
    }

    struct ifreq* it = ifc.ifc_req;
    const struct ifreq* const end = it + (ifc.ifc_len / sizeof(struct ifreq));

    for (; it != end; ++it)
    {
        if (interfaceName() == it->ifr_name)
        {
            break;
        }
    }
    if (interfaceName() == it->ifr_name)
    {
        strcpy(ifr.ifr_name, it->ifr_name);
        if (ioctl(sock, SIOCGIFHWADDR, &ifr) != 0)
        {
            log<level::ERR>("ioctl failed for SIOCGIFHWADDR:",
                            entry("ERROR=%s", strerror(errno)));
            return macAddress;
        }

        snprintf(macAddress, SIZE_MAC, MAC_ADDRESS_FORMAT,
                 ifr.ifr_hwaddr.sa_data[0], ifr.ifr_hwaddr.sa_data[1],
                 ifr.ifr_hwaddr.sa_data[2], ifr.ifr_hwaddr.sa_data[3],
                 ifr.ifr_hwaddr.sa_data[4], ifr.ifr_hwaddr.sa_data[5]);
    }
    return macAddress;
}

size_t EthernetInterface::getAddressCount(IP::Protocol addressType) const
{
    size_t count = 0;

    std::for_each(addrs.cbegin(), addrs.cend(),
                  [&count,addressType](const auto & addr)
    {
        if (addr.second->type() == addressType)
        {
            count += 1;
        }
    });

    return count;
}

void EthernetInterface::deleteObject(const std::string& ipaddress)
{
    this->addrs.erase(addrs.find(ipaddress));
}

std::string EthernetInterface::getAddressObjectPath(IP::Protocol
                                                    addressType) const
{

    std::string type = convertForMessage(addressType);
    type = type.substr(type.rfind('.')+1);
    std::transform(type.begin(), type.end(), type.begin(), ::tolower);

    std::experimental::filesystem::path objectPath;
    objectPath /= std::string(OBJ_NETWORK);
    objectPath /= interfaceName();
    objectPath /= type;
    objectPath /= std::to_string(getAddressCount(addressType));
    return objectPath.string();

}

}//namespace network
}//namespace phosphor
