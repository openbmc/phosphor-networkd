#include "config.h"
#include "ipaddress.hpp"
#include "ethernet_interface.hpp"
#include "network_manager.hpp"
#include "routing_table.hpp"

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
#include <sstream>
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
                                     Manager& parent) :
                                     Ifaces(bus, objPath.c_str(), true),
                                     bus(bus),
                                     manager(parent),
                                     objPath(objPath)
{
    auto intfName = objPath.substr(objPath.rfind("/") + 1);
    interfaceName(intfName);
    dHCPEnabled(dhcpEnabled);
    mACAddress(getMACAddress());
    createIPAddressObjects();
    // Emit deferred signal.
    this->emit_object_added();
}

void EthernetInterface::createIPAddressObjects()
{
    std::string gateway;
    addrs.clear();

    auto addrs = getInterfaceAddrs()[interfaceName()];
    IP::Protocol addressType = IP::Protocol::IPv4;
    IP::AddressOrigin origin = IP::AddressOrigin::Static;
    route::Table routingTable;
    for (auto addr : addrs)
    {
        if (addr.addrType == AF_INET6)
        {
            addressType = IP::Protocol::IPv6;
        }
        if (dHCPEnabled())
        {
            origin = IP::AddressOrigin::DHCP;
        }
        else if (isLinkLocal(addr.ipaddress))
        {
            origin = IP::AddressOrigin::LinkLocal;
        }
        gateway = routingTable.getGateway(addr.addrType, addr.ipaddress, addr.prefix);

        std::string ipAddressObjectPath = generateObjectPath(addressType,
                                                             addr.ipaddress,
                                                             addr.prefix,
                                                             gateway);

        this->addrs.emplace(
                std::make_pair(
                    addr.ipaddress,
                    std::make_unique<phosphor::network::IPAddress>(
                        bus,
                        ipAddressObjectPath.c_str(),
                        *this,
                        addressType,
                        addr.ipaddress,
                        origin,
                        addr.prefix,
                        gateway)));
    }

}

void EthernetInterface::iP(IP::Protocol protType,
                           std::string ipaddress,
                           uint8_t prefixLength,
                           std::string gateway)
{

    if (dHCPEnabled())
    {
        log<level::INFO>("DHCP enabled on the interface"),
                        entry("INTERFACE=%s",interfaceName());
        return;
    }

    IP::AddressOrigin origin = IP::AddressOrigin::Static;

    std::string objectPath = generateObjectPath(protType,
                                                ipaddress,
                                                prefixLength,
                                                gateway);

    this->addrs.emplace(
            std::make_pair(ipaddress,
                           std::make_unique<phosphor::network::IPAddress>(
                                bus,
                                objectPath.c_str(),
                                *this,
                                protType,
                                ipaddress,
                                origin,
                                prefixLength,
                                gateway)));

    manager.writeToConfigurationFile();
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

std::string EthernetInterface::generateId(const std::string& ipaddress,
                                          uint8_t prefixLength,
                                          const std::string& gateway)
{
    std::stringstream hexId;
    std::string hashString = ipaddress;
    hashString += std::to_string(prefixLength);
    hashString += gateway;

    // Only want 8 hex digits.
    hexId << std::hex << ((std::hash<std::string> {}(
                               hashString)) & 0xFFFFFFFF);
    return hexId.str();
}

void EthernetInterface::deleteObject(const std::string& ipaddress)
{
    auto it = addrs.find(ipaddress);
    if (it == addrs.end())
    {
        log<level::ERR>("DeleteObject:Unable to find the object.");
        return;
    }
    this->addrs.erase(it);
    manager.writeToConfigurationFile();
}

std::string EthernetInterface::generateObjectPath(IP::Protocol addressType,
                                                  const std::string& ipaddress,
                                                  uint8_t prefixLength,
                                                  const std::string& gateway) const
{
    std::string type = convertForMessage(addressType);
    type = type.substr(type.rfind('.') + 1);
    std::transform(type.begin(), type.end(), type.begin(), ::tolower);

    std::experimental::filesystem::path objectPath;
    objectPath /= objPath;
    objectPath /= type;
    objectPath /= generateId(ipaddress, prefixLength, gateway);
    return objectPath.string();
}

bool EthernetInterface::dHCPEnabled(bool value)
{
    EthernetInterfaceIntf::dHCPEnabled(value);
    if (value == true)
    {
        manager.writeToConfigurationFile();
        createIPAddressObjects();
    }
    return value;
}

}//namespace network
}//namespace phosphor
