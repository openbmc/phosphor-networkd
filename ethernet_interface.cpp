#include "ethernet_interface.hpp"

#include <phosphor-logging/log.hpp>

#include <linux/ethtool.h>
#include <linux/if.h>
#include <linux/sockios.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

namespace phosphor
{
namespace network
{

using namespace phosphor::logging;
constexpr auto MAC_ADDRESS_FORMAT = "%02X:%02X:%02X:%02X:%02X:%02X";
constexpr size_t SIZE_MAC = 18;
constexpr size_t SIZE_BUFF = 512;

EthernetInterface::EthernetInterface(sdbusplus::bus::bus& bus,
                   const char* objPath,
                   std::string intfName,
                   bool dhcpEnabled) :
                   details::EthernetIface(bus, objPath),
                   busLog(bus)
{
    interfaceName(intfName);
    dHCPEnabled(dhcpEnabled);
    //speed(getSpeed());
    mACAddress(getMACAddress());
    // Emit deferred signal.
    this->emit_object_added();
}

/*
Note:- We don't have support for  ethtool now
will enable this code once we bring the ethtool
in the image.
*/
InterfaceInfo EthernetInterface::getInterfaceInfo() const
{
    int sock{-1};
    struct ifreq ifr{0};
    struct ethtool_cmd edata{0};
    uint16_t speed {0};
    uint8_t autoneg {0};
    uint8_t duplex {0};
    do
    {
        sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
        if (sock < 0)
        {
            log<level::ERR>("socket creation  failed:",
                    entry("ERROR = %s", strerror(errno)));
            break;
        }

        strncpy(ifr.ifr_name, interfaceName().c_str(), sizeof(ifr.ifr_name));
        ifr.ifr_data = (char*)&edata;

        edata.cmd = ETHTOOL_GSET;

        if (ioctl(sock, SIOCETHTOOL, &ifr) < 0)
        {
            log<level::ERR>("ioctl failed for SIOCETHTOOL:",
                    entry("ERROR = %s", strerror(errno)));
            break;

        }
        speed = edata.speed;
        duplex = edata.duplex;
        autoneg = edata.autoneg;
    }while(0);

    if (sock)
        close(sock);
    return std::make_tuple(speed,duplex,autoneg);
}

/** @brief get the mac address of the interface.
 *  @return macaddress on success
 */

std::string EthernetInterface::getMACAddress() const
{
    struct ifreq ifr;
    struct ifconf ifc;
    char buf[SIZE_BUFF];
    char mac_address[SIZE_MAC];

    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (sock < 0)
    {
        log<level::ERR>("socket creation  failed:",
                 entry("ERROR = %s", strerror(errno)));
        return mac_address;
    }

    ifc.ifc_len = sizeof(buf);
    ifc.ifc_buf = buf;
    if (ioctl(sock, SIOCGIFCONF, &ifc) < 0 )
    {
        log<level::ERR>("ioctl failed for SIOCGIFCONF:",
                entry("ERROR = %s", strerror(errno)));
        return mac_address;
    }

    struct ifreq* it = ifc.ifc_req;
    const struct ifreq* const end = it + (ifc.ifc_len / sizeof(struct ifreq));

    for (; it != end; ++it)
    {
        strcpy(ifr.ifr_name, it->ifr_name);
        if (interfaceName() == ifr.ifr_name)
            break;
    }
    if (interfaceName() == it->ifr_name)
    {

        if (ioctl(sock, SIOCGIFHWADDR, &ifr) != 0)
        {
            log<level::ERR>("ioctl failed for SIOCGIFHWADDR:",
                    entry("errno = %s", strerror(errno)));
            return mac_address;
        }
        // maximum size of mac address is 12 bytes
        // SIZE_MAC is defined as 18 bytes including ":"
        memcpy(mac_address, ifr.ifr_hwaddr.sa_data, SIZE_MAC-6);
        snprintf(mac_address, SIZE_MAC, MAC_ADDRESS_FORMAT,
                ifr.ifr_hwaddr.sa_data[0], ifr.ifr_hwaddr.sa_data[1],
                ifr.ifr_hwaddr.sa_data[2], ifr.ifr_hwaddr.sa_data[3],
                ifr.ifr_hwaddr.sa_data[4], ifr.ifr_hwaddr.sa_data[5]);
    }
    return mac_address;
}
}//namespace network
}//namespace phosphor
