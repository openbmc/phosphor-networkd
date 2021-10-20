#include "config.h"

#include "ethernet_interface.hpp"

#include "config_parser.hpp"
#include "neighbor.hpp"
#include "network_manager.hpp"
#include "routing_table.hpp"
#include "vlan_interface.hpp"

#include <arpa/inet.h>
#include <fmt/format.h>
#include <linux/ethtool.h>
#include <linux/rtnetlink.h>
#include <linux/sockios.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/log.hpp>
#include <sdbusplus/bus/match.hpp>
#include <sstream>
#include <stdplus/raw.hpp>
#include <string>
#include <string_view>
#include <unordered_map>
#include <variant>
#include <xyz/openbmc_project/Common/error.hpp>

namespace phosphor
{
namespace network
{

using namespace phosphor::logging;
using namespace sdbusplus::xyz::openbmc_project::Common::Error;
using NotAllowed = sdbusplus::xyz::openbmc_project::Common::Error::NotAllowed;
using NotAllowedArgument = xyz::openbmc_project::Common::NotAllowed;
using Argument = xyz::openbmc_project::Common::InvalidArgument;
constexpr auto RESOLVED_SERVICE = "org.freedesktop.resolve1";
constexpr auto RESOLVED_INTERFACE = "org.freedesktop.resolve1.Link";
constexpr auto PROPERTY_INTERFACE = "org.freedesktop.DBus.Properties";
constexpr auto RESOLVED_SERVICE_PATH = "/org/freedesktop/resolve1/link/";
constexpr auto METHOD_GET = "Get";

struct EthernetIntfSocket
{
    EthernetIntfSocket(int domain, int type, int protocol)
    {
        if ((sock = socket(domain, type, protocol)) < 0)
        {
            log<level::ERR>("socket creation failed:",
                            entry("ERROR=%s", strerror(errno)));
        }
    }

    ~EthernetIntfSocket()
    {
        if (sock >= 0)
        {
            close(sock);
        }
    }

    int sock{-1};
};

std::map<EthernetInterface::DHCPConf, std::string> mapDHCPToSystemd = {
    {EthernetInterface::DHCPConf::both, "true"},
    {EthernetInterface::DHCPConf::v4, "ipv4"},
    {EthernetInterface::DHCPConf::v6, "ipv6"},
    {EthernetInterface::DHCPConf::none, "false"}};

EthernetInterface::EthernetInterface(sdbusplus::bus::bus& bus,
                                     const std::string& objPath,
                                     DHCPConf dhcpEnabled, Manager& parent,
                                     bool emitSignal,
                                     std::optional<bool> enabled) :
    Ifaces(bus, objPath.c_str(), true),
    bus(bus), manager(parent), objPath(objPath)
{
    auto intfName = objPath.substr(objPath.rfind("/") + 1);
    std::replace(intfName.begin(), intfName.end(), '_', '.');
    interfaceName(intfName);
    EthernetInterfaceIntf::dhcpEnabled(dhcpEnabled);
    EthernetInterfaceIntf::ipv6AcceptRA(getIPv6AcceptRAFromConf());
    EthernetInterfaceIntf::nicEnabled(enabled ? *enabled : queryNicEnabled());
    route::Table routingTable;
    auto gatewayList = routingTable.getDefaultGateway();
    auto gateway6List = routingTable.getDefaultGateway6();
    std::string defaultGateway;
    std::string defaultGateway6;

    for (auto& gateway : gatewayList)
    {
        if (gateway.first == intfName)
        {
            defaultGateway = gateway.second;
            break;
        }
    }

    for (auto& gateway6 : gateway6List)
    {
        if (gateway6.first == intfName)
        {
            defaultGateway6 = gateway6.second;
            break;
        }
    }

    EthernetInterfaceIntf::defaultGateway(defaultGateway);
    EthernetInterfaceIntf::defaultGateway6(defaultGateway6);
    // Don't get the mac address from the system as the mac address
    // would be same as parent interface.
    if (intfName.find(".") == std::string::npos)
    {
        MacAddressIntf::macAddress(getMACAddress(intfName));
    }
    EthernetInterfaceIntf::ntpServers(getNTPServersFromConf());

    EthernetInterfaceIntf::linkUp(linkUp());
    EthernetInterfaceIntf::mtu(mtu());

#ifdef NIC_SUPPORTS_ETHTOOL
    InterfaceInfo ifInfo = EthernetInterface::getInterfaceInfo();

    EthernetInterfaceIntf::autoNeg(std::get<2>(ifInfo));
    EthernetInterfaceIntf::speed(std::get<0>(ifInfo));
#endif

    // Emit deferred signal.
    if (emitSignal)
    {
        this->emit_object_added();
    }
}

static IP::Protocol convertFamily(int family)
{
    switch (family)
    {
        case AF_INET:
            return IP::Protocol::IPv4;
        case AF_INET6:
            return IP::Protocol::IPv6;
    }

    throw std::invalid_argument("Bad address family");
}

void EthernetInterface::disableDHCP(IP::Protocol protocol)
{
    DHCPConf dhcpState = EthernetInterfaceIntf::dhcpEnabled();
    if (dhcpState == EthernetInterface::DHCPConf::both)
    {
        if (protocol == IP::Protocol::IPv4)
        {
            dhcpEnabled(EthernetInterface::DHCPConf::v6);
        }
        else if (protocol == IP::Protocol::IPv6 &&
                 !EthernetInterfaceIntf::ipv6AcceptRA())
        {
            // systemd-networkd defacto enables DHCPv6 when RA is enabled
            dhcpEnabled(EthernetInterface::DHCPConf::v4);
        }
    }
    else if ((dhcpState == EthernetInterface::DHCPConf::v4) &&
             (protocol == IP::Protocol::IPv4))
    {
        dhcpEnabled(EthernetInterface::DHCPConf::none);
    }
    else if ((dhcpState == EthernetInterface::DHCPConf::v6) &&
             ((protocol == IP::Protocol::IPv6) &&
              !EthernetInterfaceIntf::ipv6AcceptRA()))
    {
        // systemd-networkd defacto enables DHCPv6 when RA is enabled
        dhcpEnabled(EthernetInterface::DHCPConf::none);
    }
}

bool EthernetInterface::dhcpIsEnabled(IP::Protocol family, bool ignoreProtocol)
{
    bool dhcpv6Enabled = ((EthernetInterfaceIntf::dhcpEnabled() ==
                           EthernetInterface::DHCPConf::both)) ||
                         (((EthernetInterfaceIntf::dhcpEnabled() ==
                            EthernetInterface::DHCPConf::v6)) &&
                          ((family == IP::Protocol::IPv6) || ignoreProtocol)) ||
                         EthernetInterfaceIntf::ipv6AcceptRA();
    bool dhcpv4Enabled = ((EthernetInterfaceIntf::dhcpEnabled() ==
                           EthernetInterface::DHCPConf::both)) ||
                         ((EthernetInterfaceIntf::dhcpEnabled() ==
                           EthernetInterface::DHCPConf::v4) &&
                          ((family == IP::Protocol::IPv4) || ignoreProtocol));
    return dhcpv6Enabled || dhcpv4Enabled;
}

bool EthernetInterface::dhcpToBeEnabled(IP::Protocol family,
                                        const std::string& nextDHCPState)
{
    return ((nextDHCPState == "true") ||
            ((nextDHCPState == "ipv6") && (family == IP::Protocol::IPv6)) ||
            ((nextDHCPState == "ipv4") && (family == IP::Protocol::IPv4)));
}

bool EthernetInterface::originIsManuallyAssigned(IP::AddressOrigin origin)
{
    return (
#ifdef LINK_LOCAL_AUTOCONFIGURATION
        (origin == IP::AddressOrigin::Static)
#else
        (origin == IP::AddressOrigin::Static ||
         origin == IP::AddressOrigin::LinkLocal)
#endif

    );
}

void EthernetInterface::createIPAddressObjects()
{
    addrs.clear();

    auto addrs = getInterfaceAddrs()[interfaceName()];

    for (auto& addr : addrs)
    {
        IP::Protocol addressType = convertFamily(addr.addrType);
        IP::AddressOrigin origin = IP::AddressOrigin::Static;
        if (dhcpIsEnabled(addressType))
        {
            origin = IP::AddressOrigin::DHCP;
        }
        if (isLinkLocalIP(addr.ipaddress))
        {
            origin = IP::AddressOrigin::LinkLocal;
        }
        // Obsolete parameter
        std::string gateway = "";

        std::string ipAddressObjectPath = generateObjectPath(
            addressType, addr.ipaddress, addr.prefix, gateway, origin);

        this->addrs.insert_or_assign(
            addr.ipaddress,
            std::make_shared<phosphor::network::IPAddress>(
                bus, ipAddressObjectPath.c_str(), *this, addressType,
                addr.ipaddress, origin, addr.prefix, gateway));
    }
}

void EthernetInterface::createStaticNeighborObjects()
{
    staticNeighbors.clear();

    NeighborFilter filter;
    filter.interface = ifIndex();
    filter.state = NUD_PERMANENT;
    auto neighbors = getCurrentNeighbors(filter);
    for (const auto& neighbor : neighbors)
    {
        if (!neighbor.mac)
        {
            continue;
        }
        std::string ip = toString(neighbor.address);
        std::string mac = mac_address::toString(*neighbor.mac);
        std::string objectPath = generateStaticNeighborObjectPath(ip, mac);
        staticNeighbors.emplace(ip,
                                std::make_shared<phosphor::network::Neighbor>(
                                    bus, objectPath.c_str(), *this, ip, mac,
                                    Neighbor::State::Permanent));
    }
}

unsigned EthernetInterface::ifIndex() const
{
    unsigned idx = if_nametoindex(interfaceName().c_str());
    if (idx == 0)
    {
        throw std::system_error(errno, std::generic_category(),
                                "if_nametoindex");
    }
    return idx;
}

ObjectPath EthernetInterface::ip(IP::Protocol protType, std::string ipaddress,
                                 uint8_t prefixLength, std::string gateway)
{
    if (dhcpIsEnabled(protType))
    {
        log<level::INFO>("DHCP enabled on the interface"),
            entry("INTERFACE=%s", interfaceName().c_str());
        disableDHCP(protType);
    }

    IP::AddressOrigin origin = IP::AddressOrigin::Static;

    int addressFamily = (protType == IP::Protocol::IPv4) ? AF_INET : AF_INET6;

    if (!isValidIP(addressFamily, ipaddress))
    {
        log<level::ERR>("Not a valid IP address"),
            entry("ADDRESS=%s", ipaddress.c_str());
        elog<InvalidArgument>(Argument::ARGUMENT_NAME("ipaddress"),
                              Argument::ARGUMENT_VALUE(ipaddress.c_str()));
    }

    // Gateway is an obsolete parameter
    gateway = "";

    if (!isValidPrefix(addressFamily, prefixLength))
    {
        log<level::ERR>("PrefixLength is not correct "),
            entry("PREFIXLENGTH=%" PRIu8, prefixLength);
        elog<InvalidArgument>(
            Argument::ARGUMENT_NAME("prefixLength"),
            Argument::ARGUMENT_VALUE(std::to_string(prefixLength).c_str()));
    }

    std::string objectPath =
        generateObjectPath(protType, ipaddress, prefixLength, gateway, origin);
    this->addrs.insert_or_assign(ipaddress,
                                 std::make_shared<phosphor::network::IPAddress>(
                                     bus, objectPath.c_str(), *this, protType,
                                     ipaddress, origin, prefixLength, gateway));

    writeConfigurationFile();
    manager.reloadConfigs();

    return objectPath;
}

ObjectPath EthernetInterface::neighbor(std::string ipAddress,
                                       std::string macAddress)
{
    if (!isValidIP(AF_INET, ipAddress) && !isValidIP(AF_INET6, ipAddress))
    {
        log<level::ERR>("Not a valid IP address",
                        entry("ADDRESS=%s", ipAddress.c_str()));
        elog<InvalidArgument>(Argument::ARGUMENT_NAME("ipAddress"),
                              Argument::ARGUMENT_VALUE(ipAddress.c_str()));
    }
    if (!mac_address::isUnicast(mac_address::fromString(macAddress)))
    {
        log<level::ERR>("Not a valid MAC address",
                        entry("MACADDRESS=%s", ipAddress.c_str()));
        elog<InvalidArgument>(Argument::ARGUMENT_NAME("macAddress"),
                              Argument::ARGUMENT_VALUE(macAddress.c_str()));
    }

    std::string objectPath =
        generateStaticNeighborObjectPath(ipAddress, macAddress);
    staticNeighbors.emplace(ipAddress,
                            std::make_shared<phosphor::network::Neighbor>(
                                bus, objectPath.c_str(), *this, ipAddress,
                                macAddress, Neighbor::State::Permanent));

    writeConfigurationFile();
    manager.reloadConfigs();

    return objectPath;
}

#ifdef NIC_SUPPORTS_ETHTOOL
/*
  Enable this code if your NIC driver supports the ETHTOOL features.
  Do this by adding the following to your phosphor-network*.bbappend file.
     EXTRA_OECONF_append = " --enable-nic-ethtool=yes"
  The default compile mode is to omit getInterfaceInfo()
*/
InterfaceInfo EthernetInterface::getInterfaceInfo() const
{
    ifreq ifr = {};
    ethtool_cmd edata = {};
    LinkSpeed speed = {};
    Autoneg autoneg = {};
    DuplexMode duplex = {};
    LinkUp linkState = {};
    NICEnabled enabled = {};
    MTU mtuSize = {};
    EthernetIntfSocket eifSocket(PF_INET, SOCK_DGRAM, IPPROTO_IP);

    if (eifSocket.sock < 0)
    {
        return std::make_tuple(speed, duplex, autoneg, linkState, enabled,
                               mtuSize);
    }

    std::strncpy(ifr.ifr_name, interfaceName().c_str(), IFNAMSIZ - 1);
    ifr.ifr_data = reinterpret_cast<char*>(&edata);

    edata.cmd = ETHTOOL_GSET;
    if (ioctl(eifSocket.sock, SIOCETHTOOL, &ifr) >= 0)
    {
        speed = edata.speed;
        duplex = edata.duplex;
        autoneg = edata.autoneg;
    }

    enabled = nicEnabled();
    linkState = linkUp();
    mtuSize = mtu();

    return std::make_tuple(speed, duplex, autoneg, linkState, enabled, mtuSize);
}
#endif

/** @brief get the mac address of the interface.
 *  @return macaddress on success
 */

std::string
    EthernetInterface::getMACAddress(const std::string& interfaceName) const
{
    std::string activeMACAddr = MacAddressIntf::macAddress();
    EthernetIntfSocket eifSocket(PF_INET, SOCK_DGRAM, IPPROTO_IP);

    if (eifSocket.sock < 0)
    {
        return activeMACAddr;
    }

    ifreq ifr = {};
    std::strncpy(ifr.ifr_name, interfaceName.c_str(), IFNAMSIZ - 1);
    if (ioctl(eifSocket.sock, SIOCGIFHWADDR, &ifr) != 0)
    {
        log<level::ERR>("ioctl failed for SIOCGIFHWADDR:",
                        entry("ERROR=%s", strerror(errno)));
        elog<InternalFailure>();
    }

    static_assert(sizeof(ifr.ifr_hwaddr.sa_data) >= sizeof(ether_addr));
    std::string_view hwaddr(reinterpret_cast<char*>(ifr.ifr_hwaddr.sa_data),
                            sizeof(ifr.ifr_hwaddr.sa_data));
    return mac_address::toString(stdplus::raw::copyFrom<ether_addr>(hwaddr));
}

std::string EthernetInterface::generateId(const std::string& ipaddress,
                                          uint8_t prefixLength,
                                          const std::string& gateway,
                                          const std::string& origin)
{
    std::stringstream hexId;
    std::string hashString = ipaddress;
    hashString += std::to_string(prefixLength);
    hashString += gateway;
    hashString += origin;

    // Only want 8 hex digits.
    hexId << std::hex << ((std::hash<std::string>{}(hashString)) & 0xFFFFFFFF);
    return hexId.str();
}

std::string EthernetInterface::generateNeighborId(const std::string& ipAddress,
                                                  const std::string& macAddress)
{
    std::stringstream hexId;
    std::string hashString = ipAddress + macAddress;

    // Only want 8 hex digits.
    hexId << std::hex << ((std::hash<std::string>{}(hashString)) & 0xFFFFFFFF);
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

    writeConfigurationFile();
    manager.reloadConfigs();
}

void EthernetInterface::deleteStaticNeighborObject(const std::string& ipAddress)
{
    auto it = staticNeighbors.find(ipAddress);
    if (it == staticNeighbors.end())
    {
        log<level::ERR>(
            "DeleteStaticNeighborObject:Unable to find the object.");
        return;
    }
    staticNeighbors.erase(it);

    writeConfigurationFile();
    manager.reloadConfigs();
}

void EthernetInterface::deleteVLANFromSystem(const std::string& interface)
{
    auto confDir = manager.getConfDir();
    fs::path networkFile = confDir;
    networkFile /= systemd::config::networkFilePrefix + interface +
                   systemd::config::networkFileSuffix;

    fs::path deviceFile = confDir;
    deviceFile /= interface + systemd::config::deviceFileSuffix;

    // delete the vlan network file
    if (fs::is_regular_file(networkFile))
    {
        fs::remove(networkFile);
    }

    // delete the vlan device file
    if (fs::is_regular_file(deviceFile))
    {
        fs::remove(deviceFile);
    }

    // TODO  systemd doesn't delete the virtual network interface
    // even after deleting all the related configuartion.
    // https://github.com/systemd/systemd/issues/6600
    try
    {
        deleteInterface(interface);
    }
    catch (const InternalFailure& e)
    {
        commit<InternalFailure>();
    }
}

void EthernetInterface::deleteVLANObject(const std::string& interface)
{
    auto it = vlanInterfaces.find(interface);
    if (it == vlanInterfaces.end())
    {
        log<level::ERR>("DeleteVLANObject:Unable to find the object",
                        entry("INTERFACE=%s", interface.c_str()));
        return;
    }

    deleteVLANFromSystem(interface);
    // delete the interface
    vlanInterfaces.erase(it);

    writeConfigurationFile();
    manager.reloadConfigs();
}

std::string EthernetInterface::generateObjectPath(
    IP::Protocol addressType, const std::string& ipaddress,
    uint8_t prefixLength, const std::string& gateway,
    IP::AddressOrigin origin) const
{
    std::string type = convertForMessage(addressType);
    type = type.substr(type.rfind('.') + 1);
    std::transform(type.begin(), type.end(), type.begin(), ::tolower);

    std::filesystem::path objectPath;
    objectPath /= objPath;
    objectPath /= type;
    objectPath /=
        generateId(ipaddress, prefixLength, gateway, convertForMessage(origin));
    return objectPath.string();
}

std::string EthernetInterface::generateStaticNeighborObjectPath(
    const std::string& ipAddress, const std::string& macAddress) const
{
    std::filesystem::path objectPath;
    objectPath /= objPath;
    objectPath /= "static_neighbor";
    objectPath /= generateNeighborId(ipAddress, macAddress);
    return objectPath.string();
}

bool EthernetInterface::ipv6AcceptRA(bool value)
{
    if (value == EthernetInterfaceIntf::ipv6AcceptRA())
    {
        return value;
    }
    EthernetInterfaceIntf::ipv6AcceptRA(value);
    if (value)
    {
        // Per systemd-networkd(5) enabling IPv6AcceptRA automatically implies
        // DHCPv6 is true. Do not rely on the implied state, explicitly assign
        // it until systemd-networkd changes its behavior.
        DHCPConf dhcpState = EthernetInterfaceIntf::dhcpEnabled();
        if (dhcpState == EthernetInterface::DHCPConf::v4)
        {
            dhcpEnabled(EthernetInterface::DHCPConf::both);
        }
        else if (dhcpState == EthernetInterface::DHCPConf::none)
        {
            dhcpEnabled(EthernetInterface::DHCPConf::v6);
        }
    }

    writeConfigurationFile();
    manager.reloadConfigs();

    return value;
}

EthernetInterface::DHCPConf EthernetInterface::dhcpEnabled(DHCPConf value)
{
    if (value == EthernetInterfaceIntf::dhcpEnabled())
    {
        return value;
    }
    EthernetInterfaceIntf::dhcpEnabled(value);

    writeConfigurationFile();
    manager.reloadConfigs();

    return value;
}

bool EthernetInterface::linkUp() const
{
    EthernetIntfSocket eifSocket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
    bool value = EthernetInterfaceIntf::linkUp();

    if (eifSocket.sock < 0)
    {
        return value;
    }

    ifreq ifr = {};
    std::strncpy(ifr.ifr_name, interfaceName().c_str(), IF_NAMESIZE - 1);
    if (ioctl(eifSocket.sock, SIOCGIFFLAGS, &ifr) == 0)
    {
        value = static_cast<bool>(ifr.ifr_flags & IFF_RUNNING);
    }
    else
    {
        log<level::ERR>("ioctl failed for SIOCGIFFLAGS:",
                        entry("ERROR=%s", strerror(errno)));
    }
    return value;
}

size_t EthernetInterface::mtu() const
{
    EthernetIntfSocket eifSocket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
    size_t value = EthernetInterfaceIntf::mtu();

    if (eifSocket.sock < 0)
    {
        return value;
    }

    ifreq ifr = {};
    std::strncpy(ifr.ifr_name, interfaceName().c_str(), IF_NAMESIZE - 1);
    if (ioctl(eifSocket.sock, SIOCGIFMTU, &ifr) == 0)
    {
        value = ifr.ifr_mtu;
    }
    else
    {
        log<level::ERR>("ioctl failed for SIOCGIFMTU:",
                        entry("ERROR=%s", strerror(errno)));
    }
    return value;
}

size_t EthernetInterface::mtu(size_t value)
{
    if (value == EthernetInterfaceIntf::mtu())
    {
        return value;
    }
    else if (value == 0)
    {
        return EthernetInterfaceIntf::mtu();
    }

    EthernetIntfSocket eifSocket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (eifSocket.sock < 0)
    {
        return EthernetInterfaceIntf::mtu();
    }

    ifreq ifr = {};
    std::strncpy(ifr.ifr_name, interfaceName().c_str(), IF_NAMESIZE - 1);
    ifr.ifr_mtu = value;

    if (ioctl(eifSocket.sock, SIOCSIFMTU, &ifr) != 0)
    {
        log<level::ERR>("ioctl failed for SIOCSIFMTU:",
                        entry("ERROR=%s", strerror(errno)));
        return EthernetInterfaceIntf::mtu();
    }
    EthernetInterfaceIntf::mtu(value);

    return value;
}

bool EthernetInterface::queryNicEnabled() const
{
    constexpr auto svc = "org.freedesktop.network1";
    constexpr auto intf = "org.freedesktop.network1.Link";
    constexpr auto prop = "AdministrativeState";
    char* rpath;
    sd_bus_path_encode("/org/freedesktop/network1/link",
                       std::to_string(ifIndex()).c_str(), &rpath);
    std::string path(rpath);
    free(rpath);

    // Store / Parser for the AdministrativeState return value
    std::optional<bool> ret;
    auto cb = [&](const std::string& state) {
        if (state != "initialized")
        {
            ret = state != "unmanaged";
        }
    };

    // Build a matcher before making the property call to ensure we
    // can eventually get the value.
    sdbusplus::bus::match::match match(
        bus,
        fmt::format("type='signal',sender='{}',path='{}',interface='{}',member="
                    "'PropertiesChanged',arg0='{}',",
                    svc, path, PROPERTY_INTERFACE, intf)
            .c_str(),
        [&](sdbusplus::message::message& m) {
            std::string intf;
            std::unordered_map<std::string, std::variant<std::string>> values;
            try
            {
                m.read(intf, values);
                auto it = values.find(prop);
                // Ignore properties that aren't AdministrativeState
                if (it != values.end())
                {
                    cb(std::get<std::string>(it->second));
                }
            }
            catch (const std::exception& e)
            {
                log<level::ERR>(
                    fmt::format(
                        "AdministrativeState match parsing failed on {}: {}",
                        interfaceName(), e.what())
                        .c_str(),
                    entry("INTERFACE=%s", interfaceName().c_str()),
                    entry("ERROR=%s", e.what()));
            }
        });

    // Actively call for the value in case the interface is already configured
    auto method =
        bus.new_method_call(svc, path.c_str(), PROPERTY_INTERFACE, METHOD_GET);
    method.append(intf, prop);
    try
    {
        auto reply = bus.call(method);
        std::variant<std::string> state;
        reply.read(state);
        cb(std::get<std::string>(state));
    }
    catch (const std::exception& e)
    {
        log<level::ERR>(
            fmt::format("Failed to get AdministrativeState on {}: {}",
                        interfaceName(), e.what())
                .c_str(),
            entry("INTERFACE=%s", interfaceName().c_str()),
            entry("ERROR=%s", e.what()));
    }

    // The interface is not yet configured by systemd-networkd, wait until it
    // signals us a valid state.
    while (!ret)
    {
        bus.wait();
        bus.process_discard();
    }

    return *ret;
}

bool EthernetInterface::nicEnabled(bool value)
{
    if (value == EthernetInterfaceIntf::nicEnabled())
    {
        return value;
    }

    EthernetIntfSocket eifSocket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (eifSocket.sock < 0)
    {
        return EthernetInterfaceIntf::nicEnabled();
    }

    ifreq ifr = {};
    std::strncpy(ifr.ifr_name, interfaceName().c_str(), IF_NAMESIZE - 1);
    if (ioctl(eifSocket.sock, SIOCGIFFLAGS, &ifr) != 0)
    {
        log<level::ERR>("ioctl failed for SIOCGIFFLAGS:",
                        entry("ERROR=%s", strerror(errno)));
        return EthernetInterfaceIntf::nicEnabled();
    }

    ifr.ifr_flags &= ~IFF_UP;
    ifr.ifr_flags |= value ? IFF_UP : 0;

    if (ioctl(eifSocket.sock, SIOCSIFFLAGS, &ifr) != 0)
    {
        log<level::ERR>("ioctl failed for SIOCSIFFLAGS:",
                        entry("ERROR=%s", strerror(errno)));
        return EthernetInterfaceIntf::nicEnabled();
    }
    EthernetInterfaceIntf::nicEnabled(value);

    writeConfigurationFile();
    manager.reloadConfigs();

    return value;
}

ServerList EthernetInterface::nameservers(ServerList /*value*/)
{
    elog<NotAllowed>(NotAllowedArgument::REASON("ReadOnly Property"));
    return EthernetInterfaceIntf::nameservers();
}

ServerList EthernetInterface::staticNameServers(ServerList value)
{
    for (const auto& nameserverip : value)
    {
        if (!isValidIP(AF_INET, nameserverip) &&
            !isValidIP(AF_INET6, nameserverip))
        {
            log<level::ERR>("Not a valid IP address"),
                entry("ADDRESS=%s", nameserverip.c_str());
            elog<InvalidArgument>(
                Argument::ARGUMENT_NAME("StaticNameserver"),
                Argument::ARGUMENT_VALUE(nameserverip.c_str()));
        }
    }
    try
    {
        EthernetInterfaceIntf::staticNameServers(value);

        writeConfigurationFile();
        manager.reloadConfigs();
    }
    catch (const InternalFailure& e)
    {
        log<level::ERR>("Exception processing DNS entries");
    }
    return EthernetInterfaceIntf::staticNameServers();
}

void EthernetInterface::loadNameServers()
{
    EthernetInterfaceIntf::nameservers(getNameServerFromResolvd());
    EthernetInterfaceIntf::staticNameServers(getstaticNameServerFromConf());
}

ServerList EthernetInterface::getstaticNameServerFromConf()
{
    fs::path confPath = manager.getConfDir();

    std::string fileName = systemd::config::networkFilePrefix +
                           interfaceName() + systemd::config::networkFileSuffix;
    confPath /= fileName;
    ServerList servers;
    config::Parser parser(confPath.string());
    auto rc = config::ReturnCode::SUCCESS;

    std::tie(rc, servers) = parser.getValues("Network", "DNS");
    if (rc != config::ReturnCode::SUCCESS)
    {
        log<level::DEBUG>("Unable to get the value for network[DNS]",
                          entry("RC=%d", rc));
    }
    return servers;
}

ServerList EthernetInterface::getNameServerFromResolvd()
{
    ServerList servers;
    std::string OBJ_PATH = RESOLVED_SERVICE_PATH + std::to_string(ifIndex());

    /*
      The DNS property under org.freedesktop.resolve1.Link interface contains
      an array containing all DNS servers currently used by resolved. It
      contains similar information as the DNS server data written to
      /run/systemd/resolve/resolv.conf.

      Each structure in the array consists of a numeric network interface index,
      an address family, and a byte array containing the DNS server address
      (either 4 bytes in length for IPv4 or 16 bytes in lengths for IPv6).
      The array contains DNS servers configured system-wide, including those
      possibly read from a foreign /etc/resolv.conf or the DNS= setting in
      /etc/systemd/resolved.conf, as well as per-interface DNS server
      information either retrieved from systemd-networkd or configured by
      external software via SetLinkDNS().
    */

    using type = std::vector<std::tuple<int32_t, std::vector<uint8_t>>>;
    std::variant<type> name; // Variable to capture the DNS property
    auto method = bus.new_method_call(RESOLVED_SERVICE, OBJ_PATH.c_str(),
                                      PROPERTY_INTERFACE, METHOD_GET);

    method.append(RESOLVED_INTERFACE, "DNS");
    auto reply = bus.call(method);

    try
    {
        reply.read(name);
    }
    catch (const sdbusplus::exception::exception& e)
    {
        log<level::ERR>("Failed to get DNS information from Systemd-Resolved");
    }
    auto tupleVector = std::get_if<type>(&name);
    for (auto i = tupleVector->begin(); i != tupleVector->end(); ++i)
    {
        int addressFamily = std::get<0>(*i);
        std::vector<uint8_t>& ipaddress = std::get<1>(*i);

        switch (addressFamily)
        {
            case AF_INET:
                if (ipaddress.size() == sizeof(struct in_addr))
                {
                    servers.push_back(toString(
                        *reinterpret_cast<struct in_addr*>(ipaddress.data())));
                }
                else
                {
                    log<level::ERR>(
                        "Invalid data recived from Systemd-Resolved");
                }
                break;

            case AF_INET6:
                if (ipaddress.size() == sizeof(struct in6_addr))
                {
                    servers.push_back(toString(
                        *reinterpret_cast<struct in6_addr*>(ipaddress.data())));
                }
                else
                {
                    log<level::ERR>(
                        "Invalid data recived from Systemd-Resolved");
                }
                break;

            default:
                log<level::ERR>(
                    "Unsupported address family in DNS from Systemd-Resolved");
                break;
        }
    }
    return servers;
}

void EthernetInterface::loadVLAN(VlanId id)
{
    std::string vlanInterfaceName = interfaceName() + "." + std::to_string(id);
    std::string path = objPath;
    path += "_" + std::to_string(id);

    DHCPConf dhcpEnabled =
        getDHCPValue(manager.getConfDir().string(), vlanInterfaceName);
    auto vlanIntf = std::make_unique<phosphor::network::VlanInterface>(
        bus, path.c_str(), dhcpEnabled, EthernetInterfaceIntf::nicEnabled(), id,
        *this, manager);

    // Fetch the ip address from the system
    // and create the dbus object.
    vlanIntf->createIPAddressObjects();
    vlanIntf->createStaticNeighborObjects();

    this->vlanInterfaces.emplace(std::move(vlanInterfaceName),
                                 std::move(vlanIntf));
}

ObjectPath EthernetInterface::createVLAN(VlanId id)
{
    std::string vlanInterfaceName = interfaceName() + "." + std::to_string(id);
    std::string path = objPath;
    path += "_" + std::to_string(id);

    // Pass the parents nicEnabled property, so that the child
    // VLAN interface can inherit.

    auto vlanIntf = std::make_unique<phosphor::network::VlanInterface>(
        bus, path.c_str(), EthernetInterface::DHCPConf::none,
        EthernetInterfaceIntf::nicEnabled(), id, *this, manager);

    // write the device file for the vlan interface.
    vlanIntf->writeDeviceFile();

    this->vlanInterfaces.emplace(vlanInterfaceName, std::move(vlanIntf));

    writeConfigurationFile();
    manager.reloadConfigs();

    return path;
}

bool EthernetInterface::getIPv6AcceptRAFromConf()
{
    fs::path confPath = manager.getConfDir();

    std::string fileName = systemd::config::networkFilePrefix +
                           interfaceName() + systemd::config::networkFileSuffix;
    confPath /= fileName;
    config::ValueList values;
    config::Parser parser(confPath.string());
    auto rc = config::ReturnCode::SUCCESS;
    std::tie(rc, values) = parser.getValues("Network", "IPv6AcceptRA");
    if (rc != config::ReturnCode::SUCCESS)
    {
        log<level::DEBUG>("Unable to get the value for Network[IPv6AcceptRA]",
                          entry("rc=%d", rc));
        return false;
    }
    return (values[0] == "true");
}

ServerList EthernetInterface::getNTPServersFromConf()
{
    fs::path confPath = manager.getConfDir();

    std::string fileName = systemd::config::networkFilePrefix +
                           interfaceName() + systemd::config::networkFileSuffix;
    confPath /= fileName;

    ServerList servers;
    config::Parser parser(confPath.string());
    auto rc = config::ReturnCode::SUCCESS;

    std::tie(rc, servers) = parser.getValues("Network", "NTP");
    if (rc != config::ReturnCode::SUCCESS)
    {
        log<level::DEBUG>("Unable to get the value for Network[NTP]",
                          entry("rc=%d", rc));
    }

    return servers;
}

ServerList EthernetInterface::ntpServers(ServerList servers)
{
    auto ntpServers = EthernetInterfaceIntf::ntpServers(servers);

    writeConfigurationFile();
    manager.reloadConfigs();

    return ntpServers;
}
// Need to merge the below function with the code which writes the
// config file during factory reset.
// TODO openbmc/openbmc#1751

void EthernetInterface::writeConfigurationFile()
{
    // write all the static ip address in the systemd-network conf file

    using namespace std::string_literals;
    namespace fs = std::filesystem;

    // if there is vlan interafce then write the configuration file
    // for vlan also.

    for (const auto& intf : vlanInterfaces)
    {
        intf.second->writeConfigurationFile();
    }

    fs::path confPath = manager.getConfDir();

    std::string fileName = systemd::config::networkFilePrefix +
                           interfaceName() + systemd::config::networkFileSuffix;
    confPath /= fileName;
    std::fstream stream;

    stream.open(confPath.c_str(), std::fstream::out);
    if (!stream.is_open())
    {
        log<level::ERR>("Unable to open the file",
                        entry("FILE=%s", confPath.c_str()));
        elog<InternalFailure>();
    }

    // Write the device
    stream << "[Match]\n";
    stream << "Name=" << interfaceName() << "\n";

    auto addrs = getAddresses();

    // Write the link section
    stream << "[Link]\n";
    auto mac = MacAddressIntf::macAddress();
    if (!mac.empty())
    {
        stream << "MACAddress=" << mac << "\n";
    }

    if (!EthernetInterfaceIntf::nicEnabled())
    {
        stream << "Unmanaged=yes\n";
    }

    // write the network section
    stream << "[Network]\n";
#ifdef LINK_LOCAL_AUTOCONFIGURATION
    stream << "LinkLocalAddressing=yes\n";
#else
    stream << "LinkLocalAddressing=no\n";
#endif
    stream << std::boolalpha
           << "IPv6AcceptRA=" << EthernetInterfaceIntf::ipv6AcceptRA() << "\n";

    // Add the VLAN entry
    for (const auto& intf : vlanInterfaces)
    {
        stream << "VLAN=" << intf.second->EthernetInterface::interfaceName()
               << "\n";
    }
    // Add the NTP server
    for (const auto& ntp : EthernetInterfaceIntf::ntpServers())
    {
        stream << "NTP=" << ntp << "\n";
    }

    // Add the DNS entry
    for (const auto& dns : EthernetInterfaceIntf::staticNameServers())
    {
        stream << "DNS=" << dns << "\n";
    }

    // Add the DHCP entry
    stream << "DHCP="s +
                  mapDHCPToSystemd[EthernetInterfaceIntf::dhcpEnabled()] + "\n";

    // Static IP addresses
    for (const auto& addr : addrs)
    {
        if (originIsManuallyAssigned(addr.second->origin()) &&
            !dhcpIsEnabled(addr.second->type()))
        {
            // Process all static addresses
            std::string address = addr.second->address() + "/" +
                                  std::to_string(addr.second->prefixLength());

            // build the address entries. Do not use [Network] shortcuts to
            // insert address entries.
            stream << "[Address]\n";
            stream << "Address=" << address << "\n";
        }
    }

    if (!dhcpIsEnabled(IP::Protocol::IPv4))
    {
        auto gateway = EthernetInterfaceIntf::defaultGateway();
        if (!gateway.empty())
        {
            stream << "[Route]\n";
            stream << "Gateway=" << gateway << "\n";
        }
    }

    if (!dhcpIsEnabled(IP::Protocol::IPv6))
    {
        auto gateway6 = EthernetInterfaceIntf::defaultGateway6();
        if (!gateway6.empty())
        {
            stream << "[Route]\n";
            stream << "Gateway=" << gateway6 << "\n";
        }
    }

    // Write the neighbor sections
    for (const auto& neighbor : staticNeighbors)
    {
        stream << "[Neighbor]"
               << "\n";
        stream << "Address=" << neighbor.second->ipAddress() << "\n";
        stream << "MACAddress=" << neighbor.second->macAddress() << "\n";
    }

    // Write the dhcp section irrespective of whether DHCP is enabled or not
    writeDHCPSection(stream);

    stream.close();
}

void EthernetInterface::writeDHCPSection(std::fstream& stream)
{
    using namespace std::string_literals;
    // write the dhcp section
    stream << "[DHCP]\n";

    // Hardcoding the client identifier to mac, to address below issue
    // https://github.com/openbmc/openbmc/issues/1280
    stream << "ClientIdentifier=mac\n";
    if (manager.getDHCPConf())
    {
        auto value = manager.getDHCPConf()->dnsEnabled() ? "true"s : "false"s;
        stream << "UseDNS="s + value + "\n";

        value = manager.getDHCPConf()->ntpEnabled() ? "true"s : "false"s;
        stream << "UseNTP="s + value + "\n";

        value = manager.getDHCPConf()->hostNameEnabled() ? "true"s : "false"s;
        stream << "UseHostname="s + value + "\n";

        value =
            manager.getDHCPConf()->sendHostNameEnabled() ? "true"s : "false"s;
        stream << "SendHostname="s + value + "\n";
    }
}

std::string EthernetInterface::macAddress(std::string value)
{
    ether_addr newMAC;
    try
    {
        newMAC = mac_address::fromString(value);
    }
    catch (const std::invalid_argument&)
    {
        log<level::ERR>("MACAddress is not valid.",
                        entry("MAC=%s", value.c_str()));
        elog<InvalidArgument>(Argument::ARGUMENT_NAME("MACAddress"),
                              Argument::ARGUMENT_VALUE(value.c_str()));
    }
    if (!mac_address::isUnicast(newMAC))
    {
        log<level::ERR>("MACAddress is not valid.",
                        entry("MAC=%s", value.c_str()));
        elog<InvalidArgument>(Argument::ARGUMENT_NAME("MACAddress"),
                              Argument::ARGUMENT_VALUE(value.c_str()));
    }

    auto interface = interfaceName();
    std::string validMAC = mac_address::toString(newMAC);

    // We don't need to update the system if the address is unchanged
    ether_addr oldMAC = mac_address::fromString(MacAddressIntf::macAddress());
    if (!stdplus::raw::equal(newMAC, oldMAC))
    {
        // Update everything that depends on the MAC value
        for (const auto& [name, intf] : vlanInterfaces)
        {
            intf->MacAddressIntf::macAddress(validMAC);
        }
        MacAddressIntf::macAddress(validMAC);

        // TODO: would remove the call below and
        //      just restart systemd-netwokd
        //      through https://github.com/systemd/systemd/issues/6696
        execute("/sbin/ip", "ip", "link", "set", "dev", interface.c_str(),
                "down");
        writeConfigurationFile();
        manager.reloadConfigs();
    }

#ifdef HAVE_UBOOT_ENV
    // Ensure that the valid address is stored in the u-boot-env
    auto envVar = interfaceToUbootEthAddr(interface.c_str());
    if (envVar)
    {
        // Trimming MAC addresses that are out of range. eg: AA:FF:FF:FF:FF:100;
        // and those having more than 6 bytes. eg: AA:AA:AA:AA:AA:AA:BB
        execute("/sbin/fw_setenv", "fw_setenv", envVar->c_str(),
                validMAC.c_str());
    }
#endif // HAVE_UBOOT_ENV

    return value;
}

void EthernetInterface::deleteAll()
{
    if (dhcpIsEnabled(IP::Protocol::IPv4, true))
    {
        log<level::INFO>("DHCP enabled on the interface"),
            entry("INTERFACE=%s", interfaceName().c_str());
    }

    // clear all the ip on the interface
    addrs.clear();

    writeConfigurationFile();
    manager.reloadConfigs();
}

std::string EthernetInterface::defaultGateway(std::string gateway)
{
    auto gw = EthernetInterfaceIntf::defaultGateway();
    if (gw == gateway)
    {
        return gw;
    }

    if (!isValidIP(AF_INET, gateway))
    {
        log<level::ERR>("Not a valid v4 Gateway",
                        entry("GATEWAY=%s", gateway.c_str()));
        elog<InvalidArgument>(Argument::ARGUMENT_NAME("GATEWAY"),
                              Argument::ARGUMENT_VALUE(gateway.c_str()));
    }
    gw = EthernetInterfaceIntf::defaultGateway(gateway);

    writeConfigurationFile();
    manager.reloadConfigs();

    return gw;
}

std::string EthernetInterface::defaultGateway6(std::string gateway)
{
    auto gw = EthernetInterfaceIntf::defaultGateway6();
    if (gw == gateway)
    {
        return gw;
    }

    if (!isValidIP(AF_INET6, gateway))
    {
        log<level::ERR>("Not a valid v6 Gateway",
                        entry("GATEWAY=%s", gateway.c_str()));
        elog<InvalidArgument>(Argument::ARGUMENT_NAME("GATEWAY"),
                              Argument::ARGUMENT_VALUE(gateway.c_str()));
    }
    gw = EthernetInterfaceIntf::defaultGateway6(gateway);

    writeConfigurationFile();
    manager.reloadConfigs();

    return gw;
}
} // namespace network
} // namespace phosphor
