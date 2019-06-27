#include "config.h"

#include "ethernet_interface.hpp"

#include "config_parser.hpp"
#include "ipaddress.hpp"
#include "neighbor.hpp"
#include "network_manager.hpp"
#include "routing_table.hpp"
#include "vlan_interface.hpp"

#include <arpa/inet.h>
#include <linux/ethtool.h>
#include <linux/sockios.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <experimental/filesystem>
#include <fstream>
#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/log.hpp>
#include <sstream>
#include <string>
#include <xyz/openbmc_project/Common/error.hpp>

namespace phosphor
{
namespace network
{

using namespace phosphor::logging;
using namespace sdbusplus::xyz::openbmc_project::Common::Error;
using Argument = xyz::openbmc_project::Common::InvalidArgument;

EthernetInterface::EthernetInterface(sdbusplus::bus::bus& bus,
                                     const std::string& objPath,
                                     bool dhcpEnabled, Manager& parent,
                                     bool emitSignal) :
    Ifaces(bus, objPath.c_str(), true),
    bus(bus), manager(parent), objPath(objPath)
{
    auto intfName = objPath.substr(objPath.rfind("/") + 1);
    std::replace(intfName.begin(), intfName.end(), '_', '.');
    interfaceName(intfName);
    EthernetInterfaceIntf::dHCPEnabled(dhcpEnabled);
    MacAddressIntf::mACAddress(getMACAddress(intfName));
    EthernetInterfaceIntf::nTPServers(getNTPServersFromConf());
    EthernetInterfaceIntf::nameservers(getNameServerFromConf());

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

void EthernetInterface::createIPAddressObjects()
{
    addrs.clear();

    auto addrs = getInterfaceAddrs()[interfaceName()];

    route::Table routingTable;

    for (auto& addr : addrs)
    {
        IP::Protocol addressType = convertFamily(addr.addrType);
        IP::AddressOrigin origin = IP::AddressOrigin::Static;
        if (dHCPEnabled())
        {
            origin = IP::AddressOrigin::DHCP;
        }
        if (isLinkLocalIP(addr.ipaddress))
        {
            origin = IP::AddressOrigin::LinkLocal;
        }
        std::string gateway =
            routingTable.getGateway(addr.addrType, addr.ipaddress, addr.prefix);

        std::string ipAddressObjectPath = generateObjectPath(
            addressType, addr.ipaddress, addr.prefix, gateway);

        this->addrs.emplace(addr.ipaddress,
                            std::make_shared<phosphor::network::IPAddress>(
                                bus, ipAddressObjectPath.c_str(), *this,
                                addressType, addr.ipaddress, origin,
                                addr.prefix, gateway));
    }
}

void EthernetInterface::createStaticNeighborObjects()
{
    staticNeighbors.clear();

    auto neighbors = getCurrentNeighbors();
    for (const auto& neighbor : neighbors)
    {
        if (!neighbor.permanent || !neighbor.mac ||
            neighbor.interface != interfaceName())
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

ObjectPath EthernetInterface::iP(IP::Protocol protType, std::string ipaddress,
                                 uint8_t prefixLength, std::string gateway)
{

    if (dHCPEnabled())
    {
        log<level::INFO>("DHCP enabled on the interface"),
            entry("INTERFACE=%s", interfaceName().c_str());
        dHCPEnabled(false);
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

    if (!gateway.empty() && (!isValidIP(addressFamily, gateway)))
    {
        log<level::ERR>("Not a valid Gateway"),
            entry("GATEWAY=%s", gateway.c_str());
        elog<InvalidArgument>(Argument::ARGUMENT_NAME("gateway"),
                              Argument::ARGUMENT_VALUE(gateway.c_str()));
    }

    if (!isValidPrefix(addressFamily, prefixLength))
    {
        log<level::ERR>("PrefixLength is not correct "),
            entry("PREFIXLENGTH=%d", gateway.c_str());
        elog<InvalidArgument>(
            Argument::ARGUMENT_NAME("prefixLength"),
            Argument::ARGUMENT_VALUE(std::to_string(prefixLength).c_str()));
    }

    std::string objectPath =
        generateObjectPath(protType, ipaddress, prefixLength, gateway);
    this->addrs.emplace(ipaddress,
                        std::make_shared<phosphor::network::IPAddress>(
                            bus, objectPath.c_str(), *this, protType, ipaddress,
                            origin, prefixLength, gateway));

    manager.writeToConfigurationFile();
    return objectPath;
}

ObjectPath EthernetInterface::neighbor(std::string iPAddress,
                                       std::string mACAddress)
{
    if (!isValidIP(AF_INET, iPAddress) && !isValidIP(AF_INET6, iPAddress))
    {
        log<level::ERR>("Not a valid IP address",
                        entry("ADDRESS=%s", iPAddress.c_str()));
        elog<InvalidArgument>(Argument::ARGUMENT_NAME("iPAddress"),
                              Argument::ARGUMENT_VALUE(iPAddress.c_str()));
    }
    if (!mac_address::validate(mACAddress))
    {
        log<level::ERR>("Not a valid MAC address",
                        entry("MACADDRESS=%s", iPAddress.c_str()));
        elog<InvalidArgument>(Argument::ARGUMENT_NAME("mACAddress"),
                              Argument::ARGUMENT_VALUE(mACAddress.c_str()));
    }

    std::string objectPath =
        generateStaticNeighborObjectPath(iPAddress, mACAddress);
    staticNeighbors.emplace(iPAddress,
                            std::make_shared<phosphor::network::Neighbor>(
                                bus, objectPath.c_str(), *this, iPAddress,
                                mACAddress, Neighbor::State::Permanent));
    manager.writeToConfigurationFile();
    return objectPath;
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
    ifreq ifr{0};
    ethtool_cmd edata{0};
    LinkSpeed speed{0};
    Autoneg autoneg{0};
    DuplexMode duplex{0};
    do
    {
        sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
        if (sock < 0)
        {
            log<level::ERR>("socket creation  failed:",
                            entry("ERROR=%s", strerror(errno)));
            break;
        }

        strcpy(ifr.ifr_name, interfaceName().c_str());
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
    } while (0);

    if (sock)
    {
        close(sock);
    }
    return std::make_tuple(speed, duplex, autoneg);
}

/** @brief get the mac address of the interface.
 *  @return macaddress on success
 */

std::string
    EthernetInterface::getMACAddress(const std::string& interfaceName) const
{
    ifreq ifr{};
    char macAddress[mac_address::size]{};

    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (sock < 0)
    {
        log<level::ERR>("socket creation  failed:",
                        entry("ERROR=%s", strerror(errno)));
        return macAddress;
    }

    std::strcpy(ifr.ifr_name, interfaceName.c_str());
    if (ioctl(sock, SIOCGIFHWADDR, &ifr) != 0)
    {
        log<level::ERR>("ioctl failed for SIOCGIFHWADDR:",
                        entry("ERROR=%s", strerror(errno)));
        return macAddress;
    }

    std::snprintf(macAddress, mac_address::size, mac_address::format,
                  ifr.ifr_hwaddr.sa_data[0], ifr.ifr_hwaddr.sa_data[1],
                  ifr.ifr_hwaddr.sa_data[2], ifr.ifr_hwaddr.sa_data[3],
                  ifr.ifr_hwaddr.sa_data[4], ifr.ifr_hwaddr.sa_data[5]);

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
    hexId << std::hex << ((std::hash<std::string>{}(hashString)) & 0xFFFFFFFF);
    return hexId.str();
}

std::string EthernetInterface::generateNeighborId(const std::string& iPAddress,
                                                  const std::string& mACAddress)
{
    std::stringstream hexId;
    std::string hashString = iPAddress + mACAddress;

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
    manager.writeToConfigurationFile();
}

void EthernetInterface::deleteStaticNeighborObject(const std::string& iPAddress)
{
    auto it = staticNeighbors.find(iPAddress);
    if (it == staticNeighbors.end())
    {
        log<level::ERR>(
            "DeleteStaticNeighborObject:Unable to find the object.");
        return;
    }
    staticNeighbors.erase(it);
    manager.writeToConfigurationFile();
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
    catch (InternalFailure& e)
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

    manager.writeToConfigurationFile();
}

std::string EthernetInterface::generateObjectPath(
    IP::Protocol addressType, const std::string& ipaddress,
    uint8_t prefixLength, const std::string& gateway) const
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

std::string EthernetInterface::generateStaticNeighborObjectPath(
    const std::string& iPAddress, const std::string& mACAddress) const
{
    std::experimental::filesystem::path objectPath;
    objectPath /= objPath;
    objectPath /= "static_neighbor";
    objectPath /= generateNeighborId(iPAddress, mACAddress);
    return objectPath.string();
}

bool EthernetInterface::dHCPEnabled(bool value)
{
    if (value == EthernetInterfaceIntf::dHCPEnabled())
    {
        return value;
    }

    EthernetInterfaceIntf::dHCPEnabled(value);
    manager.writeToConfigurationFile();
    return value;
}

ServerList EthernetInterface::nameservers(ServerList value)
{
    try
    {
        EthernetInterfaceIntf::nameservers(value);

        writeConfigurationFile();

        // Currently we don't have systemd-resolved enabled
        // in the openbmc. Once we update the network conf file,
        // it should be read by systemd-resolved.service.

        // The other reason to write the resolv conf is,
        // we don't want to restart the networkd for nameserver change.
        // as restarting of systemd-networkd takes more then 2 secs
        writeDNSEntries(value, resolvConfFile);
    }
    catch (InternalFailure& e)
    {
        log<level::ERR>("Exception processing DNS entries");
    }
    return EthernetInterfaceIntf::nameservers();
}

ServerList EthernetInterface::getNameServerFromConf()
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

void EthernetInterface::writeDNSEntries(const ServerList& dnsList,
                                        const std::string& file)
{
    std::fstream outStream(file, std::fstream::out);
    if (!outStream.is_open())
    {
        log<level::ERR>("Unable to open the file",
                        entry("FILE=%s", file.c_str()));
        elog<InternalFailure>();
    }

    outStream << "### Generated manually via dbus settings ###\n";
    for (const auto& server : dnsList)
    {
        outStream << "nameserver " << server << "\n";
    }
}

void EthernetInterface::loadVLAN(VlanId id)
{
    std::string vlanInterfaceName = interfaceName() + "." + std::to_string(id);
    std::string path = objPath;
    path += "_" + std::to_string(id);

    auto dhcpEnabled =
        getDHCPValue(manager.getConfDir().string(), vlanInterfaceName);

    auto vlanIntf = std::make_unique<phosphor::network::VlanInterface>(
        bus, path.c_str(), dhcpEnabled, id, *this, manager);

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

    auto vlanIntf = std::make_unique<phosphor::network::VlanInterface>(
        bus, path.c_str(), false, id, *this, manager);

    // write the device file for the vlan interface.
    vlanIntf->writeDeviceFile();

    this->vlanInterfaces.emplace(vlanInterfaceName, std::move(vlanIntf));
    // write the new vlan device entry to the configuration(network) file.
    manager.writeToConfigurationFile();

    return path;
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

ServerList EthernetInterface::nTPServers(ServerList servers)
{
    auto ntpServers = EthernetInterfaceIntf::nTPServers(servers);

    writeConfigurationFile();
    // timesynchd reads the NTP server configuration from the
    // network file.
    manager.restartSystemdUnit(networkdService);
    return ntpServers;
}
// Need to merge the below function with the code which writes the
// config file during factory reset.
// TODO openbmc/openbmc#1751

void EthernetInterface::writeConfigurationFile()
{
    // write all the static ip address in the systemd-network conf file

    using namespace std::string_literals;
    using AddressOrigin =
        sdbusplus::xyz::openbmc_project::Network::server::IP::AddressOrigin;
    namespace fs = std::experimental::filesystem;

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

    // write the network section
    stream << "[Network]\n";
#ifdef LINK_LOCAL_AUTOCONFIGURATION
    stream << "LinkLocalAddressing=yes\n";
#else
    stream << "LinkLocalAddressing=no\n";
#endif
    stream << "IPv6AcceptRA=false\n";

    // Add the VLAN entry
    for (const auto& intf : vlanInterfaces)
    {
        stream << "VLAN=" << intf.second->EthernetInterface::interfaceName()
               << "\n";
    }
    // Add the DHCP entry
    auto value = dHCPEnabled() ? "true"s : "false"s;
    stream << "DHCP="s + value + "\n";

    // When the interface configured as dhcp, we don't need below given entries
    // in config file.
    if (dHCPEnabled() == false)
    {
        // Add the NTP server
        for (const auto& ntp : EthernetInterfaceIntf::nTPServers())
        {
            stream << "NTP=" << ntp << "\n";
        }

        // Add the DNS entry
        for (const auto& dns : EthernetInterfaceIntf::nameservers())
        {
            stream << "DNS=" << dns << "\n";
        }

        // Static
        for (const auto& addr : addrs)
        {
            if (addr.second->origin() == AddressOrigin::Static
#ifndef LINK_LOCAL_AUTOCONFIGURATION
                || addr.second->origin() == AddressOrigin::LinkLocal
#endif
            )
            {
                std::string address =
                    addr.second->address() + "/" +
                    std::to_string(addr.second->prefixLength());

                stream << "Address=" << address << "\n";
            }
        }

        if (manager.getSystemConf())
        {
            const auto& gateway = manager.getSystemConf()->defaultGateway();
            if (!gateway.empty())
            {
                stream << "Gateway=" << gateway << "\n";
            }
            const auto& gateway6 = manager.getSystemConf()->defaultGateway6();
            if (!gateway6.empty())
            {
                stream << "Gateway=" << gateway6 << "\n";
            }
        }

        // write the route section
        for (const auto& addr : addrs)
        {
            if (addr.second->origin() == AddressOrigin::Static)
            {
                int addressFamily = addr.second->type() == IP::Protocol::IPv4
                                        ? AF_INET
                                        : AF_INET6;

                std::string destination =
                    getNetworkID(addressFamily, addr.second->address(),
                                 addr.second->prefixLength());

                if (addr.second->gateway() != "0.0.0.0" &&
                    addr.second->gateway() != "" && destination != "0.0.0.0" &&
                    destination != "")
                {
                    stream << "[Route]\n";
                    stream << "Gateway=" << addr.second->gateway() << "\n";
                    stream << "Destination=" << destination << "\n";
                }
            }
        }
    }

    // Write the neighbor sections
    for (const auto& neighbor : staticNeighbors)
    {
        stream << "[Neighbor]"
               << "\n";
        stream << "Address=" << neighbor.second->iPAddress() << "\n";
        stream << "MACAddress=" << neighbor.second->mACAddress() << "\n";
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
        auto value = manager.getDHCPConf()->dNSEnabled() ? "true"s : "false"s;
        stream << "UseDNS="s + value + "\n";

        value = manager.getDHCPConf()->nTPEnabled() ? "true"s : "false"s;
        stream << "UseNTP="s + value + "\n";

        value = manager.getDHCPConf()->hostNameEnabled() ? "true"s : "false"s;
        stream << "UseHostname="s + value + "\n";

        value =
            manager.getDHCPConf()->sendHostNameEnabled() ? "true"s : "false"s;
        stream << "SendHostname="s + value + "\n";
    }
}

std::string EthernetInterface::mACAddress(std::string value)
{
    if (!mac_address::validate(value))
    {
        log<level::ERR>("MACAddress is not valid.",
                        entry("MAC=%s", value.c_str()));
        elog<InvalidArgument>(Argument::ARGUMENT_NAME("MACAddress"),
                              Argument::ARGUMENT_VALUE(value.c_str()));
    }

    // check whether MAC is broadcast mac.
    auto intMac = mac_address::internal::convertToInt(value);

    if (!(intMac ^ mac_address::broadcastMac))
    {
        log<level::ERR>("MACAddress is a broadcast mac.",
                        entry("MAC=%s", value.c_str()));
        elog<InvalidArgument>(Argument::ARGUMENT_NAME("MACAddress"),
                              Argument::ARGUMENT_VALUE(value.c_str()));
    }

    // Check if the MAC changed.
    auto pmac = MacAddressIntf::mACAddress();
    if (strcasecmp(pmac.c_str(), value.c_str()) == 0)
    {
        return MacAddressIntf::mACAddress();
    }

    // Allow the mac to be set if one of the condition is true.
    //   1) Incoming Mac is of local admin type.
    //      or
    //   2) Incoming mac is same as eeprom Mac.

    if (!(intMac & mac_address::localAdminMask))
    {
        try
        {
            auto inventoryMac = mac_address::getfromInventory(bus);
            auto intInventoryMac =
                mac_address::internal::convertToInt(inventoryMac);

            if (intInventoryMac != intMac)
            {
                log<level::ERR>("Given MAC address is neither a local Admin "
                                "type nor is same as in inventory");
                elog<InvalidArgument>(Argument::ARGUMENT_NAME("MACAddress"),
                                      Argument::ARGUMENT_VALUE(value.c_str()));
            }
        }
        catch (InternalFailure& e)
        {
            log<level::ERR>("Exception occurred during getting of MAC "
                            "address from Inventory");
            elog<InternalFailure>();
        }
    }
    auto interface = interfaceName();
    execute("/sbin/fw_setenv", "fw_setenv", "ethaddr", value.c_str());
    // TODO: would replace below three calls
    //      with restarting of systemd-netwokd
    //      through https://github.com/systemd/systemd/issues/6696
    execute("/sbin/ip", "ip", "link", "set", "dev", interface.c_str(), "down");
    execute("/sbin/ip", "ip", "link", "set", "dev", interface.c_str(),
            "address", value.c_str());

    execute("/sbin/ip", "ip", "link", "set", "dev", interface.c_str(), "up");

    auto mac = MacAddressIntf::mACAddress(std::move(value));
    // update all the vlan interfaces
    for (const auto& intf : vlanInterfaces)
    {
        intf.second->updateMacAddress();
    }

    // restart the systemd networkd so that dhcp client gets the
    // ip for the changed mac address.
    if (dHCPEnabled())
    {
        manager.restartSystemdUnit(networkdService);
    }
    return mac;
}

void EthernetInterface::deleteAll()
{
    if (EthernetInterfaceIntf::dHCPEnabled())
    {
        log<level::INFO>("DHCP enabled on the interface"),
            entry("INTERFACE=%s", interfaceName().c_str());
    }

    // clear all the ip on the interface
    addrs.clear();
    manager.writeToConfigurationFile();
}

} // namespace network
} // namespace phosphor
