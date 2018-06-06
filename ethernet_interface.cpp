#include "config.h"
#include "config_parser.hpp"
#include "ethernet_interface.hpp"
#include "ipaddress.hpp"
#include "network_manager.hpp"
#include "routing_table.hpp"
#include "vlan_interface.hpp"
#include "xyz/openbmc_project/Common/error.hpp"

#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/log.hpp>

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
#include <sstream>
#include <string>

namespace phosphor
{
namespace network
{

using namespace phosphor::logging;
using namespace sdbusplus::xyz::openbmc_project::Common::Error;
using Argument = xyz::openbmc_project::Common::InvalidArgument;

EthernetInterface::EthernetInterface(sdbusplus::bus::bus& bus,
                                     const std::string& objPath,
                                     bool dhcpEnabled,
                                     Manager& parent,
                                     bool emitSignal) :
                                     Ifaces(bus, objPath.c_str(), true),
                                     bus(bus),
                                     manager(parent),
                                     objPath(objPath)
{
    auto intfName = objPath.substr(objPath.rfind("/") + 1);
    std::replace(intfName.begin(), intfName.end(), '_', '.');
    interfaceName(intfName);
    EthernetInterfaceIntf::dHCPEnabled(dhcpEnabled);
    EthernetInterfaceIntf::iPAddressEnables(getIPAddressEnablesFromConf());
    EthernetInterfaceIntf::iPv6AcceptRA(getIPv6AcceptRAFromConf());
    MacAddressIntf::mACAddress(getMACAddress(intfName));
    EthernetInterfaceIntf::nTPServers(getNTPServersFromConf());
    EthernetInterfaceIntf::nameservers(getNameServerFromConf());

    // Emit deferred signal.
    if (emitSignal)
    {
        this->emit_object_added();
    }
}

void EthernetInterface::createIPAddressObjects()
{
    std::string gateway;
    addrs.clear();

    auto addrs = getInterfaceAddrs()[interfaceName()];

    IP::Protocol addressType = IP::Protocol::IPv4;
    IP::AddressOrigin origin = IP::AddressOrigin::Static;
    route::Table routingTable;

    for (auto& addr : addrs)
    {
        if (addr.addrType == AF_INET6)
        {
            addressType = IP::Protocol::IPv6;
        }
        if (dHCPEnabled())
        {
            origin = IP::AddressOrigin::DHCP;
        }
        else if (isLinkLocalIP(addr.ipaddress))
        {
            origin = IP::AddressOrigin::LinkLocal;
        }
        gateway = routingTable.getGateway(addr.addrType, addr.ipaddress, addr.prefix);

        std::string ipAddressObjectPath = generateObjectPath(addressType,
                                                             addr.ipaddress,
                                                             addr.prefix,
                                                             gateway);

        this->addrs.emplace(
                    addr.ipaddress,
                    std::make_shared<phosphor::network::IPAddress>(
                        bus,
                        ipAddressObjectPath.c_str(),
                        *this,
                        addressType,
                        addr.ipaddress,
                        origin,
                        addr.prefix,
                        gateway));

        origin = IP::AddressOrigin::Static;
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
        elog<InvalidArgument>(Argument::ARGUMENT_NAME("prefixLength"),
                              Argument::ARGUMENT_VALUE(std::to_string(
                                          prefixLength).c_str()));
    }


    std::string objectPath = generateObjectPath(protType,
                                                ipaddress,
                                                prefixLength,
                                                gateway);
    this->addrs.emplace(
                ipaddress,
                std::make_shared<phosphor::network::IPAddress>(
                        bus,
                        objectPath.c_str(),
                        *this,
                        protType,
                        ipaddress,
                        origin,
                        prefixLength,
                        gateway));

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

std::string EthernetInterface::getMACAddress(
        const std::string& interfaceName)
{
    struct ifreq ifr{};
    char macAddress[mac_address::size] {};

    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (sock < 0)
    {
        log<level::ERR>("socket creation  failed:",
                        entry("ERROR=%s", strerror(errno)));
        return macAddress;
    }

    strcpy(ifr.ifr_name, interfaceName.c_str());
    if (ioctl(sock, SIOCGIFHWADDR, &ifr) != 0)
    {
        log<level::ERR>("ioctl failed for SIOCGIFHWADDR:",
                entry("ERROR=%s", strerror(errno)));
        return macAddress;
    }

    snprintf(macAddress, mac_address::size, mac_address::format,
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
                         entry("INTERFACE=%s",interface.c_str()));
        return;
    }

    deleteVLANFromSystem(interface);
    // delete the interface
    vlanInterfaces.erase(it);

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
bool EthernetInterface::iPv6AcceptRA(bool value)
{
    if (value == EthernetInterfaceIntf::iPv6AcceptRA())
    {
        return value;
    }
    EthernetInterfaceIntf::iPv6AcceptRA(value);
    manager.writeToConfigurationFile();
    return value;
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
                           interfaceName() +
                           systemd::config::networkFileSuffix;
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
    for(const auto& server : dnsList)
    {
        outStream << "nameserver " << server << "\n";
    }
}

void EthernetInterface::loadVLAN(VlanId id)
{
    std::string vlanInterfaceName = interfaceName() + "." +
                                    std::to_string(id);
    std::string path = objPath;
    path += "_" + std::to_string(id);

    auto dhcpEnabled = getDHCPValue(manager.getConfDir().string(),
                                    vlanInterfaceName);

    auto vlanIntf = std::make_unique<phosphor::network::VlanInterface>(
                        bus,
                        path.c_str(),
                        dhcpEnabled,
                        id,
                        *this,
                        manager);

   // Fetch the ip address from the system
   // and create the dbus object.
    vlanIntf->createIPAddressObjects();

    this->vlanInterfaces.emplace(std::move(vlanInterfaceName),
                                 std::move(vlanIntf));
}

void EthernetInterface::createVLAN(VlanId id)
{
    std::string vlanInterfaceName = interfaceName() + "." +
                                    std::to_string(id);
    std::string path = objPath;
    path += "_" + std::to_string(id);


    auto vlanIntf = std::make_unique<phosphor::network::VlanInterface>(
                        bus,
                        path.c_str(),
                        false,
                        id,
                        *this,
                        manager);

    // write the device file for the vlan interface.
    vlanIntf->writeDeviceFile();

    this->vlanInterfaces.emplace(vlanInterfaceName,
                                 std::move(vlanIntf));
    // write the new vlan device entry to the configuration(network) file.
    manager.writeToConfigurationFile();
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
    if (values[0] == "true")
    {
        return true;
    }

    return false;
}
EthernetInterface::IPAllowed EthernetInterface::getIPAddressEnablesFromConf()
{
    fs::path confPath = manager.getConfDir();

    std::string fileName = systemd::config::networkFilePrefix +
                           interfaceName() + systemd::config::networkFileSuffix;
    confPath /= fileName;
    config::ValueList values;
    config::Parser parser(confPath.string());
    auto rc = config::ReturnCode::SUCCESS;
    std::tie(rc, values) = parser.getValues("Network", "DHCP");
    if (rc != config::ReturnCode::SUCCESS)
    {
        log<level::DEBUG>("Unable to get the value for Network[DHCP]",
                          entry("rc=%d", rc));
        return EthernetInterface::IPAllowed::IPv4AndIPv6;
    }
    // true, false, ipv4, ipv6
    if (values[0] == "ipv6")
    {
        return EthernetInterface::IPAllowed::IPv6Only;
    }
    else if (values[0] == "ipv4")
    {
        return EthernetInterface::IPAllowed::IPv4Only;
    }
    else if (values[0] == "off")
    {
        // This function should not get called if DHCP == off
        log<level::DEBUG>("Function not available in static mode");
        return EthernetInterface::IPAllowed::IPv4AndIPv6;
    }
    else
    {
        return EthernetInterface::IPAllowed::IPv4AndIPv6;
    }
}
EthernetInterface::IPAllowed
    EthernetInterface::iPAddressEnables(EthernetInterface::IPAllowed iPAllowed)
{
    if (iPAllowed == EthernetInterfaceIntf::iPAddressEnables())
    {
        return iPAllowed;
    }

    EthernetInterfaceIntf::iPAddressEnables(iPAllowed);
    writeConfigurationFile();

    return iPAllowed;
}
ServerList EthernetInterface::getNTPServersFromConf()
{
    fs::path confPath = manager.getConfDir();

    std::string fileName = systemd::config::networkFilePrefix + interfaceName() +
        systemd::config::networkFileSuffix;
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
    auto ntpServers =  EthernetInterfaceIntf::nTPServers(servers);

    writeConfigurationFile();
    // timesynchd reads the NTP server configuration from the
    // network file.
    restartSystemdUnit(networkdService);
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

    for (const auto& intf: vlanInterfaces)
    {
        intf.second->writeConfigurationFile();
    }

    fs::path confPath = manager.getConfDir();

    std::string fileName = systemd::config::networkFilePrefix + interfaceName() +
                           systemd::config::networkFileSuffix;
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
    stream << "[" << "Match" << "]\n";
    stream << "Name=" << interfaceName() << "\n";

    auto addrs = getAddresses();

    // write the network section
    stream << "[" << "Network" << "]\n";
    stream << "LinkLocalAddressing=yes\n";
    stream << std::boolalpha
           << "IPv6AcceptRA=" << EthernetInterfaceIntf::iPv6AcceptRA() << "\n";

    // Add the VLAN entry
    for (const auto& intf: vlanInterfaces)
    {
        stream << "VLAN=" << intf.second->EthernetInterface::interfaceName()
            << "\n";
    }
    // Add the DHCP entry
    std::string dhcpValue = "false";
    if (dHCPEnabled())
    {
        IPAllowed ipAllowed = EthernetInterfaceIntf::iPAddressEnables();
        if (ipAllowed == IPAllowed::IPv4AndIPv6)
        {
            dhcpValue = "true";
        }
        else if (ipAllowed == IPAllowed::IPv4Only)
        {
            dhcpValue = "ipv4";
        }
        else if (ipAllowed == IPAllowed::IPv6Only)
        {
            dhcpValue = "ipv6";
        }
    }
    stream << "DHCP=" << dhcpValue << "\n";

    // When the interface configured as dhcp, we don't need below given entries
    // in config file.
    if (dHCPEnabled() == false)
    {
        //Add the NTP server
        for (const auto& ntp : EthernetInterfaceIntf::nTPServers())
        {
            stream << "NTP=" << ntp << "\n";
        }

        //Add the DNS entry
        for (const auto& dns : EthernetInterfaceIntf::nameservers())
        {
            stream << "DNS=" << dns << "\n";
        }

        // Static
        for (const auto& addr : addrs)
        {
            if (addr.second->origin() == AddressOrigin::Static)
            {
                std::string address = addr.second->address() + "/" +
                                    std::to_string(addr.second->prefixLength());

                stream << "Address=" << address << "\n";
            }
        }

        if (manager.getSystemConf())
        {
            stream << "Gateway=" << manager.getSystemConf()->defaultGateway()
                   << "\n";
        }

        // write the route section
        for (const auto& addr : addrs)
        {
            if (addr.second->origin() == AddressOrigin::Static)
            {
                int addressFamily = addr.second->type() == IP::Protocol::IPv4 ?
                                    AF_INET : AF_INET6;

                std::string destination = getNetworkID(
                                              addressFamily,
                                              addr.second->address(),
                                              addr.second->prefixLength());

                if (addr.second->gateway() != "0.0.0.0" &&
                    addr.second->gateway() != "" &&
                    destination != "0.0.0.0" &&
                    destination != "")
                {
                    stream << "[" << "Route" << "]\n";
                    stream << "Gateway=" << addr.second->gateway() << "\n";
                    stream << "Destination=" << destination << "\n";
                }
            }
        }
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
            auto intInventoryMac = mac_address::internal::convertToInt(inventoryMac);

            if (intInventoryMac != intMac)
            {
                log<level::ERR>("Given MAC address is neither a local Admin "
                                  "type nor is same as in inventory");
                elog<InvalidArgument>(Argument::ARGUMENT_NAME("MACAddress"),
                                      Argument::ARGUMENT_VALUE(value.c_str()));
            }
        }
        catch(InternalFailure& e)
        {
            log<level::ERR>("Exception occurred during getting of MAC "
                            "address from Inventory");
            return  MacAddressIntf::mACAddress();
        }
    }
    auto interface = interfaceName();
    execute("/sbin/fw_setenv", "fw_setenv", "ethaddr", value.c_str());
    //TODO: would replace below three calls
    //      with restarting of systemd-netwokd
    //      through https://github.com/systemd/systemd/issues/6696
    execute("/sbin/ip", "ip", "link", "set", "dev", interface.c_str(), "down");
    execute("/sbin/ip", "ip", "link", "set", "dev", interface.c_str(), "address",
            value.c_str());

    execute("/sbin/ip", "ip", "link", "set", "dev", interface.c_str(), "up");

    auto mac = MacAddressIntf::mACAddress(std::move(value));
    //update all the vlan interfaces
    for(const auto& intf: vlanInterfaces)
    {
        intf.second->updateMacAddress();
    }

    // restart the systemd networkd so that dhcp client gets the
    // ip for the changed mac address.
    if (dHCPEnabled())
    {
        restartSystemdUnit(networkdService);
    }
    return mac;

}

void EthernetInterface::deleteAll()
{
    if(EthernetInterfaceIntf::dHCPEnabled())
    {
        log<level::INFO>("DHCP enabled on the interface"),
                        entry("INTERFACE=%s", interfaceName().c_str());

    }

    // clear all the ip on the interface
    addrs.clear();
    manager.writeToConfigurationFile();
}

}//namespace network
}//namespace phosphor
