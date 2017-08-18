#include "config.h"
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

constexpr auto mapperBus = "xyz.openbmc_project.ObjectMapper";
constexpr auto mapperObj = "/xyz/openbmc_project/object_mapper";
constexpr auto mapperIntf = "xyz.openbmc_project.ObjectMapper";
constexpr auto propIntf = "org.freedesktop.DBus.Properties";
constexpr auto methodGet = "Get";

using DbusObjectPath = std::string;
using DbusService = std::string;
using DbusInterface = std::string;
using ObjectTree = std::map<DbusObjectPath,
                                  std::map<DbusService, std::vector<DbusInterface>>>;

using Value = sdbusplus::message::variant<std::string>;

constexpr auto invBus = "xyz.openbmc_project.Inventory.Manager";
constexpr auto invNetworkIntf =
        "xyz.openbmc_project.Inventory.Item.NetworkInterface";
constexpr auto invRoot = "/xyz/openbmc_project/inventory";

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
    MacAddressIntf::mACAddress(getMACAddress(intfName));

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
                    std::move(addr.ipaddress),
                    std::make_shared<phosphor::network::IPAddress>(
                        bus,
                        ipAddressObjectPath.c_str(),
                        *this,
                        addressType,
                        addr.ipaddress,
                        origin,
                        addr.prefix,
                        gateway));
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
                std::move(ipaddress),
                std::make_shared<phosphor::network::IPAddress>(
                        bus,
                        objectPath.c_str(),
                        *this,
                        protType,
                        ipaddress,
                        origin,
                        prefixLength,
                        gateway));

    writeConfigurationFile();
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
        const std::string& interfaceName) const
{
    struct ifreq ifr{};
    char macAddress[sizeMAC] {};

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

    snprintf(macAddress, sizeMAC, macAddressFormat,
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
    writeConfigurationFile();
}

void EthernetInterface::deleteVLANObject(const std::string& interface)
{
    using namespace std::string_literals;

    auto it = vlanInterfaces.find(interface);
    if (it == vlanInterfaces.end())
    {
        log<level::ERR>("DeleteVLANObject:Unable to find the object",
                         entry("INTERFACE=%s",interface.c_str()));
        return;
    }

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
    // delete the interface
    vlanInterfaces.erase(it);
    // restart the systemd-networkd

    restartSystemdUnit("systemd-networkd.service");

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
    if (value == EthernetInterfaceIntf::dHCPEnabled())
    {
        return value;
    }

    EthernetInterfaceIntf::dHCPEnabled(value);
    if (value)
    {
        writeConfigurationFile();
        createIPAddressObjects();
    }

    return value;
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
                        EthernetInterfaceIntf::dHCPEnabled(),
                        id,
                        *this,
                        manager);

    // write the device file for the vlan interface.
    vlanIntf->writeDeviceFile();

    this->vlanInterfaces.emplace(vlanInterfaceName,
                                 std::move(vlanIntf));
    // write the new vlan device entry to the configuration(network) file.
    writeConfigurationFile();

    // Create the dbus object for the link local ipv6 address.
    vlanInterfaces[vlanInterfaceName]->createIPAddressObjects();

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
    // DHCP
    if (dHCPEnabled() == true)
    {
        // write the dhcp section if interface is
        // configured as dhcp.
        writeDHCPSection(stream);
        stream.close();
        return;
    }
    // Add the Vlan entry
    for(const auto& intf: vlanInterfaces)
    {
        stream << "VLAN=" << intf.second->EthernetInterface::interfaceName() << "\n";
    }

    // Static
    for (const auto& addr : addrs)
    {
        if (addr.second->origin() == AddressOrigin::Static)
        {
            std::string address = addr.second->address() + "/" + std::to_string(
                                      addr.second->prefixLength());

            stream << "Address=" << address << "\n";
         }
    }

    if (manager.getSystemConf())
    {
        stream << "Gateway=" << manager.getSystemConf()->defaultGateway()
            << "\n";
    }
    // write the route section
    stream << "[" << "Route" << "]\n";
    for(const auto& addr : addrs)
    {
        if (addr.second->origin() == AddressOrigin::Static)
        {
            int addressFamily = addr.second->type() == IP::Protocol::IPv4 ? AF_INET : AF_INET6;
            std::string destination = getNetworkID(
                    addressFamily,
                    addr.second->address(),
                    addr.second->prefixLength());

            if (addr.second->gateway() != "0.0.0.0" &&
                addr.second->gateway() != "" &&
                destination != "0.0.0.0" &&
                destination != "")
            {
                stream << "Gateway=" << addr.second->gateway() << "\n";
                stream << "Destination=" << destination << "\n";
            }

        }
    }

    stream.close();
    restartSystemdUnit("systemd-networkd.service");
}

void EthernetInterface::writeDHCPSection(std::fstream& stream)
{
    using namespace std::string_literals;
    stream << "DHCP=true\n";
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
    }
}

std::string EthernetInterface::mACAddress(std::string value)
{
    if (!validateMAC(value))
    {
        log<level::DEBUG>("MACAddress is not valid.",
                          entry("MAC=%s", value.c_str()));
        return MacAddressIntf::mACAddress();
    }
    // check for local Admin  MAC
    auto intMac = getIntMacAddress(value);

    if (!(intMac & localAdminMask))
    {
        log<level::DEBUG>("MACAddress is not a local admin mac.",
                          entry("MAC=%s", value.c_str()));

        return MacAddressIntf::mACAddress();
    }

    if (!(intMac ^ broadcastMac))
    {
        log<level::DEBUG>("MACAddress is a broadcast mac.",
                          entry("MAC=%s", value.c_str()));
        return MacAddressIntf::mACAddress();
    }

    auto eepRomMac = getMACAddressfromVPD();
    auto invMac = getIntMacAddress(std::move(eepRomMac));

    if (invMac == intMac)
    {
        log<level::DEBUG>("MACAddress is same as VPD mac.");
        return MacAddressIntf::mACAddress();
    }

    execute("/sbin/fw_setenv", "fw_setenv", "ethaddr", value.c_str());
    execute("/sbin/ip", "ip", "link", "set", "dev", "eth0", "down");
    execute("/sbin/ip", "ip", "link", "set", "dev", "eth0", "address",
            value.c_str());

    execute("/sbin/ip", "ip", "link", "set", "dev", "eth0", "up");

    auto mac = MacAddressIntf::mACAddress(std::move(value));
    return mac;

}

std::string EthernetInterface::getMACAddressfromVPD()
{
    std::vector<DbusInterface> interfaces;
    interfaces.emplace_back(invNetworkIntf);

    auto depth = 0;

    auto mapperCall = bus.new_method_call(mapperBus,
                                          mapperObj,
                                          mapperIntf,
                                          "GetSubTree");

    mapperCall.append(invRoot, depth, interfaces);

    auto mapperReply = bus.call(mapperCall);
    if (mapperReply.is_method_error())
    {
        log<level::ERR>("Error in mapper call");
        elog<InternalFailure>();
    }

    ObjectTree objectTree;
    mapperReply.read(objectTree);

    if (objectTree.empty())
    {
        log<level::ERR>("No Object has impelmented the interface",
                        entry("INTERFACE=%s", invNetworkIntf));
        elog<InternalFailure>();
    }

    auto objPath = std::move(objectTree.begin()->first);
    auto service = std::move(objectTree.begin()->second.begin()->first);

    Value value;

    auto method = bus.new_method_call(
                      service.c_str(),
                      objPath.c_str(),
                      propIntf,
                      methodGet);

    method.append(invNetworkIntf, "MACAddress");

    auto reply = bus.call(method);

    if (reply.is_method_error())
    {
         log<level::ERR>("Failed to get MACAddress",
                        entry("PATH=%s", objPath.c_str()),
                        entry("INTERFACE=%s", invNetworkIntf));
        elog<InternalFailure>();
    }

    reply.read(value);
    return value.get<std::string>();
}

}//namespace network
}//namespace phosphor
