#include "config.h"

#include "ethernet_interface.hpp"

#include "config_parser.hpp"
#include "network_manager.hpp"
#include "system_queries.hpp"
#include "util.hpp"

#include <fmt/compile.h>
#include <fmt/format.h>
#include <linux/if_addr.h>
#include <linux/neighbour.h>
#include <linux/rtnetlink.h>

#include <algorithm>
#include <filesystem>
#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/log.hpp>
#include <sdbusplus/bus/match.hpp>
#include <stdplus/raw.hpp>
#include <stdplus/zstring.hpp>
#include <string>
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
using std::literals::string_view_literals::operator""sv;
constexpr auto RESOLVED_SERVICE = "org.freedesktop.resolve1";
constexpr auto RESOLVED_INTERFACE = "org.freedesktop.resolve1.Link";
constexpr auto PROPERTY_INTERFACE = "org.freedesktop.DBus.Properties";
constexpr auto RESOLVED_SERVICE_PATH = "/org/freedesktop/resolve1/link/";
constexpr auto METHOD_GET = "Get";

template <typename Func>
inline decltype(std::declval<Func>()())
    ignoreError(std::string_view msg, stdplus::zstring_view intf,
                decltype(std::declval<Func>()()) fallback, Func&& func) noexcept
{
    try
    {
        return func();
    }
    catch (const std::exception& e)
    {
        auto err = fmt::format("{} failed on {}: {}", msg, intf, e.what());
        log<level::ERR>(err.c_str(), entry("INTERFACE=%s", intf.c_str()));
    }
    return fallback;
}
EthernetInterface::EthernetInterface(sdbusplus::bus_t& bus,
                                     stdplus::zstring_view objPath,
                                     const config::Parser& config,
                                     Manager& parent, bool emitSignal,
                                     std::optional<bool> enabled) :
    Ifaces(bus, objPath.c_str(),
           emitSignal ? Ifaces::action::defer_emit
                      : Ifaces::action::emit_no_signals),
    bus(bus), manager(parent), objPath(objPath)
{
    auto intfName = std::string(objPath.substr(objPath.rfind('/') + 1));
    std::replace(intfName.begin(), intfName.end(), '_', '.');
    interfaceName(intfName);
    ifIdx = system::intfIndex(intfName);
    auto dhcpVal = getDHCPValue(config);
    EthernetInterfaceIntf::dhcp4(dhcpVal.v4);
    EthernetInterfaceIntf::dhcp6(dhcpVal.v6);
    EthernetInterfaceIntf::ipv6AcceptRA(getIPv6AcceptRA(config));
    EthernetInterfaceIntf::nicEnabled(enabled ? *enabled : queryNicEnabled());
    const auto& gatewayList = manager.getRouteTable().getDefaultGateway();
    const auto& gateway6List = manager.getRouteTable().getDefaultGateway6();
    std::string defaultGateway;
    std::string defaultGateway6;

    for (const auto& gateway : gatewayList)
    {
        if (gateway.first == intfName)
        {
            defaultGateway = gateway.second;
            break;
        }
    }

    for (const auto& gateway6 : gateway6List)
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
        auto mac = ignoreError("getMAC", intfName, std::nullopt,
                               [&] { return system::getMAC(intfName); });
        if (mac)
        {
            MacAddressIntf::macAddress(mac_address::toString(*mac));
        }
    }
    EthernetInterfaceIntf::ntpServers(
        config.map.getValueStrings("Network", "NTP"));

    EthernetInterfaceIntf::linkUp(linkUp());
    EthernetInterfaceIntf::mtu(mtu());

    auto ethInfo = ignoreError("GetEthInfo", intfName, {},
                               [&] { return system::getEthInfo(intfName); });
    EthernetInterfaceIntf::autoNeg(ethInfo.autoneg);
    EthernetInterfaceIntf::speed(ethInfo.speed);

    // Emit deferred signal.
    if (emitSignal)
    {
        this->emit_object_added();
    }
}

static IP::Protocol getProtocol(const InAddrAny& addr)
{
    if (std::holds_alternative<in_addr>(addr))
    {
        return IP::Protocol::IPv4;
    }
    else if (std::holds_alternative<in6_addr>(addr))
    {
        return IP::Protocol::IPv6;
    }

    throw std::runtime_error("Invalid addr type");
}

bool EthernetInterface::dhcpIsEnabled(IP::Protocol family)
{
    switch (family)
    {
        case IP::Protocol::IPv6:
            return dhcp6();
        case IP::Protocol::IPv4:
            return dhcp4();
    }
    throw std::logic_error("Unreachable");
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

    AddressFilter filter;
    filter.interface = ifIdx;
    auto currentAddrs = getCurrentAddresses(filter);
    for (const auto& addr : currentAddrs)
    {
        if (addr.flags & IFA_F_DEPRECATED)
        {
            continue;
        }
        auto address = toString(addr.address);
        IP::Protocol addressType = getProtocol(addr.address);
        IP::AddressOrigin origin = IP::AddressOrigin::Static;
        if (dhcpIsEnabled(addressType))
        {
            origin = IP::AddressOrigin::DHCP;
        }
        if (addr.scope == RT_SCOPE_LINK)
        {
            origin = IP::AddressOrigin::LinkLocal;
        }

        auto ipAddressObjectPath =
            generateObjectPath(addressType, address, addr.prefix, origin);

        this->addrs.insert_or_assign(
            address, std::make_unique<IPAddress>(bus, ipAddressObjectPath,
                                                 *this, addressType, address,
                                                 origin, addr.prefix));
    }
}

void EthernetInterface::createStaticNeighborObjects()
{
    staticNeighbors.clear();

    NeighborFilter filter;
    filter.interface = ifIdx;
    filter.state = NUD_PERMANENT;
    auto neighbors = getCurrentNeighbors(filter);
    for (const auto& neighbor : neighbors)
    {
        if (!neighbor.mac)
        {
            continue;
        }
        auto ip = toString(neighbor.address);
        auto mac = mac_address::toString(*neighbor.mac);
        auto objectPath = generateStaticNeighborObjectPath(ip, mac);
        staticNeighbors.emplace(
            ip, std::make_unique<Neighbor>(bus, objectPath, *this, ip, mac,
                                           Neighbor::State::Permanent));
    }
}

ObjectPath EthernetInterface::ip(IP::Protocol protType, std::string ipaddress,
                                 uint8_t prefixLength, std::string)
{
    if (dhcpIsEnabled(protType))
    {
        log<level::INFO>("DHCP enabled on the interface, disabling"),
            entry("INTERFACE=%s", interfaceName().c_str());
        switch (protType)
        {
            case IP::Protocol::IPv4:
                dhcp4(false);
                break;
            case IP::Protocol::IPv6:
                dhcp6(false);
                break;
        }
        // Delete the IP address object and that reloads the networkd
        // to allow the same IP address to be set as Static IP
        deleteObject(ipaddress);
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

    if (!isValidPrefix(addressFamily, prefixLength))
    {
        log<level::ERR>("PrefixLength is not correct "),
            entry("PREFIXLENGTH=%" PRIu8, prefixLength);
        elog<InvalidArgument>(
            Argument::ARGUMENT_NAME("prefixLength"),
            Argument::ARGUMENT_VALUE(std::to_string(prefixLength).c_str()));
    }

    auto objectPath =
        generateObjectPath(protType, ipaddress, prefixLength, origin);
    this->addrs.insert_or_assign(
        ipaddress,
        std::make_unique<IPAddress>(bus, objectPath, *this, protType, ipaddress,
                                    origin, prefixLength));

    writeConfigurationFile();
    manager.reloadConfigs();

    return objectPath;
}

ObjectPath EthernetInterface::neighbor(std::string ipAddress,
                                       std::string macAddress)
{
    if (!isValidIP(ipAddress))
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

    auto objectPath = generateStaticNeighborObjectPath(ipAddress, macAddress);
    staticNeighbors.emplace(
        ipAddress,
        std::make_unique<Neighbor>(bus, objectPath, *this, ipAddress,
                                   macAddress, Neighbor::State::Permanent));

    writeConfigurationFile();
    manager.reloadConfigs();

    return objectPath;
}

void EthernetInterface::deleteObject(std::string_view ipaddress)
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

void EthernetInterface::deleteStaticNeighborObject(std::string_view ipAddress)
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

void EthernetInterface::deleteVLANFromSystem(stdplus::zstring_view interface)
{
    const auto& confDir = manager.getConfDir();
    auto networkFile = config::pathForIntfConf(confDir, interface);
    auto deviceFile = config::pathForIntfDev(confDir, interface);

    // delete the vlan network file
    std::error_code ec;
    std::filesystem::remove(networkFile, ec);
    std::filesystem::remove(deviceFile, ec);

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

void EthernetInterface::deleteVLANObject(stdplus::zstring_view interface)
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
    IP::Protocol addressType, std::string_view ipAddress, uint8_t prefixLength,
    IP::AddressOrigin origin) const
{
    std::string_view type;
    switch (addressType)
    {
        case IP::Protocol::IPv4:
            type = "ipv4"sv;
            break;
        case IP::Protocol::IPv6:
            type = "ipv6"sv;
            break;
    }
    return fmt::format(
        FMT_COMPILE("{}/{}/{:08x}"), objPath, type,
        static_cast<uint32_t>(hash_multi(
            ipAddress, prefixLength,
            static_cast<std::underlying_type_t<IP::AddressOrigin>>(origin))));
}

std::string EthernetInterface::generateStaticNeighborObjectPath(
    std::string_view ipAddress, std::string_view macAddress) const
{
    return fmt::format(
        FMT_COMPILE("{}/static_neighbor/{:08x}"), objPath,
        static_cast<uint32_t>(hash_multi(ipAddress, macAddress)));
}

bool EthernetInterface::ipv6AcceptRA(bool value)
{
    if (ipv6AcceptRA() != EthernetInterfaceIntf::ipv6AcceptRA(value))
    {
        writeConfigurationFile();
        manager.reloadConfigs();
    }
    return value;
}

bool EthernetInterface::dhcp4(bool value)
{
    if (dhcp4() != EthernetInterfaceIntf::dhcp4(value))
    {
        writeConfigurationFile();
        manager.reloadConfigs();
    }
    return value;
}

bool EthernetInterface::dhcp6(bool value)
{
    if (dhcp6() != EthernetInterfaceIntf::dhcp6(value))
    {
        writeConfigurationFile();
        manager.reloadConfigs();
    }
    return value;
}

EthernetInterface::DHCPConf EthernetInterface::dhcpEnabled(DHCPConf value)
{
    auto old4 = EthernetInterfaceIntf::dhcp4();
    auto new4 = EthernetInterfaceIntf::dhcp4(value == DHCPConf::v4 ||
                                             value == DHCPConf::v4v6stateless ||
                                             value == DHCPConf::both);
    auto old6 = EthernetInterfaceIntf::dhcp6();
    auto new6 = EthernetInterfaceIntf::dhcp6(value == DHCPConf::v6 ||
                                             value == DHCPConf::both);
    auto oldra = EthernetInterfaceIntf::ipv6AcceptRA();
    auto newra = EthernetInterfaceIntf::ipv6AcceptRA(
        value == DHCPConf::v6stateless || value == DHCPConf::v4v6stateless ||
        value == DHCPConf::v6 || value == DHCPConf::both);

    if (old4 != new4 || old6 != new6 || oldra != newra)
    {
        writeConfigurationFile();
        manager.reloadConfigs();
    }
    return value;
}

EthernetInterface::DHCPConf EthernetInterface::dhcpEnabled() const
{
    if (dhcp6())
    {
        return dhcp4() ? DHCPConf::both : DHCPConf::v6;
    }
    else if (dhcp4())
    {
        return ipv6AcceptRA() ? DHCPConf::v4v6stateless : DHCPConf::v4;
    }
    return ipv6AcceptRA() ? DHCPConf::v6stateless : DHCPConf::none;
}

bool EthernetInterface::linkUp() const
{
    return system::intfIsRunning(interfaceName());
}

size_t EthernetInterface::mtu() const
{
    const auto ifname = interfaceName();
    return ignoreError("getMTU", ifname, std::nullopt,
                       [&] { return system::getMTU(ifname); })
        .value_or(EthernetInterfaceIntf::mtu());
}

size_t EthernetInterface::mtu(size_t value)
{
    const size_t old = EthernetInterfaceIntf::mtu();
    if (value == old)
    {
        return value;
    }
    const auto ifname = interfaceName();
    return EthernetInterfaceIntf::mtu(ignoreError("setMTU", ifname, old, [&] {
        system::setMTU(ifname, value);
        return value;
    }));
}

bool EthernetInterface::queryNicEnabled() const
{
    constexpr auto svc = "org.freedesktop.network1";
    constexpr auto intf = "org.freedesktop.network1.Link";
    constexpr auto prop = "AdministrativeState";
    char* rpath;
    sd_bus_path_encode("/org/freedesktop/network1/link",
                       std::to_string(ifIdx).c_str(), &rpath);
    std::string path(rpath);
    free(rpath);

    // Store / Parser for the AdministrativeState return value
    std::optional<bool> ret;
    auto cb = [&](std::string_view state) {
        if (state != "initialized")
        {
            ret = state != "unmanaged";
        }
    };

    // Build a matcher before making the property call to ensure we
    // can eventually get the value.
    sdbusplus::bus::match_t match(
        bus,
        fmt::format("type='signal',sender='{}',path='{}',interface='{}',member="
                    "'PropertiesChanged',arg0='{}',",
                    svc, path, PROPERTY_INTERFACE, intf)
            .c_str(),
        [&](sdbusplus::message_t& m) {
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

    EthernetInterfaceIntf::nicEnabled(value);
    writeConfigurationFile();
    if (!value)
    {
        // We only need to bring down the interface, networkd will always bring
        // up managed interfaces
        manager.addReloadPreHook(
            [ifname = interfaceName()]() { system::setNICUp(ifname, false); });
    }
    manager.reloadConfigs();

    return value;
}

ServerList EthernetInterface::staticNameServers(ServerList value)
{
    for (const auto& nameserverip : value)
    {
        if (!isValidIP(nameserverip))
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

void EthernetInterface::loadNameServers(const config::Parser& config)
{
    EthernetInterfaceIntf::nameservers(getNameServerFromResolvd());
    EthernetInterfaceIntf::staticNameServers(
        config.map.getValueStrings("Network", "DNS"));
}

ServerList EthernetInterface::getNameServerFromResolvd()
{
    ServerList servers;
    auto OBJ_PATH = fmt::format("{}{}", RESOLVED_SERVICE_PATH, ifIdx);

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
    catch (const sdbusplus::exception_t& e)
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

std::string EthernetInterface::vlanIntfName(VlanId id) const
{
    return fmt::format(FMT_COMPILE("{}.{}"), interfaceName(), id);
}

std::string EthernetInterface::vlanObjPath(VlanId id) const
{
    return fmt::format(FMT_COMPILE("{}_{}"), objPath, id);
}

void EthernetInterface::loadVLAN(VlanId id)
{
    auto vlanInterfaceName = vlanIntfName(id);
    auto path = vlanObjPath(id);

    config::Parser config(
        config::pathForIntfConf(manager.getConfDir(), vlanInterfaceName));

    auto vlanIntf = std::make_unique<phosphor::network::VlanInterface>(
        bus, path.c_str(), config, EthernetInterfaceIntf::nicEnabled(), id,
        *this, manager);

    // Fetch the ip address from the system
    // and create the dbus object.
    vlanIntf->createIPAddressObjects();
    vlanIntf->createStaticNeighborObjects();
    vlanIntf->loadNameServers(config);

    this->vlanInterfaces.emplace(std::move(vlanInterfaceName),
                                 std::move(vlanIntf));
}

ObjectPath EthernetInterface::createVLAN(VlanId id)
{
    auto vlanInterfaceName = vlanIntfName(id);
    if (this->vlanInterfaces.find(vlanInterfaceName) !=
        this->vlanInterfaces.end())
    {
        log<level::ERR>("VLAN already exists", entry("VLANID=%u", id));
        elog<InvalidArgument>(
            Argument::ARGUMENT_NAME("VLANId"),
            Argument::ARGUMENT_VALUE(std::to_string(id).c_str()));
    }

    auto path = vlanObjPath(id);

    // Pass the parents nicEnabled property, so that the child
    // VLAN interface can inherit.
    auto vlanIntf = std::make_unique<phosphor::network::VlanInterface>(
        bus, path.c_str(), config::Parser(),
        EthernetInterfaceIntf::nicEnabled(), id, *this, manager);

    // write the device file for the vlan interface.
    vlanIntf->writeDeviceFile();

    this->vlanInterfaces.emplace(vlanInterfaceName, std::move(vlanIntf));

    writeConfigurationFile();
    manager.reloadConfigs();

    return path;
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
    for (const auto& intf : vlanInterfaces)
    {
        intf.second->writeConfigurationFile();
    }

    config::Parser config;
    config.map["Match"].emplace_back()["Name"].emplace_back(interfaceName());
    {
        auto& link = config.map["Link"].emplace_back();
#ifdef PERSIST_MAC
        auto mac = MacAddressIntf::macAddress();
        if (!mac.empty())
        {
            link["MACAddress"].emplace_back(mac);
        }
#endif
        if (!EthernetInterfaceIntf::nicEnabled())
        {
            link["Unmanaged"].emplace_back("yes");
        }
    }
    {
        auto& network = config.map["Network"].emplace_back();
        auto& lla = network["LinkLocalAddressing"];
#ifdef LINK_LOCAL_AUTOCONFIGURATION
        lla.emplace_back("yes");
#else
        lla.emplace_back("no");
#endif
        network["IPv6AcceptRA"].emplace_back(ipv6AcceptRA() ? "true" : "false");
        network["DHCP"].emplace_back(dhcp4() ? (dhcp6() ? "true" : "ipv4")
                                             : (dhcp6() ? "ipv6" : "false"));
        {
            auto& vlans = network["VLAN"];
            for (const auto& intf : vlanInterfaces)
            {
                vlans.emplace_back(
                    intf.second->EthernetInterface::interfaceName());
            }
        }
        {
            auto& ntps = network["NTP"];
            for (const auto& ntp : EthernetInterfaceIntf::ntpServers())
            {
                ntps.emplace_back(ntp);
            }
        }
        {
            auto& dnss = network["DNS"];
            for (const auto& dns : EthernetInterfaceIntf::staticNameServers())
            {
                dnss.emplace_back(dns);
            }
        }
        {
            auto& address = network["Address"];
            for (const auto& addr : getAddresses())
            {
                if (originIsManuallyAssigned(addr.second->origin()) &&
                    !dhcpIsEnabled(addr.second->type()))
                {
                    address.emplace_back(
                        fmt::format("{}/{}", addr.second->address(),
                                    addr.second->prefixLength()));
                }
            }
        }
        {
            auto& gateways = network["Gateway"];
            if (!dhcp4())
            {
                auto gateway = EthernetInterfaceIntf::defaultGateway();
                if (!gateway.empty())
                {
                    gateways.emplace_back(gateway);
                }
            }

            if (!dhcp6())
            {
                auto gateway6 = EthernetInterfaceIntf::defaultGateway6();
                if (!gateway6.empty())
                {
                    gateways.emplace_back(gateway6);
                }
            }
        }
    }
    config.map["IPv6AcceptRA"].emplace_back()["DHCPv6Client"].emplace_back(
        dhcp6() ? "true" : "false");
    {
        auto& neighbors = config.map["Neighbor"];
        for (const auto& sneighbor : staticNeighbors)
        {
            auto& neighbor = neighbors.emplace_back();
            neighbor["Address"].emplace_back(sneighbor.second->ipAddress());
            neighbor["MACAddress"].emplace_back(sneighbor.second->macAddress());
        }
    }
    {
        auto& dhcp = config.map["DHCP"].emplace_back();
        dhcp["ClientIdentifier"].emplace_back("mac");
        if (manager.getDHCPConf())
        {
            const auto& conf = *manager.getDHCPConf();
            auto dns_enabled = conf.dnsEnabled() ? "true" : "false";
            dhcp["UseDNS"].emplace_back(dns_enabled);
            dhcp["UseDomains"].emplace_back(dns_enabled);
            dhcp["UseNTP"].emplace_back(conf.ntpEnabled() ? "true" : "false");
            dhcp["UseHostname"].emplace_back(conf.hostNameEnabled() ? "true"
                                                                    : "false");
            dhcp["SendHostname"].emplace_back(
                conf.sendHostNameEnabled() ? "true" : "false");
        }
    }
    auto path = config::pathForIntfConf(manager.getConfDir(), interfaceName());
    config.writeFile(path);
    auto msg = fmt::format("Wrote networkd file: {}", path.native());
    log<level::INFO>(msg.c_str(), entry("FILE=%s", path.c_str()));
}

std::string EthernetInterface::macAddress([[maybe_unused]] std::string value)
{
#ifdef PERSIST_MAC
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

        writeConfigurationFile();
        manager.addReloadPreHook([interface]() {
            // The MAC and LLADDRs will only update if the NIC is already down
            system::setNICUp(interface, false);
        });
        manager.reloadConfigs();
    }

#ifdef HAVE_UBOOT_ENV
    // Ensure that the valid address is stored in the u-boot-env
    auto envVar = interfaceToUbootEthAddr(interface);
    if (envVar)
    {
        // Trimming MAC addresses that are out of range. eg: AA:FF:FF:FF:FF:100;
        // and those having more than 6 bytes. eg: AA:AA:AA:AA:AA:AA:BB
        execute("/sbin/fw_setenv", "fw_setenv", envVar->c_str(),
                validMAC.c_str());
    }
#endif // HAVE_UBOOT_ENV

    return value;
#else
    elog<NotAllowed>(
        NotAllowedArgument::REASON("Writing MAC address is not allowed"));
#endif // PERSIST_MAC
}

void EthernetInterface::deleteAll()
{
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

    if (!isValidIP(AF_INET, gateway) && !gateway.empty())
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

    if (!isValidIP(AF_INET6, gateway) && !gateway.empty())
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
