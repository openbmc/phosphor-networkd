#include "config.h"

#include "ethernet_interface.hpp"

#include "config_parser.hpp"
#include "network_manager.hpp"
#include "system_queries.hpp"
#include "util.hpp"

#include <linux/rtnetlink.h>
#include <net/if.h>
#include <net/if_arp.h>

#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/lg2.hpp>
#include <stdplus/fd/create.hpp>
#include <stdplus/raw.hpp>
#include <stdplus/str/cat.hpp>
#include <stdplus/zstring.hpp>
#include <xyz/openbmc_project/Common/error.hpp>

#include <algorithm>
#include <filesystem>
#include <format>
#include <string>
#include <unordered_map>
#include <variant>

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

constexpr auto TIMESYNCD_SERVICE = "org.freedesktop.timesync1";
constexpr auto TIMESYNCD_INTERFACE = "org.freedesktop.timesync1.Manager";
constexpr auto TIMESYNCD_SERVICE_PATH = "/org/freedesktop/timesync1";

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
        lg2::error("{MSG} failed on {NET_INTF}: {ERROR}", "MSG", msg,
                   "NET_INTF", intf, "ERROR", e);
    }
    return fallback;
}

static std::string makeObjPath(std::string_view root, std::string_view intf)
{
    auto ret = stdplus::strCat(root, "/"sv, intf);
    std::replace(ret.begin() + ret.size() - intf.size(), ret.end(), '.', '_');
    return ret;
}

template <typename Addr>
static bool validIntfIP(Addr a) noexcept
{
    return a.isUnicast() && !a.isLoopback();
}

EthernetInterface::EthernetInterface(stdplus::PinnedRef<sdbusplus::bus_t> bus,
                                     stdplus::PinnedRef<Manager> manager,
                                     const AllIntfInfo& info,
                                     std::string_view objRoot,
                                     const config::Parser& config,
                                     bool enabled) :
    EthernetInterface(bus, manager, info, makeObjPath(objRoot, *info.intf.name),
                      config, enabled)
{}

EthernetInterface::EthernetInterface(stdplus::PinnedRef<sdbusplus::bus_t> bus,
                                     stdplus::PinnedRef<Manager> manager,
                                     const AllIntfInfo& info,
                                     std::string&& objPath,
                                     const config::Parser& config,
                                     bool enabled) :
    Ifaces(bus, objPath.c_str(), Ifaces::action::defer_emit),
    manager(manager), bus(bus), objPath(std::move(objPath))
{
    interfaceName(*info.intf.name, true);
    auto dhcpVal = getDHCPValue(config);
    EthernetInterfaceIntf::dhcp4(dhcpVal.v4, true);
    EthernetInterfaceIntf::dhcp6(dhcpVal.v6, true);
    EthernetInterfaceIntf::ipv6AcceptRA(getIPv6AcceptRA(config), true);
    EthernetInterfaceIntf::nicEnabled(enabled, true);

    EthernetInterfaceIntf::ntpServers(
        config.map.getValueStrings("Network", "NTP"), true);

    updateInfo(info.intf, true);

    if (info.defgw4)
    {
        EthernetInterface::defaultGateway(stdplus::toStr(*info.defgw4), true);
    }
    if (info.defgw6)
    {
        EthernetInterface::defaultGateway6(stdplus::toStr(*info.defgw6), true);
    }
    emit_object_added();

    if (info.intf.vlan_id)
    {
        if (!info.intf.parent_idx)
        {
            std::runtime_error("Missing parent link");
        }
        vlan.emplace(bus, this->objPath.c_str(), info.intf, *this);
    }
    dhcp4Conf.emplace(bus, this->objPath + "/dhcp4", *this, DHCPType::v4);
    dhcp6Conf.emplace(bus, this->objPath + "/dhcp6", *this, DHCPType::v6);
    for (const auto& [_, addr] : info.addrs)
    {
        addAddr(addr);
    }
    for (const auto& [_, neigh] : info.staticNeighs)
    {
        addStaticNeigh(neigh);
    }
}

void EthernetInterface::updateInfo(const InterfaceInfo& info, bool skipSignal)
{
    ifIdx = info.idx;
    EthernetInterfaceIntf::linkUp(info.flags & IFF_RUNNING, skipSignal);
    if (info.mac)
    {
        MacAddressIntf::macAddress(stdplus::toStr(*info.mac), skipSignal);
    }
    if (info.mtu)
    {
        EthernetInterfaceIntf::mtu(*info.mtu, skipSignal);
    }
    if (ifIdx > 0)
    {
        auto ethInfo = ignoreError("GetEthInfo", *info.name, {}, [&] {
            return system::getEthInfo(*info.name);
        });
        EthernetInterfaceIntf::autoNeg(ethInfo.autoneg, skipSignal);
        EthernetInterfaceIntf::speed(ethInfo.speed, skipSignal);
    }
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

void EthernetInterface::addAddr(const AddressInfo& info)
{
    IP::AddressOrigin origin = IP::AddressOrigin::Static;
    if (dhcpIsEnabled(info.ifaddr.getAddr()))
    {
        origin = IP::AddressOrigin::DHCP;
    }

#ifdef LINK_LOCAL_AUTOCONFIGURATION
    if (info.scope == RT_SCOPE_LINK)
    {
        origin = IP::AddressOrigin::LinkLocal;
    }
#endif

    if ((info.scope == RT_SCOPE_UNIVERSE) && (info.flags & IFA_F_PERMANENT))
    {
        origin = IP::AddressOrigin::Static;
    }
    if ((info.scope == RT_SCOPE_UNIVERSE) &&
        ((info.flags & IFA_F_NOPREFIXROUTE) &&
         (info.flags & IFA_F_MANAGETEMPADDR)))
    {
        origin = IP::AddressOrigin::SLAAC;
    }
    else if ((info.scope == RT_SCOPE_UNIVERSE) &&
             ((info.flags & IFA_F_NOPREFIXROUTE)))
    {
        origin = IP::AddressOrigin::DHCP;
    }

    auto it = addrs.find(info.ifaddr);
    if (it == addrs.end())
    {
        addrs.emplace(info.ifaddr, std::make_unique<IPAddress>(
                                       bus, std::string_view(objPath), *this,
                                       info.ifaddr, origin));
    }
    else
    {
        it->second->IPIfaces::origin(origin);
    }
}

void EthernetInterface::addStaticNeigh(const NeighborInfo& info)
{
    if (!info.mac || !info.addr)
    {
        lg2::error("Missing neighbor mac on {NET_INTF}", "NET_INTF",
                   interfaceName());
        return;
    }

    if (auto it = staticNeighbors.find(*info.addr); it != staticNeighbors.end())
    {
        it->second->NeighborObj::macAddress(stdplus::toStr(*info.mac));
    }
    else
    {
        staticNeighbors.emplace(*info.addr, std::make_unique<Neighbor>(
                                                bus, std::string_view(objPath),
                                                *this, *info.addr, *info.mac,
                                                Neighbor::State::Permanent));
    }
}

ObjectPath EthernetInterface::ip(IP::Protocol protType, std::string ipaddress,
                                 uint8_t prefixLength, std::string)
{
    std::optional<stdplus::InAnyAddr> addr;
    try
    {
        switch (protType)
        {
            case IP::Protocol::IPv4:
                addr.emplace(stdplus::fromStr<stdplus::In4Addr>(ipaddress));
                break;
            case IP::Protocol::IPv6:
                addr.emplace(stdplus::fromStr<stdplus::In6Addr>(ipaddress));
                break;
            default:
                throw std::logic_error("Exhausted protocols");
        }
        if (!std::visit([](auto ip) { return validIntfIP(ip); }, *addr))
        {
            throw std::invalid_argument("not unicast");
        }
    }
    catch (const std::exception& e)
    {
        lg2::error("Invalid IP {NET_IP}: {ERROR}", "NET_IP", ipaddress, "ERROR",
                   e);
        elog<InvalidArgument>(Argument::ARGUMENT_NAME("ipaddress"),
                              Argument::ARGUMENT_VALUE(ipaddress.c_str()));
    }
    std::optional<stdplus::SubnetAny> ifaddr;
    try
    {
        if (prefixLength == 0)
        {
            throw std::invalid_argument("default route");
        }
        ifaddr.emplace(*addr, prefixLength);
    }
    catch (const std::exception& e)
    {
        lg2::error("Invalid prefix length {NET_PFX}: {ERROR}", "NET_PFX",
                   prefixLength, "ERROR", e);
        elog<InvalidArgument>(
            Argument::ARGUMENT_NAME("prefixLength"),
            Argument::ARGUMENT_VALUE(stdplus::toStr(prefixLength).c_str()));
    }

    auto it = addrs.find(*ifaddr);
    if (it == addrs.end())
    {
        it = std::get<0>(addrs.emplace(
            *ifaddr,
            std::make_unique<IPAddress>(bus, std::string_view(objPath), *this,
                                        *ifaddr, IP::AddressOrigin::Static)));
    }
    else
    {
        if (it->second->origin() == IP::AddressOrigin::Static)
        {
            return it->second->getObjPath();
        }
        it->second->IPIfaces::origin(IP::AddressOrigin::Static);
    }

    writeConfigurationFile();
    manager.get().reloadConfigs();

    return it->second->getObjPath();
}

ObjectPath EthernetInterface::neighbor(std::string ipAddress,
                                       std::string macAddress)
{
    std::optional<stdplus::InAnyAddr> addr;
    try
    {
        addr.emplace(stdplus::fromStr<stdplus::InAnyAddr>(ipAddress));
    }
    catch (const std::exception& e)
    {
        lg2::error("Not a valid IP address {NET_IP}: {ERROR}", "NET_IP",
                   ipAddress, "ERROR", e);
        elog<InvalidArgument>(Argument::ARGUMENT_NAME("ipAddress"),
                              Argument::ARGUMENT_VALUE(ipAddress.c_str()));
    }

    std::optional<stdplus::EtherAddr> lladdr;
    try
    {
        lladdr.emplace(stdplus::fromStr<stdplus::EtherAddr>(macAddress));
    }
    catch (const std::exception& e)
    {
        lg2::error("Not a valid MAC address {NET_MAC}: {ERROR}", "NET_MAC",
                   macAddress, "ERROR", e);
        elog<InvalidArgument>(Argument::ARGUMENT_NAME("macAddress"),
                              Argument::ARGUMENT_VALUE(macAddress.c_str()));
    }

    auto it = staticNeighbors.find(*addr);
    if (it == staticNeighbors.end())
    {
        it = std::get<0>(staticNeighbors.emplace(
            *addr, std::make_unique<Neighbor>(bus, std::string_view(objPath),
                                              *this, *addr, *lladdr,
                                              Neighbor::State::Permanent)));
    }
    else
    {
        auto str = stdplus::toStr(*lladdr);
        if (it->second->macAddress() == str)
        {
            return it->second->getObjPath();
        }
        it->second->NeighborObj::macAddress(str);
    }

    writeConfigurationFile();
    manager.get().reloadConfigs();

    return it->second->getObjPath();
}

bool EthernetInterface::ipv6AcceptRA(bool value)
{
    if (ipv6AcceptRA() != EthernetInterfaceIntf::ipv6AcceptRA(value))
    {
        writeConfigurationFile();
        manager.get().reloadConfigs();
    }
    return value;
}

bool EthernetInterface::dhcp4(bool value)
{
    if (dhcp4() != EthernetInterfaceIntf::dhcp4(value))
    {
        writeConfigurationFile();
        manager.get().reloadConfigs();
    }
    return value;
}

bool EthernetInterface::dhcp6(bool value)
{
    if (dhcp6() != EthernetInterfaceIntf::dhcp6(value))
    {
        writeConfigurationFile();
        manager.get().reloadConfigs();
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
        manager.get().reloadConfigs();
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

size_t EthernetInterface::mtu(size_t value)
{
    const size_t old = EthernetInterfaceIntf::mtu();
    if (value == old)
    {
        return value;
    }
    const auto ifname = interfaceName();
    return EthernetInterfaceIntf::mtu(ignoreError("SetMTU", ifname, old, [&] {
        system::setMTU(ifname, value);
        return value;
    }));
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
        manager.get().addReloadPreHook(
            [ifname = interfaceName()]() { system::setNICUp(ifname, false); });
    }
    manager.get().reloadConfigs();

    return value;
}

ServerList EthernetInterface::staticNameServers(ServerList value)
{
    std::vector<std::string> dnsUniqueValues;
    for (auto& ip : value)
    {
        try
        {
            ip = stdplus::toStr(stdplus::fromStr<stdplus::InAnyAddr>(ip));
        }
        catch (const std::exception& e)
        {
            lg2::error("Not a valid IP address {NET_IP}: {ERROR}", "NET_IP", ip,
                       "ERROR", e);
            elog<InvalidArgument>(Argument::ARGUMENT_NAME("StaticNameserver"),
                                  Argument::ARGUMENT_VALUE(ip.c_str()));
        }
        if (std::find(dnsUniqueValues.begin(), dnsUniqueValues.end(), ip) ==
            dnsUniqueValues.end())
        {
            dnsUniqueValues.push_back(ip);
        }
    }

    value =
        EthernetInterfaceIntf::staticNameServers(std::move(dnsUniqueValues));

    writeConfigurationFile();
    manager.get().reloadConfigs();

    return value;
}

void EthernetInterface::loadNTPServers(const config::Parser& config)
{
    EthernetInterfaceIntf::ntpServers(getNTPServerFromTimeSyncd());
    EthernetInterfaceIntf::staticNTPServers(
        config.map.getValueStrings("Network", "NTP"));
}

void EthernetInterface::loadNameServers(const config::Parser& config)
{
    EthernetInterfaceIntf::nameservers(getNameServerFromResolvd());
    EthernetInterfaceIntf::staticNameServers(
        config.map.getValueStrings("Network", "DNS"));
}

ServerList EthernetInterface::getNTPServerFromTimeSyncd()
{
    ServerList servers; // Variable to capture the NTP Server IPs
    auto method = bus.get().new_method_call(TIMESYNCD_SERVICE,
                                            TIMESYNCD_SERVICE_PATH,
                                            PROPERTY_INTERFACE, METHOD_GET);

    method.append(TIMESYNCD_INTERFACE, "LinkNTPServers");

    try
    {
        auto reply = bus.get().call(method);
        std::variant<ServerList> response;
        reply.read(response);
        servers = std::get<ServerList>(response);
    }
    catch (const sdbusplus::exception::SdBusError& e)
    {
        lg2::error("Failed to get NTP server information from "
                   "systemd-timesyncd: {ERROR}",
                   "ERROR", e);
    }

    return servers;
}

ServerList EthernetInterface::nameservers() const
{
    return getNameServerFromResolvd();
}

ServerList EthernetInterface::getNameServerFromResolvd() const
{
    ServerList servers;
    auto OBJ_PATH = std::format("{}{}", RESOLVED_SERVICE_PATH, ifIdx);

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
    auto method = bus.get().new_method_call(RESOLVED_SERVICE, OBJ_PATH.c_str(),
                                            PROPERTY_INTERFACE, METHOD_GET);

    method.append(RESOLVED_INTERFACE, "DNS");

    try
    {
        auto reply = bus.get().call(method);
        reply.read(name);
    }
    catch (const sdbusplus::exception_t& e)
    {
        lg2::error(
            "Failed to get DNS information from systemd-resolved: {ERROR}",
            "ERROR", e);
    }
    auto tupleVector = std::get_if<type>(&name);
    for (auto i = tupleVector->begin(); i != tupleVector->end(); ++i)
    {
        int addressFamily = std::get<0>(*i);
        std::vector<uint8_t>& ipaddress = std::get<1>(*i);
        servers.push_back(stdplus::toStr(
            addrFromBuf(addressFamily, stdplus::raw::asView<char>(ipaddress))));
    }
    return servers;
}

ObjectPath EthernetInterface::createVLAN(uint16_t id)
{
    auto idStr = stdplus::toStr(id);
    auto intfName = stdplus::strCat(interfaceName(), "."sv, idStr);
    if (manager.get().interfaces.find(intfName) !=
        manager.get().interfaces.end())
    {
        lg2::error("VLAN {NET_VLAN} already exists", "NET_VLAN", id);
        elog<InvalidArgument>(Argument::ARGUMENT_NAME("VLANId"),
                              Argument::ARGUMENT_VALUE(idStr.c_str()));
    }

    auto objRoot = std::string_view(objPath).substr(0, objPath.rfind('/'));
    auto macStr = MacAddressIntf::macAddress();
    std::optional<stdplus::EtherAddr> mac;
    if (!macStr.empty())
    {
        mac.emplace(stdplus::fromStr<stdplus::EtherAddr>(macStr));
    }
    auto info = AllIntfInfo{InterfaceInfo{
        .type = ARPHRD_ETHER,
        .idx = 0, // TODO: Query the correct value after creation
        .flags = 0,
        .name = intfName,
        .mac = std::move(mac),
        .mtu = mtu(),
        .parent_idx = ifIdx,
        .vlan_id = id,
    }};

    // Pass the parents nicEnabled property, so that the child
    // VLAN interface can inherit.
    auto vlanIntf = std::make_unique<EthernetInterface>(
        bus, manager, info, objRoot, config::Parser(), nicEnabled());
    ObjectPath ret = vlanIntf->objPath;

    manager.get().interfaces.emplace(intfName, std::move(vlanIntf));

    // write the device file for the vlan interface.
    config::Parser config;
    auto& netdev = config.map["NetDev"].emplace_back();
    netdev["Name"].emplace_back(intfName);
    netdev["Kind"].emplace_back("vlan");
    config.map["VLAN"].emplace_back()["Id"].emplace_back(std::move(idStr));
    config.writeFile(
        config::pathForIntfDev(manager.get().getConfDir(), intfName));

    writeConfigurationFile();
    manager.get().reloadConfigs();

    return ret;
}

ServerList EthernetInterface::staticNTPServers(ServerList value)
{
    value = EthernetInterfaceIntf::staticNTPServers(std::move(value));

    writeConfigurationFile();
    manager.get().reloadConfigs();

    return value;
}

ServerList EthernetInterface::ntpServers(ServerList /*servers*/)
{
    elog<NotAllowed>(NotAllowedArgument::REASON("ReadOnly Property"));
}

static constexpr std::string_view tfStr(bool value)
{
    return value ? "true"sv : "false"sv;
}

static void writeUpdatedTime(const std::filesystem::path &netFile)
{
    // JFFS2 doesn't have the time granularity to deal with sub-second
    // updates. Since we can have multiple file updates within a second
    // around a reload, we need a location which gives that precision for
    // future networkd detected reloads. TMPFS gives us this property.
    if (manager.get().getConfDir() == "/etc/systemd/network"sv)
    {
        auto dir = stdplus::strCat(netFile.native(), ".d");
        dir.replace(1, 3, "run"); // Replace /etc with /run
        auto file = dir + "/updated.conf";
        try
        {
            std::filesystem::create_directories(dir);
            using namespace stdplus::fd;
            open(file, OpenFlags(OpenAccess::WriteOnly).set(OpenFlag::Create),
                 0644);
        }
        catch (const std::exception& e)
        {
            lg2::error("Failed to write time updated file {FILE}: {ERROR}",
                       "FILE", file, "ERROR", e.what());
        }
    }
}

void EthernetInterface::writeConfigurationFile()
{
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
            for (const auto& [_, intf] : manager.get().interfaces)
            {
                if (intf->vlan && intf->vlan->parentIdx == ifIdx)
                {
                    vlans.emplace_back(intf->interfaceName());
                }
            }
        }
        {
            auto& ntps = network["NTP"];
            for (const auto& ntp : EthernetInterfaceIntf::staticNTPServers())
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
            for (const auto& addr : addrs)
            {
                if (originIsManuallyAssigned(addr.second->origin()))
                {
                    address.emplace_back(stdplus::toStr(addr.first));
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

            if (!ipv6AcceptRA())
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
        auto& dhcp4 = config.map["DHCPv4"].emplace_back();
        dhcp4["ClientIdentifier"].emplace_back("mac");
        dhcp4["UseDNS"].emplace_back(tfStr(dhcp4Conf->dnsEnabled()));
        dhcp4["UseDomains"].emplace_back(tfStr(dhcp4Conf->domainEnabled()));
        dhcp4["UseNTP"].emplace_back(tfStr(dhcp4Conf->ntpEnabled()));
        dhcp4["UseHostname"].emplace_back(tfStr(dhcp4Conf->hostNameEnabled()));
        dhcp4["SendHostname"].emplace_back(
            tfStr(dhcp4Conf->sendHostNameEnabled()));
    }
    {
        auto& dhcp6 = config.map["DHCPv6"].emplace_back();
        dhcp6["UseDNS"].emplace_back(tfStr(dhcp6Conf->dnsEnabled()));
        dhcp6["UseDomains"].emplace_back(tfStr(dhcp6Conf->domainEnabled()));
        dhcp6["UseNTP"].emplace_back(tfStr(dhcp6Conf->ntpEnabled()));
        dhcp6["UseHostname"].emplace_back(tfStr(dhcp6Conf->hostNameEnabled()));
        dhcp6["SendHostname"].emplace_back(
            tfStr(dhcp6Conf->sendHostNameEnabled()));
    }
    auto path = config::pathForIntfConf(manager.get().getConfDir(),
                                        interfaceName());
    config.writeFile(path);
    lg2::info("Wrote networkd file: {CFG_FILE}", "CFG_FILE", path);
    writeUpdatedTime(path);
}

std::string EthernetInterface::macAddress([[maybe_unused]] std::string value)
{
    if (vlan)
    {
        lg2::error("Tried to set MAC address on VLAN");
        elog<InternalFailure>();
    }
#ifdef PERSIST_MAC
    stdplus::EtherAddr newMAC;
    try
    {
        newMAC = stdplus::fromStr<stdplus::EtherAddr>(value);
    }
    catch (const std::invalid_argument&)
    {
        lg2::error("MAC Address {NET_MAC} is not valid", "NET_MAC", value);
        elog<InvalidArgument>(Argument::ARGUMENT_NAME("MACAddress"),
                              Argument::ARGUMENT_VALUE(value.c_str()));
    }
    if (!newMAC.isUnicast())
    {
        lg2::error("MAC Address {NET_MAC} is not valid", "NET_MAC", value);
        elog<InvalidArgument>(Argument::ARGUMENT_NAME("MACAddress"),
                              Argument::ARGUMENT_VALUE(value.c_str()));
    }

    auto interface = interfaceName();
    auto validMAC = stdplus::toStr(newMAC);

    // We don't need to update the system if the address is unchanged
    auto oldMAC =
        stdplus::fromStr<stdplus::EtherAddr>(MacAddressIntf::macAddress());
    if (newMAC != oldMAC)
    {
        // Update everything that depends on the MAC value
        for (const auto& [_, intf] : manager.get().interfaces)
        {
            if (intf->vlan && intf->vlan->parentIdx == ifIdx)
            {
                intf->MacAddressIntf::macAddress(validMAC);
            }
        }
        MacAddressIntf::macAddress(validMAC);

        writeConfigurationFile();
        manager.get().addReloadPreHook([interface, manager]() {
            // The MAC and LLADDRs will only update if the NIC is already down
            system::setNICUp(interface, false);
            writeUpdatedTime(config::pathForIntfConf(manager.get().getConfDir(),
                                            interface));
        });
        manager.get().reloadConfigs();
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
    manager.get().reloadConfigs();
}

template <typename Addr>
static void normalizeGateway(std::string& gw)
{
    if (gw.empty())
    {
        return;
    }
    try
    {
        auto ip = stdplus::fromStr<Addr>(gw);
        if (ip == Addr{})
        {
            gw.clear();
            return;
        }
        if (!validIntfIP(ip))
        {
            throw std::invalid_argument("Invalid unicast");
        }
        gw = stdplus::toStr(ip);
    }
    catch (const std::exception& e)
    {
        lg2::error("Invalid GW `{NET_GW}`: {ERROR}", "NET_GW", gw, "ERROR", e);
        elog<InvalidArgument>(Argument::ARGUMENT_NAME("GATEWAY"),
                              Argument::ARGUMENT_VALUE(gw.c_str()));
    }
}

std::string EthernetInterface::defaultGateway(std::string gateway)
{
    normalizeGateway<stdplus::In4Addr>(gateway);
    if (gateway != defaultGateway())
    {
        gateway = EthernetInterfaceIntf::defaultGateway(std::move(gateway));
        writeConfigurationFile();
        manager.get().reloadConfigs();
    }
    return gateway;
}

std::string EthernetInterface::defaultGateway6(std::string gateway)
{
    normalizeGateway<stdplus::In6Addr>(gateway);
    if (gateway != defaultGateway6())
    {
        gateway = EthernetInterfaceIntf::defaultGateway6(std::move(gateway));
        writeConfigurationFile();
        manager.get().reloadConfigs();
    }
    return gateway;
}

EthernetInterface::VlanProperties::VlanProperties(
    sdbusplus::bus_t& bus, stdplus::const_zstring objPath,
    const InterfaceInfo& info, stdplus::PinnedRef<EthernetInterface> eth) :
    VlanIfaces(bus, objPath.c_str(), VlanIfaces::action::defer_emit),
    parentIdx(*info.parent_idx), eth(eth)
{
    VlanIntf::id(*info.vlan_id, true);
    emit_object_added();
}

void EthernetInterface::VlanProperties::delete_()
{
    auto intf = eth.get().interfaceName();

    // Remove all configs for the current interface
    const auto& confDir = eth.get().manager.get().getConfDir();
    std::error_code ec;
    std::filesystem::remove(config::pathForIntfConf(confDir, intf), ec);
    std::filesystem::remove(config::pathForIntfDev(confDir, intf), ec);

    if (eth.get().ifIdx > 0)
    {
        eth.get().manager.get().interfacesByIdx.erase(eth.get().ifIdx);
    }
    auto it = eth.get().manager.get().interfaces.find(intf);
    auto obj = std::move(it->second);
    eth.get().manager.get().interfaces.erase(it);

    // Write an updated parent interface since it has a VLAN entry
    for (const auto& [_, intf] : eth.get().manager.get().interfaces)
    {
        if (intf->ifIdx == parentIdx)
        {
            intf->writeConfigurationFile();
        }
    }

    if (eth.get().ifIdx > 0)
    {
        // We need to forcibly delete the interface as systemd does not
        eth.get().manager.get().addReloadPostHook(
            [idx = eth.get().ifIdx]() { system::deleteIntf(idx); });

        // Ignore the interface so the reload doesn't re-query it
        eth.get().manager.get().ignoredIntf.emplace(eth.get().ifIdx);
    }

    eth.get().manager.get().reloadConfigs();
}

void EthernetInterface::reloadConfigs()
{
    manager.get().reloadConfigs();
}

} // namespace network
} // namespace phosphor
