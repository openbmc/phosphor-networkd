#pragma once
#include "ipaddress.hpp"
#include "neighbor.hpp"
#include "types.hpp"
#include "xyz/openbmc_project/Network/IP/Create/server.hpp"
#include "xyz/openbmc_project/Network/Neighbor/CreateStatic/server.hpp"

#include <sdbusplus/bus.hpp>
#include <sdbusplus/server/object.hpp>
#include <stdplus/zstring.hpp>
#include <stdplus/zstring_view.hpp>
#include <string>
#include <vector>
#include <xyz/openbmc_project/Collection/DeleteAll/server.hpp>
#include <xyz/openbmc_project/Network/EthernetInterface/server.hpp>
#include <xyz/openbmc_project/Network/MACAddress/server.hpp>

namespace phosphor
{
namespace network
{

using Ifaces = sdbusplus::server::object_t<
    sdbusplus::xyz::openbmc_project::Network::server::EthernetInterface,
    sdbusplus::xyz::openbmc_project::Network::server::MACAddress,
    sdbusplus::xyz::openbmc_project::Network::IP::server::Create,
    sdbusplus::xyz::openbmc_project::Network::Neighbor::server::CreateStatic,
    sdbusplus::xyz::openbmc_project::Collection::server::DeleteAll>;

using IP = sdbusplus::xyz::openbmc_project::Network::server::IP;

using EthernetInterfaceIntf =
    sdbusplus::xyz::openbmc_project::Network::server::EthernetInterface;
using MacAddressIntf =
    sdbusplus::xyz::openbmc_project::Network::server::MACAddress;

using ServerList = std::vector<std::string>;
using ObjectPath = sdbusplus::message::object_path;

class Manager;

class TestEthernetInterface;

class VlanInterface;

namespace config
{
class Parser;
}

using LinkSpeed = uint16_t;
using DuplexMode = uint8_t;
using Autoneg = uint8_t;
using LinkUp = bool;
using NICEnabled = bool;
using MTU = size_t;
using VlanId = uint32_t;
using InterfaceName = std::string;
using InterfaceInfo =
    std::tuple<LinkSpeed, DuplexMode, Autoneg, LinkUp, NICEnabled, MTU>;

/** @class EthernetInterface
 *  @brief OpenBMC Ethernet Interface implementation.
 *  @details A concrete implementation for the
 *  xyz.openbmc_project.Network.EthernetInterface DBus API.
 */
class EthernetInterface : public Ifaces
{
  public:
    EthernetInterface() = delete;
    EthernetInterface(const EthernetInterface&) = delete;
    EthernetInterface& operator=(const EthernetInterface&) = delete;
    EthernetInterface(EthernetInterface&&) = delete;
    EthernetInterface& operator=(EthernetInterface&&) = delete;
    virtual ~EthernetInterface() = default;

    /** @brief Constructor to put object onto bus at a dbus path.
     *  @param[in] bus - Bus to attach to.
     *  @param[in] objPath - Path to attach at.
     *  @param[in] config - The parsed configuation file.
     *  @param[in] parent - parent object.
     *  @param[in] emitSignal - true if the object added signal needs to be
     *                          send.
     *  @param[in] enabled - Override the lookup of nicEnabled
     */
    EthernetInterface(sdbusplus::bus_t& bus, stdplus::zstring_view objPath,
                      const config::Parser& config, Manager& parent,
                      bool emitSignal = true,
                      std::optional<bool> enabled = std::nullopt);

    /** @brief Function used to load the nameservers.
     */
    void loadNameServers(const config::Parser& config);

    /** @brief Function to create ipAddress dbus object.
     *  @param[in] addressType - Type of ip address.
     *  @param[in] ipAddress- IP address.
     *  @param[in] prefixLength - Length of prefix.
     */

    ObjectPath ip(IP::Protocol addressType, std::string ipAddress,
                  uint8_t prefixLength, std::string) override;

    /** @brief Function to create static neighbor dbus object.
     *  @param[in] ipAddress - IP address.
     *  @param[in] macAddress - Low level MAC address.
     */
    ObjectPath neighbor(std::string ipAddress, std::string macAddress) override;

    /* @brief delete the dbus object of the given ipAddress.
     * @param[in] ipAddress - IP address.
     */
    void deleteObject(std::string_view ipAddress);

    /* @brief delete the dbus object of the given ipAddress.
     * @param[in] ipAddress - IP address.
     */
    void deleteStaticNeighborObject(std::string_view ipAddress);

    /* @brief delete the vlan dbus object of the given interface.
     *        Also deletes the device file and the network file.
     * @param[in] interface - VLAN Interface.
     */
    void deleteVLANObject(stdplus::zstring_view interface);

    /* @brief creates the dbus object(IPaddres) given in the address list.
     * @param[in] addrs - address list for which dbus objects needs
     *                    to create.
     */
    void createIPAddressObjects();

    /* @brief creates the dbus object(Neighbor) given in the neighbor list.
     */
    void createStaticNeighborObjects();

    /* @brief Gets the index of the interface on the system
     */
    unsigned ifIndex() const;

    /* @brief Gets all the ip addresses.
     * @returns the list of ipAddress.
     */
    inline const auto& getAddresses() const
    {
        return addrs;
    }

    /* @brief Gets all the static neighbor entries.
     * @returns Static neighbor map.
     */
    inline const auto& getStaticNeighbors() const
    {
        return staticNeighbors;
    }

    /** Set value of DHCPEnabled */
    DHCPConf dhcpEnabled() const override;
    DHCPConf dhcpEnabled(DHCPConf value) override;
    using EthernetInterfaceIntf::dhcp4;
    bool dhcp4(bool value) override;
    using EthernetInterfaceIntf::dhcp6;
    bool dhcp6(bool value) override;

    /** Retrieve Link State */
    bool linkUp() const override;

    /** Retrieve MTU Size */
    size_t mtu() const override;

    /** Set size of MTU */
    size_t mtu(size_t value) override;

    /** Set value of NICEnabled */
    bool nicEnabled(bool value) override;

    /** @brief sets the MAC address.
     *  @param[in] value - MAC address which needs to be set on the system.
     *  @returns macAddress of the interface or throws an error.
     */
    std::string macAddress(std::string value) override;

    /** @brief check conf file for Router Advertisements
     *
     */
    bool ipv6AcceptRA(bool value) override;
    using EthernetInterfaceIntf::ipv6AcceptRA;

    /** @brief sets the NTP servers.
     *  @param[in] value - vector of NTP servers.
     */
    ServerList ntpServers(ServerList value) override;

    /** @brief sets the Static DNS/nameservers.
     *  @param[in] value - vector of DNS servers.
     */

    ServerList staticNameServers(ServerList value) override;

    /** @brief create Vlan interface.
     *  @param[in] id- VLAN identifier.
     */
    ObjectPath createVLAN(VlanId id);

    /** @brief load the vlan info from the system
     *         and creates the ip address dbus objects.
     *  @param[in] vlanID- VLAN identifier.
     */
    void loadVLAN(VlanId vlanID);

    /** @brief write the network conf file with the in-memory objects.
     */
    void writeConfigurationFile();

    /** @brief delete all dbus objects.
     */
    void deleteAll();

    /** @brief set the default v4 gateway of the interface.
     *  @param[in] gateway - default v4 gateway of the interface.
     */
    std::string defaultGateway(std::string gateway) override;

    /** @brief set the default v6 gateway of the interface.
     *  @param[in] gateway - default v6 gateway of the interface.
     */
    std::string defaultGateway6(std::string gateway) override;

    using EthernetInterfaceIntf::interfaceName;
    using EthernetInterfaceIntf::linkUp;
    using EthernetInterfaceIntf::mtu;
    using EthernetInterfaceIntf::nicEnabled;
    using MacAddressIntf::macAddress;

    using EthernetInterfaceIntf::defaultGateway;
    using EthernetInterfaceIntf::defaultGateway6;
    /** @brief Absolute path of the resolv conf file */
    static constexpr auto resolvConfFile = "/etc/resolv.conf";

  protected:
    /** @brief get the info of the ethernet interface.
     *  @return tuple having the link speed,autonegotiation,duplexmode .
     */
    InterfaceInfo getInterfaceInfo() const;

    /* @brief delete the vlan interface from system.
     * @param[in] interface - vlan Interface.
     */
    void deleteVLANFromSystem(stdplus::zstring_view interface);

    /** @brief get the mac address of the interface.
     *  @param[in] interfaceName - Network interface name.
     *  @return macaddress on success
     */

    std::string getMACAddress(stdplus::const_zstring interfaceName) const;

    /** @brief construct the ip address dbus object path.
     *  @param[in] addressType - Type of ip address.
     *  @param[in] ipAddress - IP address.
     *  @param[in] prefixLength - Length of prefix.
     *  @param[in] origin - The origin entry of the IP::Address

     *  @return path of the address object.
     */
    std::string generateObjectPath(IP::Protocol addressType,
                                   std::string_view ipAddress,
                                   uint8_t prefixLength,
                                   IP::AddressOrigin origin) const;

    std::string
        generateStaticNeighborObjectPath(std::string_view ipAddress,
                                         std::string_view macAddress) const;

    /** @brief get the NTP server list from the network conf
     *
     */
    ServerList getNTPServersFromConf();

    /** @brief get the name server details from the network conf
     *
     */
    virtual ServerList getNameServerFromResolvd();

    /** @brief Persistent sdbusplus DBus bus connection. */
    sdbusplus::bus_t& bus;

    /** @brief Network Manager object. */
    Manager& manager;

    /** @brief Persistent map of IPAddress dbus objects and their names */
    string_umap<std::unique_ptr<IPAddress>> addrs;

    /** @brief Persistent map of Neighbor dbus objects and their names */
    string_umap<std::unique_ptr<Neighbor>> staticNeighbors;

    /** @brief Persistent map of VLAN interface dbus objects and their names */
    string_umap<std::unique_ptr<VlanInterface>> vlanInterfaces;

    /** @brief Dbus object path */
    std::string objPath;

    friend class TestEthernetInterface;

  private:
    /** @brief Determines if DHCP is active for the IP::Protocol supplied.
     *  @param[in] protocol - Either IPv4 or IPv6
     *  @returns true/false value if DHCP is active for the input protocol
     */
    bool dhcpIsEnabled(IP::Protocol protocol);

    /** @brief Determines if the address is manually assigned
     *  @param[in] origin - The origin entry of the IP::Address
     *  @returns true/false value if the address is static
     */
    bool originIsManuallyAssigned(IP::AddressOrigin origin);

    /** @brief Determines if the NIC is enabled in systemd
     *  @returns true/false value if the NIC is enabled
     */
    bool queryNicEnabled() const;

    std::string vlanIntfName(VlanId id) const;
    std::string vlanObjPath(VlanId id) const;
};

} // namespace network
} // namespace phosphor
