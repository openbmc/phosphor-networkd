#pragma once
#include "ipaddress.hpp"
#include "neighbor.hpp"
#include "types.hpp"
#include "xyz/openbmc_project/Network/IP/Create/server.hpp"
#include "xyz/openbmc_project/Network/Neighbor/CreateStatic/server.hpp"

#include <optional>
#include <sdbusplus/bus.hpp>
#include <sdbusplus/server/object.hpp>
#include <stdplus/zstring_view.hpp>
#include <string>
#include <vector>
#include <xyz/openbmc_project/Collection/DeleteAll/server.hpp>
#include <xyz/openbmc_project/Network/EthernetInterface/server.hpp>
#include <xyz/openbmc_project/Network/MACAddress/server.hpp>
#include <xyz/openbmc_project/Network/VLAN/server.hpp>
#include <xyz/openbmc_project/Object/Delete/server.hpp>

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

using VlanIfaces = sdbusplus::server::object_t<
    sdbusplus::xyz::openbmc_project::Object::server::Delete,
    sdbusplus::xyz::openbmc_project::Network::server::VLAN>;

using VlanIntf = sdbusplus::xyz::openbmc_project::Network::server::VLAN;

using IP = sdbusplus::xyz::openbmc_project::Network::server::IP;

using EthernetInterfaceIntf =
    sdbusplus::xyz::openbmc_project::Network::server::EthernetInterface;
using MacAddressIntf =
    sdbusplus::xyz::openbmc_project::Network::server::MACAddress;

using ServerList = std::vector<std::string>;
using ObjectPath = sdbusplus::message::object_path;

class Manager;

class TestEthernetInterface;
class TestNetworkManager;

namespace config
{
class Parser;
}
namespace system
{
struct InterfaceInfo;
};

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
     *  @param[in] manager - parent object.
     *  @param[in] info - Interface information.
     *  @param[in] objRoot - Path to attach at.
     *  @param[in] config - The parsed configuation file.
     *  @param[in] vlan - The id of the vlan if configured
     *  @param[in] emitSignal - true if the object added signal needs to be
     *                          send.
     *  @param[in] enabled - Override the lookup of nicEnabled
     */
    EthernetInterface(sdbusplus::bus_t& bus, Manager& manager,
                      const system::InterfaceInfo& info,
                      std::string_view objRoot, const config::Parser& config,
                      bool emitSignal = true,
                      std::optional<bool> enabled = std::nullopt);

    /** @brief Network Manager object. */
    Manager& manager;

    /** @brief Persistent map of IPAddress dbus objects and their names */
    std::unordered_map<IfAddr, std::unique_ptr<IPAddress>> addrs;

    /** @brief Persistent map of Neighbor dbus objects and their names */
    std::unordered_map<InAddrAny, std::unique_ptr<Neighbor>> staticNeighbors;

    /** @brief Updates the interface information based on new InterfaceInfo */
    void updateInfo(const system::InterfaceInfo& info);

    /** @brief Function used to load the ntpservers
     */
    void loadNTPServers(const config::Parser& config);

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

    /* @brief creates the dbus object(IPaddres) given in the address list.
     * @param[in] addrs - address list for which dbus objects needs
     *                    to create.
     */
    void createIPAddressObjects();

    /* @brief creates the dbus object(Neighbor) given in the neighbor list.
     */
    void createStaticNeighborObjects();

    /** Set value of DHCPEnabled */
    DHCPConf dhcpEnabled() const override;
    DHCPConf dhcpEnabled(DHCPConf value) override;
    using EthernetInterfaceIntf::dhcp4;
    bool dhcp4(bool value) override;
    using EthernetInterfaceIntf::dhcp6;
    bool dhcp6(bool value) override;

    inline bool dhcpIsEnabled(in_addr) const
    {
        return dhcp4();
    }
    inline bool dhcpIsEnabled(in6_addr) const
    {
        return dhcp6();
    }
    inline bool dhcpIsEnabled(InAddrAny addr) const
    {
        return std::visit([&](auto v) { return dhcpIsEnabled(v); }, addr);
    }

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

    /** @brief sets the static NTP servers.
     *  @param[in] value - vector of NTP servers.
     */
    ServerList staticNTPServers(ServerList value) override;

    /** @brief sets the Static DNS/nameservers.
     *  @param[in] value - vector of DNS servers.
     */

    ServerList staticNameServers(ServerList value) override;

    /** @brief create Vlan interface.
     *  @param[in] id- VLAN identifier.
     */
    ObjectPath createVLAN(uint16_t id);

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

  protected:
    /** @brief get the NTP server list from the timsyncd dbus obj
     *
     */
    virtual ServerList getNTPServerFromTimeSyncd();

    /** @brief get the name server details from the network conf
     *
     */
    virtual ServerList getNameServerFromResolvd();

    /** @brief Persistent sdbusplus DBus bus connection. */
    sdbusplus::bus_t& bus;

    /** @brief Dbus object path */
    std::string objPath;

    /** @brief Interface index */
    unsigned ifIdx;

    struct VlanProperties : VlanIfaces
    {
        VlanProperties(sdbusplus::bus_t& bus, stdplus::const_zstring objPath,
                       const system::InterfaceInfo& info,
                       EthernetInterface& eth, bool emitSignal = true);
        void delete_() override;
        unsigned parentIdx;
        EthernetInterface& eth;
    };
    std::optional<VlanProperties> vlan;

    friend class TestEthernetInterface;
    friend class TestNetworkManager;

  private:
    EthernetInterface(sdbusplus::bus_t& bus, Manager& manager,
                      const system::InterfaceInfo& info, std::string&& objPath,
                      const config::Parser& config, bool emitSignal,
                      std::optional<bool> enabled);

    /** @brief Determines if the address is manually assigned
     *  @param[in] origin - The origin entry of the IP::Address
     *  @returns true/false value if the address is static
     */
    bool originIsManuallyAssigned(IP::AddressOrigin origin);

    /** @brief Determines if the NIC is enabled in systemd
     *  @returns true/false value if the NIC is enabled
     */
    bool queryNicEnabled() const;
};

} // namespace network
} // namespace phosphor
