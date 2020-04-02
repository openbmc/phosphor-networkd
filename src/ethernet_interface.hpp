#pragma once
#include "ipaddress.hpp"
#include "neighbor.hpp"
#include "types.hpp"
#include "util.hpp"
#include "xyz/openbmc_project/Channel/ChannelAccess/server.hpp"
#include "xyz/openbmc_project/Network/IP/Create/server.hpp"
#include "xyz/openbmc_project/Network/Neighbor/CreateStatic/server.hpp"

#include <nlohmann/json.hpp>
#include <sdbusplus/bus.hpp>
#include <sdbusplus/bus/match.hpp>
#include <sdbusplus/server/object.hpp>
#include <stdplus/pinned.hpp>
#include <stdplus/zstring_view.hpp>
#include <xyz/openbmc_project/Collection/DeleteAll/server.hpp>
#include <xyz/openbmc_project/Network/EthernetInterface/server.hpp>
#include <xyz/openbmc_project/Network/MACAddress/server.hpp>
#include <xyz/openbmc_project/Network/VLAN/server.hpp>
#include <xyz/openbmc_project/Object/Delete/server.hpp>

#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace phosphor
{
namespace network
{

using Ifaces = sdbusplus::server::object_t<
    sdbusplus::xyz::openbmc_project::Network::server::EthernetInterface,
    sdbusplus::xyz::openbmc_project::Network::server::MACAddress,
    sdbusplus::xyz::openbmc_project::Network::IP::server::Create,
    sdbusplus::xyz::openbmc_project::Network::Neighbor::server::CreateStatic,
    sdbusplus::xyz::openbmc_project::Collection::server::DeleteAll,
    sdbusplus::xyz::openbmc_project::Channel::server::ChannelAccess>;

using VlanIfaces = sdbusplus::server::object_t<
    sdbusplus::xyz::openbmc_project::Object::server::Delete,
    sdbusplus::xyz::openbmc_project::Network::server::VLAN>;

using VlanIntf = sdbusplus::xyz::openbmc_project::Network::server::VLAN;

using IP = sdbusplus::xyz::openbmc_project::Network::server::IP;

using EthernetInterfaceIntf =
    sdbusplus::xyz::openbmc_project::Network::server::EthernetInterface;
using MacAddressIntf =
    sdbusplus::xyz::openbmc_project::Network::server::MACAddress;
using ChannelAccessIntf =
    sdbusplus::xyz::openbmc_project::Channel::server::ChannelAccess;

using ServerList = std::vector<std::string>;
using ObjectPath = sdbusplus::message::object_path;

namespace fs = std::filesystem;
using DbusVariant = std::variant<std::string, std::vector<std::string>>;

class Manager; // forward declaration of network manager.

class TestEthernetInterface;
class TestNetworkManager;

namespace config
{
class Parser;
}

/** @class EthernetInterface
 *  @brief OpenBMC Ethernet Interface implementation.
 *  @details A concrete implementation for the
 *  xyz.openbmc_project.Network.EthernetInterface DBus API.
 */
class EthernetInterface : public Ifaces
{
  public:
    EthernetInterface(EthernetInterface&&) = delete;
    EthernetInterface& operator=(EthernetInterface&&) = delete;

    /** @brief Constructor to put object onto bus at a dbus path.
     *  @param[in] bus - Bus to attach to.
     *  @param[in] manager - parent object.
     *  @param[in] info - Interface information.
     *  @param[in] objRoot - Path to attach at.
     *  @param[in] config - The parsed configuation file.
     *  @param[in] vlan - The id of the vlan if configured
     *  @param[in] enabled - Determine if systemd-networkd is managing this link
     */
    EthernetInterface(stdplus::PinnedRef<sdbusplus::bus_t> bus,
                      stdplus::PinnedRef<Manager> manager,
                      const AllIntfInfo& info, std::string_view objRoot,
                      const config::Parser& config, bool enabled);

    /** @brief Network Manager object. */
    stdplus::PinnedRef<Manager> manager;

    /** @brief Persistent map of IPAddress dbus objects and their names */
    std::unordered_map<stdplus::SubnetAny, std::unique_ptr<IPAddress>> addrs;

    /** @brief Persistent map of Neighbor dbus objects and their names */
    std::unordered_map<stdplus::InAnyAddr, std::unique_ptr<Neighbor>>
        staticNeighbors;

    void addAddr(const AddressInfo& info);
    void addStaticNeigh(const NeighborInfo& info);

    /** @brief Updates the interface information based on new InterfaceInfo */
    void updateInfo(const InterfaceInfo& info, bool skipSignal = false);

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

    /** Set value of DHCPEnabled */
    DHCPConf dhcpEnabled() const override;
    DHCPConf dhcpEnabled(DHCPConf value) override;
    using EthernetInterfaceIntf::dhcp4;
    bool dhcp4(bool value) override;
    using EthernetInterfaceIntf::dhcp6;
    bool dhcp6(bool value) override;

    inline bool dhcpIsEnabled(stdplus::In4Addr) const
    {
        return dhcp4();
    }
    inline bool dhcpIsEnabled(stdplus::In6Addr) const
    {
        return dhcp6();
    }
    inline bool dhcpIsEnabled(stdplus::InAnyAddr addr) const
    {
        return std::visit([&](auto v) { return dhcpIsEnabled(v); }, addr);
    }

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
    void deleteAll() override;

    /** @brief set the default v4 gateway of the interface.
     *  @param[in] gateway - default v4 gateway of the interface.
     */
    std::string defaultGateway(std::string gateway) override;

    /** @brief set the default v6 gateway of the interface.
     *  @param[in] gateway - default v6 gateway of the interface.
     */
    std::string defaultGateway6(std::string gateway) override;

    /** @brief sets the channel maxium privilege.
     *  @param[in] value - Channel privilege which needs to be set on the
     * system.
     *  @returns privilege of the interface or throws an error.
     */
    std::string maxPrivilege(std::string value) override;

    using ChannelAccessIntf::maxPrivilege;
    using EthernetInterfaceIntf::dhcpEnabled;
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
    stdplus::PinnedRef<sdbusplus::bus_t> bus;

    /** @brief Dbus object path */
    std::string objPath;

    /** @brief Interface index */
    unsigned ifIdx;

    struct VlanProperties : VlanIfaces
    {
        VlanProperties(sdbusplus::bus_t& bus, stdplus::const_zstring objPath,
                       const InterfaceInfo& info,
                       stdplus::PinnedRef<EthernetInterface> eth);
        void delete_() override;
        unsigned parentIdx;
        stdplus::PinnedRef<EthernetInterface> eth;
    };
    std::optional<VlanProperties> vlan;

    friend class TestEthernetInterface;
    friend class TestNetworkManager;

  private:
    EthernetInterface(stdplus::PinnedRef<sdbusplus::bus_t> bus,
                      stdplus::PinnedRef<Manager> manager,
                      const AllIntfInfo& info, std::string&& objPath,
                      const config::Parser& config, bool enabled);

    /** @brief Determines if the address is manually assigned
     *  @param[in] origin - The origin entry of the IP::Address
     *  @returns true/false value if the address is static
     */
    bool originIsManuallyAssigned(IP::AddressOrigin origin);

    /** @brief gets the channel privilege.
     *  @param[in] interfaceName - Network interface name.
     *  @returns privilege of the interface
     */
    std::string getChannelPrivilege(const std::string& interfaceName);

    /** @brief reads the channel access info from file.
     *  @param[in] configFile - channel access filename
     *  @returns json file data
     */
    nlohmann::json readJsonFile(const std::string& configFile);

    /** @brief writes the channel access info to file.
     *  @param[in] configFile - channel access filename
     *  @param[in] jsonData - json data to write
     *  @returns success or failure
     */
    int writeJsonFile(const std::string& configFile,
                      const nlohmann::json& jsonData);
};

} // namespace network
} // namespace phosphor
