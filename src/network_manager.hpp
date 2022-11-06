#pragma once
#include "dhcp_configuration.hpp"
#include "ethernet_interface.hpp"
#include "routing_table.hpp"
#include "system_configuration.hpp"
#include "types.hpp"
#include "vlan_interface.hpp"
#include "xyz/openbmc_project/Network/VLAN/Create/server.hpp"

#include <filesystem>
#include <function2/function2.hpp>
#include <memory>
#include <sdbusplus/bus.hpp>
#include <string>
#include <string_view>
#include <vector>
#include <xyz/openbmc_project/Common/FactoryReset/server.hpp>

namespace phosphor
{
namespace network
{

using SystemConfPtr = std::unique_ptr<SystemConfiguration>;
using DHCPConfPtr = std::unique_ptr<dhcp::Configuration>;

namespace fs = std::filesystem;
namespace details
{

template <typename T, typename U>
using ServerObject = typename sdbusplus::server::object_t<T, U>;

using VLANCreateIface = details::ServerObject<
    sdbusplus::xyz::openbmc_project::Network::VLAN::server::Create,
    sdbusplus::xyz::openbmc_project::Common::server::FactoryReset>;

} // namespace details

/** @class Manager
 *  @brief OpenBMC network manager implementation.
 */
class Manager : public details::VLANCreateIface
{
  public:
    Manager() = delete;
    Manager(const Manager&) = delete;
    Manager& operator=(const Manager&) = delete;
    Manager(Manager&&) = delete;
    Manager& operator=(Manager&&) = delete;
    virtual ~Manager() = default;

    /** @brief Constructor to put object onto bus at a dbus path.
     *  @param[in] bus - Bus to attach to.
     *  @param[in] objPath - Path to attach at.
     *  @param[in] confDir - Network Configuration directory path.
     */
    Manager(sdbusplus::bus_t& bus, const char* objPath,
            const fs::path& confDir);

    ObjectPath vlan(std::string interfaceName, uint32_t id) override;

    /** @brief write the network conf file with the in-memory objects.
     */
    void writeToConfigurationFile();

    /** @brief Fetch the interface and the ipaddress details
     *         from the system and create the ethernet interraces
     *         dbus object.
     */
    virtual void createInterfaces();

    /** @brief create child interface object and the system conf object.
     */
    void createChildObjects();

    /** @brief sets the network conf directory.
     *  @param[in] dirName - Absolute path of the directory.
     */
    void setConfDir(const fs::path& dir);

    /** @brief gets the network conf directory.
     */
    inline const fs::path& getConfDir() const
    {
        return confDir;
    }

    /** @brief gets the system conf object.
     *
     */
    inline const SystemConfPtr& getSystemConf()
    {
        return systemConf;
    }

    /** @brief gets the dhcp conf object.
     *
     */
    inline const DHCPConfPtr& getDHCPConf()
    {
        return dhcpConf;
    }

    /** @brief This function gets the MAC address from the VPD and
     *  sets it on the corresponding ethernet interface during first
     *  Boot, once it sets the MAC from VPD, it creates a file named
     *  firstBoot under /var/lib to make sure we dont run this function
     *  again.
     *
     *  @param[in] ethPair - Its a pair of ethernet interface name & the
     * corresponding MAC Address from the VPD
     *
     *  return - NULL
     */
    void setFistBootMACOnInterface(
        const std::pair<std::string, std::string>& ethPair);

    /** @brief Arms a timer to tell systemd-network to reload all of the network
     * configurations
     */
    virtual void reloadConfigs();

    /** @brief Tell systemd-network to reload all of the network configurations
     */
    void doReloadConfigs();

    /** @brief Get the interfaces owned by the manager
     *
     * @return Interfaces reference.
     */
    inline const auto& getInterfaces() const
    {
        return interfaces;
    }

    /** @brief Get the routing table owned by the manager
     *
     * @return Routing table reference.
     */
    inline const auto& getRouteTable() const
    {
        return routeTable;
    }

    /** @brief Adds a hook that runs immediately prior to reloading
     *
     *  @param[in] hook - The hook to execute before reloading
     */
    inline void addReloadPreHook(fu2::unique_function<void()>&& hook)
    {
        reloadPreHooks.push_back(std::move(hook));
    }

  protected:
    /** @brief Persistent sdbusplus DBus bus connection. */
    sdbusplus::bus_t& bus;

    /** @brief Persistent map of EthernetInterface dbus objects and their names
     */
    string_umap<std::unique_ptr<EthernetInterface>> interfaces;

    /** @brief BMC network reset - resets network configuration for BMC. */
    void reset() override;

    /** @brief Path of Object. */
    std::string objectPath;

    /** @brief pointer to system conf object. */
    SystemConfPtr systemConf = nullptr;

    /** @brief pointer to dhcp conf object. */
    DHCPConfPtr dhcpConf = nullptr;

    /** @brief Network Configuration directory. */
    fs::path confDir;

    /** @brief The routing table */
    route::Table routeTable;

    /** @brief List of hooks to execute during the next reload */
    std::vector<fu2::unique_function<void()>> reloadPreHooks;
};

} // namespace network
} // namespace phosphor
