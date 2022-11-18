#pragma once
#include "dhcp_configuration.hpp"
#include "ethernet_interface.hpp"
#include "system_configuration.hpp"
#include "types.hpp"
#include "xyz/openbmc_project/Network/VLAN/Create/server.hpp"

#include <filesystem>
#include <function2/function2.hpp>
#include <memory>
#include <sdbusplus/bus.hpp>
#include <sdbusplus/bus/match.hpp>
#include <sdbusplus/message/native_types.hpp>
#include <string>
#include <string_view>
#include <vector>
#include <xyz/openbmc_project/Common/FactoryReset/server.hpp>

namespace phosphor
{
namespace network
{

using ManagerIface = sdbusplus::server::object_t<
    sdbusplus::xyz::openbmc_project::Network::VLAN::server::Create,
    sdbusplus::xyz::openbmc_project::Common::server::FactoryReset>;

/** @class Manager
 *  @brief OpenBMC network manager implementation.
 */
class Manager : public ManagerIface
{
  public:
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
            const std::filesystem::path& confDir);

    ObjectPath vlan(std::string interfaceName, uint32_t id) override;

    /** @brief write the network conf file with the in-memory objects.
     */
    void writeToConfigurationFile();

    /** @brief Adds a single interface to the interface map */
    void addInterface(const InterfaceInfo& info);
    void removeInterface(const InterfaceInfo& info);

    /** @brief Add / remove an address to the interface or queue */
    void addAddress(const AddressInfo& info);
    void removeAddress(const AddressInfo& info);

    /** @brief Add / remove a neighbor to the interface or queue */
    void addNeighbor(const NeighborInfo& info);
    void removeNeighbor(const NeighborInfo& info);

    /** @brief Add / remove default gateway for interface */
    void addDefGw(unsigned ifidx, InAddrAny addr);
    void removeDefGw(unsigned ifidx, InAddrAny addr);

    /** @brief gets the network conf directory.
     */
    inline const auto& getConfDir() const
    {
        return confDir;
    }

    /** @brief gets the system conf object.
     *
     */
    inline auto& getSystemConf()
    {
        return *systemConf;
    }

    /** @brief gets the dhcp conf object.
     *
     */
    inline auto& getDHCPConf()
    {
        return *dhcpConf;
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

    /** @brief Persistent map of EthernetInterface dbus objects and their names
     */
    string_umap<std::unique_ptr<EthernetInterface>> interfaces;
    std::unordered_map<unsigned, EthernetInterface*> interfacesByIdx;

    /** @brief Adds a hook that runs immediately prior to reloading
     *
     *  @param[in] hook - The hook to execute before reloading
     */
    inline void addReloadPreHook(fu2::unique_function<void()>&& hook)
    {
        reloadPreHooks.push_back(std::move(hook));
    }
    inline void addReloadPostHook(fu2::unique_function<void()>&& hook)
    {
        reloadPostHooks.push_back(std::move(hook));
    }

  protected:
    /** @brief Persistent sdbusplus DBus bus connection. */
    sdbusplus::bus_t& bus;

    /** @brief BMC network reset - resets network configuration for BMC. */
    void reset() override;

    /** @brief Path of Object. */
    sdbusplus::message::object_path objPath;

    /** @brief pointer to system conf object. */
    std::unique_ptr<SystemConfiguration> systemConf = nullptr;

    /** @brief pointer to dhcp conf object. */
    std::unique_ptr<dhcp::Configuration> dhcpConf = nullptr;

    /** @brief Network Configuration directory. */
    std::filesystem::path confDir;

    /** @brief Map of interface info for undiscovered interfaces */
    std::unordered_map<unsigned, AllIntfInfo> intfInfo;
    std::unordered_set<unsigned> ignoredIntf;

    /** @brief Map of enabled interfaces */
    std::unordered_map<unsigned, bool> systemdNetworkdEnabled;
    sdbusplus::bus::match_t systemdNetworkdEnabledMatch;

    /** @brief List of hooks to execute during the next reload */
    std::vector<fu2::unique_function<void()>> reloadPreHooks;
    std::vector<fu2::unique_function<void()>> reloadPostHooks;

    /** @brief Handles the recipt of an adminstrative state string */
    void handleAdminState(std::string_view state, unsigned ifidx);

    /** @brief Creates the interface in the maps */
    void createInterface(const AllIntfInfo& info, bool enabled);
};

} // namespace network
} // namespace phosphor
