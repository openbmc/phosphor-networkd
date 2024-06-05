#pragma once
#include "dhcp_configuration.hpp"
#include "ethernet_interface.hpp"
#include "system_configuration.hpp"
#include "types.hpp"
#include "xyz/openbmc_project/Network/VLAN/Create/server.hpp"

#include <function2/function2.hpp>
#include <sdbusplus/bus.hpp>
#include <sdbusplus/bus/match.hpp>
#include <sdbusplus/message/native_types.hpp>
#include <stdplus/pinned.hpp>
#include <stdplus/str/maps.hpp>
#include <stdplus/zstring_view.hpp>
#include <xyz/openbmc_project/Common/FactoryReset/server.hpp>

#include <filesystem>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

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
    Manager(Manager&&) = delete;
    Manager& operator=(Manager&&) = delete;

    /** @brief Constructor to put object onto bus at a dbus path.
     *  @param[in] bus - Bus to attach to.
     *  @param[in] reload - The executor for reloading configs
     *  @param[in] objPath - Path to attach at.
     *  @param[in] confDir - Network Configuration directory path.
     */
    Manager(stdplus::PinnedRef<sdbusplus::bus_t> bus,
            stdplus::PinnedRef<DelayedExecutor> reload,
            stdplus::zstring_view objPath,
            const std::filesystem::path& confDir);

    ObjectPath vlan(std::string interfaceName, uint32_t id) override;

    /** @brief write the network conf file with the in-memory objects.
     */
    void writeToConfigurationFile();

    /** @brief write the lldp conf file
     */
    void writeLLDPDConfigurationFile();

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
    void addDefGw(unsigned ifidx, stdplus::InAnyAddr addr);
    void removeDefGw(unsigned ifidx, stdplus::InAnyAddr addr);

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

    /** @brief Arms a timer to tell systemd-network to reload all of the network
     * configurations
     */
    inline void reloadConfigs()
    {
        reload.get().schedule();
    }

    /** Reload LLDP configuration
     */
    void reloadLLDPService();

    /** @brief Persistent map of EthernetInterface dbus objects and their names
     */
    stdplus::string_umap<std::unique_ptr<EthernetInterface>> interfaces;
    std::unordered_map<unsigned, EthernetInterface*> interfacesByIdx;
    std::unordered_set<unsigned> ignoredIntf;

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
    /** @brief Handle to the object used to trigger reloads of networkd. */
    stdplus::PinnedRef<DelayedExecutor> reload;

    /** @brief Persistent sdbusplus DBus bus connection. */
    stdplus::PinnedRef<sdbusplus::bus_t> bus;

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

    /** @brief Map of enabled interfaces */
    std::unordered_map<unsigned, bool> systemdNetworkdEnabled;
    sdbusplus::bus::match_t systemdNetworkdEnabledMatch;

    /** @brief List of hooks to execute during the next reload */
    std::vector<fu2::unique_function<void()>> reloadPreHooks;
    std::vector<fu2::unique_function<void()>> reloadPostHooks;

    /** @brief Handles the receipt of an administrative state string */
    void handleAdminState(std::string_view state, unsigned ifidx);

    /** @brief Creates the interface in the maps */
    void createInterface(const AllIntfInfo& info, bool enabled);

  private:
    /** @brief Function used to watch change in NTP server.
     */
    void watchNTPServers(EthernetInterface* intf);

    /** @brief Function to watch status of systemd timesyncd.
     */
    void watchTimeSyncActiveState(EthernetInterface* intf);

    std::unique_ptr<sdbusplus::bus::match::match> ntpServerMatch;
    std::unique_ptr<sdbusplus::bus::match::match> activeStateMatch;
};

} // namespace network
} // namespace phosphor
