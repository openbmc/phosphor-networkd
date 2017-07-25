#pragma once

#include "ethernet_interface.hpp"
#include "system_configuration.hpp"
#include "dhcp_configuration.hpp"
#include "vlan_interface.hpp"

#include <xyz/openbmc_project/Network/VLAN/Create/server.hpp>
#include <xyz/openbmc_project/Common/FactoryReset/server.hpp>
#include <sdbusplus/bus.hpp>

#include <list>
#include <memory>
#include <string>
#include <vector>
#include <experimental/filesystem>

namespace phosphor
{
namespace network
{

using SystemConfPtr = std::unique_ptr<SystemConfiguration>;
using DHCPConfPtr = std::unique_ptr<dhcp::Configuration>;

namespace fs = std::experimental::filesystem;
namespace details
{

template <typename T, typename U>
using ServerObject = typename sdbusplus::server::object::object<T, U>;

using VLANCreateIface = details::ServerObject<
    sdbusplus::xyz::openbmc_project::Network::VLAN::server::Create,
    sdbusplus::xyz::openbmc_project::Common::server::FactoryReset>;

} // namespace details

class TestNetworkManager; //forward declaration

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
         *  @param[in] dir - Network Configuration directory path.
         */
        Manager(sdbusplus::bus::bus& bus, const char* objPath,
                const std::string& dir);

        void vLAN(IntfName interfaceName, uint32_t id) override;

        /** @brief write the network conf file with the in-memory objects.
         */
        void writeToConfigurationFile();

        /** @brief Fetch the interface and the ipaddress details
         *         from the system and create the ethernet interraces
         *         dbus object.
         */
        void createInterfaces();

        /** @brief create child interface object and the system conf object.
         */
        void createChildObjects();

        /** @brief sets the network conf directory.
         *  @param[in] dirName - Absolute path of the directory.
         */
        void setConfDir(const fs::path& dir);

        /** @brief gets the network conf directory.
         */
        fs::path getConfDir() { return confDir; }

        /** @brief gets the system conf object.
         *
         */
        const SystemConfPtr& getSystemConf() { return systemConf; }

        /** @brief gets the dhcp conf object.
         *
         */
        const DHCPConfPtr& getDHCPConf() { return dhcpConf; }

    private:

        /** @brief Persistent sdbusplus DBus bus connection. */
        sdbusplus::bus::bus& bus;

        /** @brief Persistent map of EthernetInterface dbus objects and their names */
        std::map<IntfName, std::shared_ptr<EthernetInterface>> interfaces;

        /** @brief BMC network reset - resets network configuration for BMC. */
        void reset() override;

        /** @brief read the DHCP value from the configuration file
         *  @param[in] intf - Interface name.
         */
        bool getDHCPValue(const std::string& intf);

        /** @brief Path of Object. */
        std::string objectPath;

        /** @brief pointer to system conf object. */
        SystemConfPtr systemConf = nullptr;

        /** @brief pointer to dhcp conf object. */
        DHCPConfPtr dhcpConf = nullptr;

        /** @brief Network Configuration directory. */
        fs::path confDir;

        friend class TestNetworkManager;

};

} // namespace network
} // namespace phosphor
