#pragma once

#include "ethernet_interface.hpp"
#include "types.hpp"
#include "xyz/openbmc_project/Network/VLAN/Create/server.hpp"
#include <xyz/openbmc_project/Common/FactoryReset/server.hpp>

#include <sdbusplus/bus.hpp>
#include <ifaddrs.h>

#include <list>
#include <memory>
#include <string>
#include <vector>

namespace phosphor
{
namespace network
{

namespace details
{

template <typename T, typename U>
using ServerObject = typename sdbusplus::server::object::object<T, U>;

using VLANCreateIface = details::ServerObject<
    sdbusplus::xyz::openbmc_project::Network::VLAN::server::Create,
    sdbusplus::xyz::openbmc_project::Common::server::FactoryReset>;

using IntfName = std::string;

struct AddrInfo
{
    short addrType;
    std::string ipaddress;
};

using Addr_t = ifaddrs*;

struct AddrDeleter
{
    void operator()(Addr_t ptr) const
    {
        freeifaddrs(ptr);
    }
};

using AddrPtr = std::unique_ptr<ifaddrs, AddrDeleter>;

using AddrList = std::list<AddrInfo>;
using IntfAddrMap = std::map<IntfName, AddrList>;

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
         */
        Manager(sdbusplus::bus::bus& bus, const char* objPath);

        void vLAN(IntfName interfaceName, uint16_t id) override;

        /** @brief write the network conf file with the in-memory objects.
         */
        void writeToConfigurationFile();

        /** @brief Fetch the interface and the ipaddress details
         *         from the system and create the ethernet interraces
         *         dbus object.
         */
        void createInterfaces();


    private:
        /** @brief Get all the interfaces from the system.
         *  @returns list of interface names.
         */
        IntfAddrMap getInterfaceAddrs() const;

        /** @brief Restart the systemd networkd
         */
        void restartSystemdNetworkd();

        /** @brief Persistent sdbusplus DBus bus connection. */
        sdbusplus::bus::bus& bus;

        /** @brief Persistent map of EthernetInterface dbus objects and their names */
        std::map<IntfName, std::unique_ptr<EthernetInterface>> interfaces;

        /** @brief BMC network reset - resets network configuration for BMC. */
        void reset() override;

        /** @brief Path of Object. */
        std::string objectPath;

};

} // namespace network
} // namespace phosphor
