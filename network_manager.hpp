#pragma once

#include "ethernet_interface.hpp"
#include "xyz/openbmc_project/Network/VLANInterface/Create/server.hpp"

#include <sdbusplus/bus.hpp>

#include <list>
#include <string>
#include <vector>

namespace phosphor
{
namespace network
{

namespace details
{

template <typename T>
using ServerObject = typename sdbusplus::server::object::object<T>;

using VLANCreateIface =
    details::ServerObject<sdbusplus::xyz::openbmc_project::
    Network::VLAN::server::Create>;

using EthernetInterface =
    phosphor::network::EthernetInterface;

using IntfName = std::string;

struct AddrInfo {
    short addrType;
    std::string ipaddress;
};

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

    private:
        /** @brief Get all the interfaces from the system.
         *  @returns list of interface names.
         */
        details::IntfAddrMap getInterfaceAndaddrs() const;

        /** @brief Persistent map of EthernetInterface dbus objects and their names */
        std::map<IntfName, std::unique_ptr<details::EthernetInterface>> interfaces;

};

} // namespace network
} // namespace phosphor
