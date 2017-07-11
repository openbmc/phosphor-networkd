#pragma once

#include <xyz/openbmc_project/Network/DHCP/server.hpp>
#include <sdbusplus/bus.hpp>
#include <sdbusplus/server/object.hpp>

#include <string>

namespace phosphor
{
namespace network
{

class Manager; // forward declaration of network manager.

namespace dhcp
{

using ConfigIntf =
    sdbusplus::xyz::openbmc_project::Network::server::DHCP;

using Iface =
    sdbusplus::server::object::object<ConfigIntf>;


/** @class Configuration
 *  @brief DHCP configuration.
 *  @details A concrete implementation for the
 *  xyz.openbmc_project.Network.DHCP DBus interface.
 */
class Configuration : public Iface
{
    public:
        Configuration() = default;
        Configuration(const Configuration&) = delete;
        Configuration& operator=(const Configuration&) = delete;
        Configuration(Configuration&&) = delete;
        Configuration& operator=(Configuration&&) = delete;
        virtual ~Configuration() = default;

        /** @brief Constructor to put object onto bus at a dbus path.
         *  @param[in] bus - Bus to attach to.
         *  @param[in] objPath - Path to attach at.
         *  @param[in] parent - Parent object.
         */
        Configuration(sdbusplus::bus::bus& bus,
                            const std::string& objPath,
                            Manager& parent);

        /** @brief 
         *  @param[in] value - true if we need dns info from DHCP server.
         *                     else false.
         */
        bool dNS(bool value) override;

        /** @brief 
         *  @param[in] value - true if we need dns info from DHCP server.
         *                     else false.
         */
        bool nTP(bool value) override;

        /** @brief 
         *  @param[in] value - true if we need dns info from DHCP server.
         *                     else false.
         */
        bool hostName(bool value) override;

        using ConfigIntf::dNS;
        using ConfigIntf::nTP;
        using ConfigIntf::hostName;

    private:

        /** @brief Persistent sdbusplus DBus bus connection. */
        sdbusplus::bus::bus& bus;

        /** @brief Network Manager object. */
        phosphor::network::Manager& manager;

};

} // namespace dhcp
} // namespace network
} // namespace phosphor
