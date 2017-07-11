#pragma once

#include "xyz/openbmc_project/Network/DHCPConfiguration/server.hpp"
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
                      Manager& parent) :
            Iface(bus, objPath.c_str()),
            bus(bus),
            manager(parent){}

        /** @brief If true then DNS servers received from the DHCP server
         *         will be used and take precedence over any statically
         *         configured ones.
         *  @param[in] value - true if DNS server needed from DHCP server
         *                     else false.
         */
        bool dNS(bool value) override;

        /** @brief If true then NTP servers received from the DHCP server
                   will be used by systemd-timesyncd.
         *  @param[in] value - true if NTP server needed from DHCP server
         *                     else false.
         */
        bool nTP(bool value) override;

        /** @brief If true then Hostname received from the DHCP server will
         *         be set as the hostname of the system
         *  @param[in] value - true if hostname needed from the DHCP server
         *                     else false.
         *
         */
        bool hostName(bool value) override;

        /* @brief Network Manager needed the below function to know the
         *        value of the properties (ntp,dns,hostname).
         *
         */
        using ConfigIntf::dNS;
        using ConfigIntf::nTP;
        using ConfigIntf::hostName;

    private:

        /** @brief sdbusplus DBus bus connection. */
        sdbusplus::bus::bus& bus;

        /** @brief Network Manager object. */
        phosphor::network::Manager& manager;

};

} // namespace dhcp
} // namespace network
} // namespace phosphor
