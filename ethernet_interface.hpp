#pragma once

#include "xyz/openbmc_project/Network/EthernetInterface/server.hpp"

#include <sdbusplus/bus.hpp>
#include <sdbusplus/server/object.hpp>

#include <iostream>
#include <string>

namespace phosphor
{
namespace network
{
namespace details
{

template <typename T>
using ServerObject = typename sdbusplus::server::object::object<T>;

using EthernetIface =
    sdbusplus::server::object::object<
    sdbusplus::xyz::openbmc_project::Network::server::EthernetInterface>;

} // namespace details

using LinkSpeed = uint16_t;
using DuplexMode = uint8_t;
using Autoneg = uint8_t;
using InterfaceInfo = std::tuple<LinkSpeed,DuplexMode,Autoneg>;


/** @class EthernetInterface
 *  @brief OpenBMC Ethernet Interface implementation.
 *  @details A concrete implementation for the
 *  xyz.openbmc_project.Network.EthernetInterface DBus API.
 */
class EthernetInterface : public details::EthernetIface
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
         *  @param[in] objPath - Path to attach at.
         *  @param[in] intfName - name of the ethernet interface.
         *  @param[in] dhcpEnabled - dhcp value.
         */
        EthernetInterface(sdbusplus::bus::bus& bus,
                          const char* objPath,
                          std::string intfName,
                          bool dhcpEnabled);



    private:

        /** @brief get the info of the ethernet interface.
         *  @return tuple having the link speed,autonegotiation,duplexmode .
         */

        InterfaceInfo getInterfaceInfo() const;

        /** @brief get the mac address of the interface.
         *  @return macaddress on success
         */

        std::string getMACAddress() const;

};

} // namespace network
} // namespace phosphor
