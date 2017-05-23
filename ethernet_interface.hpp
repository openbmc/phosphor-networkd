#pragma once

#include "ipaddress.hpp"
#include "types.hpp"

#include "xyz/openbmc_project/Network/EthernetInterface/server.hpp"
#include "xyz/openbmc_project/Network/IP/Create/server.hpp"

#include <sdbusplus/bus.hpp>
#include <sdbusplus/server/object.hpp>

#include <string>

namespace phosphor
{
namespace network
{

using Ifaces =
    sdbusplus::server::object::object<
        sdbusplus::xyz::openbmc_project::Network::server::EthernetInterface,
        sdbusplus::xyz::openbmc_project::Network::IP::server::Create>;

using IP = sdbusplus::xyz::openbmc_project::Network::server::IP;


using LinkSpeed = uint16_t;
using DuplexMode = uint8_t;
using Autoneg = uint8_t;
using InterfaceInfo = std::tuple<LinkSpeed, DuplexMode, Autoneg>;


/** @class EthernetInterface
 *  @brief OpenBMC Ethernet Interface implementation.
 *  @details A concrete implementation for the
 *  xyz.openbmc_project.Network.EthernetInterface DBus API.
 */
class EthernetInterface : public Ifaces
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
         *  @param[in] dhcpEnabled - is dhcp enabled(true/false).
         */
        EthernetInterface(sdbusplus::bus::bus& bus,
                          const std::string& objPath,
                          bool dhcpEnabled,
                          const AddrList& addrs);

        /** @brief Function to create ipaddress dbus object.
         *  @param[in] addressType - Type of ip address.
         *  @param[in] ipaddress- IP adress.
         *  @param[in] prefixLength - Length of prefix.
         *  @param[in] gateway - Gateway ip address.
         */

        void iP(IP::Protocol addressType,
                std::string ipaddress,
                uint8_t prefixLength,
                std::string gateway) override;

        /** @brief delete the dbus object of the given ipaddress.
         */

        void deleteObject(const std::string& ipaddress);


    private:

        /** @brief get the info of the ethernet interface.
         *  @return tuple having the link speed,autonegotiation,duplexmode .
         */

        InterfaceInfo getInterfaceInfo() const;

        /** @brief get the mac address of the interface.
         *  @return macaddress on success
         */

        std::string getMACAddress() const;

        /** @brief construct the ip address dbus object path.
         *  @param[in] addressType - Type of ip address.
         *  @param[in] ipaddress - IP address.
         *  @param[in] prefixLength - Length of prefix.
         *  @param[in] gateway - Gateway addess.

         *  @return path of the address object.
         */

        std::string generateObjectPath(IP::Protocol addressType,
                                       const std::string& ipaddress,
                                       uint8_t prefixLength,
                                       const std::string& gateway) const;

        /** @brief generates the id by doing hash of ipaddress,
         *         prefixlength and the gateway.
         *  @param[in] ipaddress - IP address.
         *  @param[in] prefixLength - Length of prefix.
         *  @param[in] gateway - Gateway addess.
         *  @return hash string.
         */

        static std::string generateId(const std::string& ipaddress,
                                      uint8_t prefixLength,
                                      const std::string& gateway);

        /** @brief Persistent sdbusplus DBus bus connection. */
        sdbusplus::bus::bus& bus;

        /** @brief Persistent map of IPAddress dbus objects and their names */
        std::map<std::string, std::unique_ptr<IPAddress>> addrs;


};

} // namespace network
} // namespace phosphor
