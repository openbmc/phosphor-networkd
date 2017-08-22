#pragma once

#include "types.hpp"
#include "util.hpp"

#include "xyz/openbmc_project/Network/EthernetInterface/server.hpp"
#include "xyz/openbmc_project/Network/MACAddress/server.hpp"
#include "xyz/openbmc_project/Network/IP/Create/server.hpp"

#include <sdbusplus/bus.hpp>
#include <sdbusplus/server/object.hpp>
#include <string>
#include <experimental/filesystem>

namespace phosphor
{
namespace network
{

using Ifaces =
    sdbusplus::server::object::object<
        sdbusplus::xyz::openbmc_project::Network::server::EthernetInterface,
        sdbusplus::xyz::openbmc_project::Network::server::MACAddress,
        sdbusplus::xyz::openbmc_project::Network::IP::server::Create>;

using IP = sdbusplus::xyz::openbmc_project::Network::server::IP;

using EthernetInterfaceIntf =
    sdbusplus::xyz::openbmc_project::Network::server::EthernetInterface;
using MacAddressIntf =
    sdbusplus::xyz::openbmc_project::Network::server::MACAddress;

using ServerList = std::vector<std::string>;

namespace fs = std::experimental::filesystem;

class Manager; // forward declaration of network manager.

class TestEthernetInterface;

class VlanInterface;

class IPAddress;

using LinkSpeed = uint16_t;
using DuplexMode = uint8_t;
using Autoneg = uint8_t;
using VlanId = uint32_t;
using InterfaceName = std::string;
using InterfaceInfo = std::tuple<LinkSpeed, DuplexMode, Autoneg>;
using AddressMap = std::map<std::string, std::shared_ptr<IPAddress>>;
using VlanInterfaceMap = std::map<InterfaceName, std::unique_ptr<VlanInterface>>;

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
         *  @param[in] dhcpEnabled - is dhcp enabled(true/false).
         *  @param[in] parent - parent object.
         *  @param[in] emitSignal - true if the object added signal needs to be
         *                          send.
         */
        EthernetInterface(sdbusplus::bus::bus& bus,
                          const std::string& objPath,
                          bool dhcpEnabled,
                          Manager& parent,
                          bool emitSignal = true);

        /** @brief Function to create ipaddress dbus object.
         *  @param[in] addressType - Type of ip address.
         *  @param[in] ipaddress- IP address.
         *  @param[in] prefixLength - Length of prefix.
         *  @param[in] gateway - Gateway ip address.
         */

        void iP(IP::Protocol addressType,
                std::string ipaddress,
                uint8_t prefixLength,
                std::string gateway) override;

        /* @brief delete the dbus object of the given ipaddress.
         * @param[in] ipaddress - IP address.
         */
        void deleteObject(const std::string& ipaddress);

        /* @brief delete the vlan dbus object of the given interface.
         *        Also deletes the device file and the network file.
         * @param[in] interface - VLAN Interface.
         */
        void deleteVLANObject(const std::string& interface);

        /* @brief creates the dbus object(IPaddres) given in the address list.
         * @param[in] addrs - address list for which dbus objects needs
         *                    to create.
         */
        void createIPAddressObjects();

        /* @brief Gets all the ip addresses.
         * @returns the list of ipaddress.
         */
        const AddressMap& getAddresses() const { return addrs; }

        /** Set value of DHCPEnabled */
        bool dHCPEnabled(bool value) override;

        /** @brief sets the MAC address.
         *  @param[in] value - MAC address which needs to be set on the system.
         */
        std::string mACAddress(std::string value) override;

        /** @brief sets the DNS/nameservers.
         *  @param[in] value - vector of DNS servers.
         */
        ServerList nameservers(ServerList value) override;

        /** @brief sets the NTP servers.
         *  @param[in] value - vector of NTP servers.
         */
        ServerList nTPServers(ServerList value) override;

        /** @brief create Vlan interface.
         *  @param[in] id- VLAN identifier.
         */
        void createVLAN(VlanId id);

        /** @brief load the vlan info from the system
         *         and creates the ip address dbus objects.
         *  @param[in] vlanID- VLAN identifier.
         */
        void loadVLAN(VlanId vlanID);

        /** @brief write the network conf file with the in-memory objects.
         */
        void writeConfigurationFile();

        using EthernetInterfaceIntf::dHCPEnabled;
        using EthernetInterfaceIntf::interfaceName;
        using MacAddressIntf::mACAddress;
        // abosolute path of the resolvConfFile.
        std::string resolvConfFile;


    protected:

        /** @brief get the info of the ethernet interface.
         *  @return tuple having the link speed,autonegotiation,duplexmode .
         */

        InterfaceInfo getInterfaceInfo() const;

        /** @brief get the mac address of the interface.
         *  @param[in] interfaceName - Network interface name.
         *  @return macaddress on success
         */

        std::string getMACAddress(const std::string& interfaceName) const;

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

        /** @brief write the dhcp section **/
        void writeDHCPSection(std::fstream& stream);;

        /** @brief gets the MAC address from the VPD.**/
        std::string getMACAddressfromVPD();

        /** @brief write the resolv conf file with the given dns list.
         *  @param[in] dnsList - DNS server list which needs to be written.
         */
        void writeResolveConf(const ServerList& dnsList);

        /** @brief get the name server details from the network conf
         *
         */
        ServerList getNameServerFromConf();

        /** @brief get the NTP server list from the network conf
         *
         */
        ServerList getNTPServersFromConf();

        /** @brief Persistent sdbusplus DBus bus connection. */
        sdbusplus::bus::bus& bus;

        /** @brief Network Manager object. */
        Manager& manager;

        /** @brief Persistent map of IPAddress dbus objects and their names */
        AddressMap addrs;

        /** @brief Persistent map of VLAN interface dbus objects and their names */
        VlanInterfaceMap vlanInterfaces;

        /** @brief Dbus object path */
        std::string objPath;

        friend class TestEthernetInterface;
};

} // namespace network
} // namespace phosphor
