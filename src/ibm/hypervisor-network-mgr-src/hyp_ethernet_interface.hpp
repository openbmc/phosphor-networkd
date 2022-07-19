#pragma once

#include "ethernet_interface.hpp"
#include "hyp_ip_interface.hpp"
#include "hyp_network_manager.hpp"
#include "types.hpp"
#include "xyz/openbmc_project/Network/IP/Create/server.hpp"

#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/elog.hpp>
#include <phosphor-logging/log.hpp>
#include <sdbusplus/bus.hpp>
#include <xyz/openbmc_project/Common/error.hpp>

namespace phosphor
{
namespace network
{

class HypNetworkMgr; // forward declaration of hypervisor network manager.

class HypIPAddress;

using namespace phosphor::logging;

using CreateIface = sdbusplus::server::object::object<
    sdbusplus::xyz::openbmc_project::Network::server::EthernetInterface,
    sdbusplus::xyz::openbmc_project::Network::IP::server::Create>;

using biosTableRetAttrValueType = std::variant<std::string, int64_t>;

using biosTableType = std::map<std::string, std::variant<int64_t, std::string>>;

using PendingAttributesType =
    std::map<std::string,
             std::tuple<std::string, std::variant<int64_t, std::string>>>;

using HypEthernetIntf =
    sdbusplus::xyz::openbmc_project::Network::server::EthernetInterface;

using HypIP = sdbusplus::xyz::openbmc_project::Network::server::IP;

using ObjectPath = sdbusplus::message::object_path;

using ipAddrMapType = string_umap<std::unique_ptr<HypIPAddress>>;

static std::shared_ptr<sdbusplus::bus::match::match> matchBIOSAttrUpdate;

/** @class HypEthernetInterface
 *  @brief Hypervisor Ethernet Interface implementation.
 */
class HypEthInterface : public CreateIface
{
  public:
    HypEthInterface() = delete;
    HypEthInterface(const HypEthInterface&) = delete;
    HypEthInterface& operator=(const HypEthInterface&) = delete;
    HypEthInterface(HypEthInterface&&) = delete;
    HypEthInterface& operator=(HypEthInterface&&) = delete;
    virtual ~HypEthInterface() = default;

    /** @brief Constructor to put object onto bus at a dbus path.
     *  @param[in] bus - Bus to attach to.
     *  @param[in] path - Path to attach at.
     *  @param[in] parent - parent object.
     */
    HypEthInterface(sdbusplus::bus::bus& bus, const char* path,
                    const std::string& intfName, HypNetworkMgr& parent) :
        CreateIface(bus, path, CreateIface::action::defer_emit),
        bus(bus), objectPath(path), manager(parent)
    {
        HypEthernetIntf::interfaceName(intfName);
    };

    /* @brief Method to return the value of the input attribute
     *        from the BaseBIOSTable
     *  @param[in] attrName - name of the bios attribute
     *  @param[out] - value of the bios attribute
     */
    biosTableRetAttrValueType getAttrFromBiosTable(const std::string& attrName);

    /* @brief Function to watch the Base Bios Table for ip
     *        address change from the host and refresh the hypervisor networkd
     * service
     */
    void watchBaseBiosTable();

    /* @brief creates the IP dbus object
     */
    virtual void createIPAddressObjects();

    /** @brief Function to create ipAddress dbus object.
     *  @param[in] addressType - Type of ip address.
     *  @param[in] ipAddress- IP address.
     *  @param[in] prefixLength - Length of prefix.
     *  @param[in] gateway - Gateway ip address.
     */

    ObjectPath ip(HypIP::Protocol addressType, std::string ipAddress,
                  uint8_t prefixLength, std::string gateway) override;

    /* @brief Function to delete the IP dbus object
     *  @param[in] ipaddress - ipaddress to delete.
     */
    bool deleteObject(const std::string& ipaddress);

    /* @brief Returns interface id
     * @param[out] - if0/if1
     */
    std::string getIntfLabel();

    /* @brief Function to update the ip address property in
              the dbus object
     * @detail if there is a change in ip address in bios
               table, the ip is updated in the dbus obj path
     * @param[in] updatedIp - ip to update
     */
    void updateIPAddress(std::string ip, std::string updatedIp);

    /* @brief Function that returns parent's bios attrs map
     */
    biosTableType getBiosAttrsMap();

    /* @brief Function to set ip address properties in
              the parent's bios attrs map
     * @detail if there is a change in any properties either in bios
               table or on the dbus object, the bios attrs map data member
               of the parent should be updated with the latest value
     * @param[in] attrName - attrName for which there is a change in value
     * @param[in] attrValue - updated value
     * @param[in] attrType - type of the attrValue (string/integer)
     */
    void setIpPropsInMap(std::string attrName,
                         std::variant<std::string, int64_t> attrValue,
                         std::string attrType);

    /** Set value of DHCPEnabled */
    HypEthernetIntf::DHCPConf dhcpEnabled() const override;
    HypEthernetIntf::DHCPConf dhcpEnabled(DHCPConf value) override;
    using HypEthernetIntf::dhcp4;
    bool dhcp4(bool value) override;
    using HypEthernetIntf::dhcp6;
    bool dhcp6(bool value) override;

    /** @brief check conf file for Router Advertisements
     *
     */
    bool ipv6AcceptRA(bool value) override;
    using HypEthernetIntf::ipv6AcceptRA;

    using HypEthernetIntf::interfaceName;

  protected:
    /** @brief sdbusplus DBus bus connection. */
    sdbusplus::bus::bus& bus;

    /** @brief object path */
    std::string objectPath;

    /** @brief Parent of this object */
    HypNetworkMgr& manager;

  protected:
    /** @brief Determines if DHCP is active for the HypIP::Protocol supplied.
     *  @param[in] protocol - Either IPv4 or IPv6
     *  @returns true/false value if DHCP is active for the input protocol
     */
    bool dhcpIsEnabled(HypIP::Protocol protocol);

    /** @brief List of the ipaddress and the ip dbus objects */
    ipAddrMapType addrs;
};

} // namespace network
} // namespace phosphor
