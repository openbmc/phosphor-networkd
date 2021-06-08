#pragma once

#include "ethernet_interface.hpp"
#include "hyp_ip_interface.hpp"
#include "hyp_network_manager.hpp"
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
using HypIP = sdbusplus::xyz::openbmc_project::Network::server::IP;

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
        CreateIface(bus, path, true),
        bus(bus), objectPath(path), manager(parent)
    {
        HypEthernetIntf::interfaceName(intfName);

        createIPAddressObjects();
        watchBaseBiosTable();
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

    /* @brief Fuction to get the ip dbus object
     *        w.r.t the attribute name given.
     * @param[in] attrName - attrName
     * @param[in] oldIpAddr - optional (needed in case of ip address change in
     * bios table)
     *
     * @return pointer to the ip dbus object
     */
    std::shared_ptr<phosphor::network::HypIPAddress>
        getIPAddrObject(std::string attrName, std::string /*oldIpAddr*/);

    /* @brief Function to set the bios properties in the
     *        ip dbus object given.
     * @param[in] ipObj - pointer to the ip dbus object.
     * @param[in] attrName - bios attribute name.
     * @param[in] attrValue - bios attribute value.
     */
    void setBiosPropInDbus(
        std::shared_ptr<phosphor::network::HypIPAddress> ipObj,
        std::string attrName, std::variant<std::string, uint8_t> attrValue);

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

    /* @brief Returns the dhcp enabled property
     * @param[in] protocol - ipv4/ipv6
     * @return bool - true if dhcpEnabled
     */
    bool isDHCPEnabled(IP::Protocol protocol, bool ignoreProtocol = false);

    /* @brief Disables DHCP conf
     * @param[in] protocol - ipv4/ipv6
     */
    void disableDHCP(IP::Protocol protocol);

    /* @brief Set value of DHCPEnabled
     * @param[in] value - value that determines if the dhcp is enabled/not
     *                    possible values: both, none, v4, v6
     */
    HypEthernetIntf::DHCPConf
        dhcpEnabled(HypEthernetIntf::DHCPConf value) override;

    using HypEthernetIntf::dhcpEnabled;
    using HypEthernetIntf::interfaceName;

  private:
    /** @brief sdbusplus DBus bus connection. */
    sdbusplus::bus::bus& bus;

    /** @brief object path */
    std::string objectPath;

    /** @brief Parent of this object */
    HypNetworkMgr& manager;

    /** @brief List of the ipaddress and the ip dbus objects */
    std::map<std::string, std::shared_ptr<HypIPAddress>> addrs;
};

} // namespace network
} // namespace phosphor
