#pragma once

#include "ethernet_interface.hpp"
#include "hyp_ip_interface.hpp"
#include "hyp_network_manager.hpp"

#include <filesystem>
#include <fstream>
#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/log.hpp>
#include <sdbusplus/bus.hpp>
#include <sdbusplus/server/object.hpp>

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
    sdbusplus::xyz::openbmc_project::Collection::server::DeleteAll>;

using biosTableType = std::map<std::string, std::variant<int64_t, std::string>>;

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
                    HypNetworkMgr& parent) :
        CreateIface(bus, path),
        bus(bus), objectPath(path), manager(parent)
    {
        // register signal - watch bios tale for any updates
        watchBaseBiosTable();
        createIPAddressObjects();
    };

    /* @brief creates the IP dbus object
     */
    virtual void createIPAddressObjects();

    /* @brief Function to delete the IP dbus object
     *  @param[in] ipaddress - ipaddress to delete.
     */
    void deleteObject(const std::string& ipaddress);

    /** @brief Delete all IP dbus objects.
     */
    void deleteAll();

    /* @brief Fuction to watch the Base Bios Table for any
     *        property change and update the aprropriate
     *        property in the dbus object
     */
    void watchBaseBiosTable();

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

    /* @brief Utility function to generate unique id
              for the ip dbus object
     * @param[in] ipaddress - ip address.
     * @param[in] prefixLength - prefix length.
     * @param[in] gateway - gateway
     */
    virtual std::string generateId(const std::string& ipaddress,
                                   uint8_t prefixLength,
                                   const std::string& gateway);

    /* @brief Function to update the ip address property in
              the dbus object
     * @detail if there is a change in ip address in bios
               table, the ip is updated in the dbus obj path
     * @param[in] updatedIp - ip to update
     */
    void updateIPAddress(std::string ip, std::string updatedIp);

    /* @brief Function tohat returns parent's bios attrs map
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
