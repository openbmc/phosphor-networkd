#pragma once

#include "ethernet_interface.hpp"
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
        CreateIface(bus, path, CreateIface::action::defer_emit),
        bus(bus), objectPath(path), manager(parent)
    {
        HypEthernetIntf::interfaceName(intfName);
    };

    /** @brief Function to create ipAddress dbus object.
     *  @param[in] addressType - Type of ip address.
     *  @param[in] ipAddress- IP address.
     *  @param[in] prefixLength - Length of prefix.
     *  @param[in] gateway - Gateway ip address.
     */

    ObjectPath ip(HypIP::Protocol /*addressType*/, std::string /*ipAddress*/,
                  uint8_t /*prefixLength*/, std::string /*gateway*/) override
    {
        return std::string();
    };

    /* @brief Function that returns parent's bios attrs map
     */
    biosTableType getBiosAttrsMap();

    /* @brief Set value of DHCPEnabled
     * @param[in] value - value that determines if the dhcp is enabled/not
     *                    possible values: both, none, v4, v6
     */
    HypEthernetIntf::DHCPConf
        dhcpEnabled(HypEthernetIntf::DHCPConf value) override;

    using HypEthernetIntf::dhcpEnabled;
    using HypEthernetIntf::interfaceName;

  protected:
    /** @brief sdbusplus DBus bus connection. */
    sdbusplus::bus::bus& bus;

    /** @brief object path */
    std::string objectPath;

    /** @brief Parent of this object */
    HypNetworkMgr& manager;
};

} // namespace network
} // namespace phosphor
