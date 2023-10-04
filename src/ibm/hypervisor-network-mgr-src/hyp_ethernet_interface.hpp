#pragma once

#include "hyp_network_manager.hpp"
#include "xyz/openbmc_project/Network/IP/Create/server.hpp"

#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/elog.hpp>
#include <sdbusplus/bus.hpp>
#include <xyz/openbmc_project/Common/error.hpp>
#include <xyz/openbmc_project/Network/EthernetInterface/server.hpp>
#include <xyz/openbmc_project/Network/IP/server.hpp>

namespace phosphor
{
namespace network
{

class HypNetworkMgr; // forward declaration of hypervisor network manager.

using namespace phosphor::logging;
using HypIP = sdbusplus::xyz::openbmc_project::Network::server::IP;

using CreateIface = sdbusplus::server::object_t<
    sdbusplus::xyz::openbmc_project::Network::server::EthernetInterface,
    sdbusplus::xyz::openbmc_project::Network::IP::server::Create>;

using biosTableType = std::map<std::string, std::variant<int64_t, std::string>>;

using HypEthernetIntf =
    sdbusplus::xyz::openbmc_project::Network::server::EthernetInterface;

using ObjectPath = sdbusplus::message::object_path;

static std::shared_ptr<sdbusplus::bus::match_t> matchBIOSAttrUpdate;

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
    HypEthInterface(sdbusplus::bus_t& bus, const char* path,
                    std::string_view intfName, HypNetworkMgr& parent) :
        CreateIface(bus, path, CreateIface::action::defer_emit),
        bus(bus), objectPath(path), manager(parent)
    {
        HypEthernetIntf::interfaceName(intfName.data(), true);
        emit_object_added();
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

    /* @brief Returns the dhcp enabled property
     * @param[in] protocol - ipv4/ipv6
     * @return bool - true if dhcpEnabled
     */
    bool isDHCPEnabled(HypIP::Protocol protocol);

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
    sdbusplus::bus_t& bus;

    /** @brief object path */
    std::string objectPath;

    /** @brief Parent of this object */
    HypNetworkMgr& manager;

  private:
    /** @brief Determines if DHCP is active for the IP::Protocol supplied.
     *  @param[in] protocol - Either IPv4 or IPv6
     *  @returns true/false value if DHCP is active for the input protocol
     */
    bool dhcpIsEnabled(HypIP::Protocol protocol);
};

} // namespace network
} // namespace phosphor
