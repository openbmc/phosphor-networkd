#pragma once

#include "hyp_ip_interface.hpp"
#include "hyp_network_manager.hpp"
#include "types.hpp"

#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/elog.hpp>
#include <phosphor-logging/lg2.hpp>
#include <sdbusplus/bus.hpp>
#include <stdplus/pinned.hpp>
#include <stdplus/str/maps.hpp>
#include <xyz/openbmc_project/BIOSConfig/Manager/server.hpp>
#include <xyz/openbmc_project/Common/error.hpp>
#include <xyz/openbmc_project/Network/EthernetInterface/server.hpp>
#include <xyz/openbmc_project/Network/IP/Create/server.hpp>
#include <xyz/openbmc_project/Network/IP/server.hpp>

namespace phosphor
{
namespace network
{

class HypNetworkMgr; // forward declaration of hypervisor network manager.

class HypIPAddress;

using namespace phosphor::logging;

using CreateIface = sdbusplus::server::object_t<
    sdbusplus::xyz::openbmc_project::Network::server::EthernetInterface,
    sdbusplus::xyz::openbmc_project::Network::IP::server::Create>;

using biosTableRetAttrValueType = std::variant<std::string, int64_t>;

using biosTableType = std::map<std::string, std::variant<int64_t, std::string>>;

using HypEthernetIntf =
    sdbusplus::xyz::openbmc_project::Network::server::EthernetInterface;

using HypIP = sdbusplus::xyz::openbmc_project::Network::server::IP;

using ObjectPath = sdbusplus::message::object_path;

using ipAddrMapType = stdplus::string_umap<std::unique_ptr<HypIPAddress>>;

static std::shared_ptr<sdbusplus::bus::match_t> matchBIOSAttrUpdate;

using namespace sdbusplus::xyz::openbmc_project::Common::Error;
using Argument = xyz::openbmc_project::Common::InvalidArgument;

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
     *  @param[in] intfName - ethernet interface id (eth0/eth1)
     *  @param[in] parent - parent object.
     */
    HypEthInterface(stdplus::PinnedRef<sdbusplus::bus_t> bus,
                    sdbusplus::message::object_path path,
                    std::string_view intfName,
                    stdplus::PinnedRef<HypNetworkMgr> parent) :
        CreateIface(bus, path.str.c_str(), CreateIface::action::defer_emit),
        bus(bus), objectPath(std::move(path)), manager(parent)
    {
        HypEthernetIntf::interfaceName(intfName.data(), true);
        emit_object_added();
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

    template <typename Addr>
    static bool validIntfIP(Addr a) noexcept
    {
        return a.isUnicast() && !a.isLoopback();
    }

    template <typename Addr>
    static void validateGateway(std::string& gw)
    {
        try
        {
            auto ip = stdplus::fromStr<Addr>(gw);
            if (ip == Addr{})
            {
                throw std::invalid_argument("Empty gateway");
            }
            if (!validIntfIP(ip))
            {
                throw std::invalid_argument("Invalid unicast");
            }
            gw = stdplus::toStr(ip);
        }
        catch (const std::exception& e)
        {
            lg2::error("Invalid Gateway `{GATEWAY}`: {ERROR}", "GATEWAY", gw,
                       "ERROR", e);
            elog<InvalidArgument>(Argument::ARGUMENT_NAME("GATEWAY"),
                                  Argument::ARGUMENT_VALUE(gw.c_str()));
        }
    }

    /** @brief set the default v6 gateway of the interface.
     *  @param[in] gateway - default v6 gateway of the interface.
     */
    std::string defaultGateway6(std::string gateway) override;
    using HypEthernetIntf::defaultGateway6;

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
    stdplus::PinnedRef<sdbusplus::bus_t> bus;

    /** @brief object path */
    sdbusplus::message::object_path objectPath;

    /** @brief Parent of this object */
    stdplus::PinnedRef<HypNetworkMgr> manager;

    /** @brief List of the ipaddress and the ip dbus objects */
    ipAddrMapType addrs;
};

} // namespace network
} // namespace phosphor
