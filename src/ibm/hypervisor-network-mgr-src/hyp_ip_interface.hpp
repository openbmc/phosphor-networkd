#pragma once

#include "hyp_ethernet_interface.hpp"
#include "util.hpp"

#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/log.hpp>
#include <xyz/openbmc_project/Network/IP/server.hpp>
#include <xyz/openbmc_project/Object/Delete/server.hpp>
#include <xyz/openbmc_project/Object/Enable/server.hpp>

namespace phosphor
{
namespace network
{
class HypEthInterface;

using namespace phosphor::logging;

using HypIPIfaces = sdbusplus::server::object::object<
    sdbusplus::xyz::openbmc_project::Network::server::IP,
    sdbusplus::xyz::openbmc_project::Object::server::Delete,
    sdbusplus::xyz::openbmc_project::Object::server::Enable>;

using HypIP = sdbusplus::xyz::openbmc_project::Network::server::IP;

using PendingAttributesType =
    std::map<std::string,
             std::tuple<std::string, std::variant<int64_t, std::string>>>;

/** @class HypIPAddress
 *  @brief Hypervisor IPAddress implementation.
 *  @details A concrete implementation for the
 *  xyz.openbmc_project.Network.IPProtocol
 *  xyz.openbmc_project.Network.IP Dbus interfaces. for hypervisor
 */
class HypIPAddress : public HypIPIfaces
{
  public:
    HypIPAddress() = delete;
    HypIPAddress(const HypIPAddress&) = delete;
    HypIPAddress& operator=(const HypIPAddress&) = delete;
    HypIPAddress(HypIPAddress&&) = delete;
    HypIPAddress& operator=(HypIPAddress&&) = delete;
    virtual ~HypIPAddress() = default;

    /** @brief Constructor to put object onto bus at a dbus path.
     *  @param[in] bus - Bus to attach to.
     *  @param[in] objPath - Path to attach at.
     *  @param[in] parent - Parent object.
     *  @param[in] type - ipaddress type(v4/v6).
     *  @param[in] ipAddress - ipadress.
     *  @param[in] origin - origin of ipaddress(dhcp/static).
     *  @param[in] prefixLength - Length of prefix.
     *  @param[in] gateway - gateway address.
     */
    HypIPAddress(sdbusplus::bus::bus& bus, const char* objPath,
                 HypEthInterface& parent, HypIP::Protocol type,
                 const std::string& ipaddress, HypIP::AddressOrigin origin,
                 uint8_t prefixLength, const std::string& gateway,
                 const std::string& intf);

    std::string address(std::string ipAddress) override;
    uint8_t prefixLength(uint8_t) override;
    std::string gateway(std::string gateway) override;
    HypIP::Protocol type(HypIP::Protocol type) override;
    HypIP::AddressOrigin origin(HypIP::AddressOrigin origin) override;

    /** @brief Delete this d-bus object.
     */
    void delete_() override {}

    using HypIP::address;
    using HypIP::gateway;
    using HypIP::origin;
    using HypIP::prefixLength;
    using HypIP::type;

  private:
    std::string objectPath;

    /** @brief Hypervisor eth interface id. */
    std::string intf;

    /** @brief Parent Object. */
    HypEthInterface& parent;
};

} // namespace network
} // namespace phosphor