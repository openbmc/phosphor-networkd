#pragma once
#include "types.hpp"

#include <sdbusplus/bus.hpp>
#include <sdbusplus/message/native_types.hpp>
#include <sdbusplus/server/object.hpp>
#include <stdplus/pinned.hpp>
#include <xyz/openbmc_project/Network/IP/server.hpp>
#include <xyz/openbmc_project/Object/Delete/server.hpp>

#include <string_view>

namespace phosphor
{
namespace network
{

using IPIfaces = sdbusplus::server::object_t<
    sdbusplus::xyz::openbmc_project::Network::server::IP,
    sdbusplus::xyz::openbmc_project::Object::server::Delete>;

using IP = sdbusplus::xyz::openbmc_project::Network::server::IP;

class EthernetInterface;

/** @class IPAddress
 *  @brief OpenBMC IPAddress implementation.
 *  @details A concrete implementation for the
 *  xyz.openbmc_project.Network.IPProtocol
 *  xyz.openbmc_project.Network.IP Dbus interfaces.
 */
class IPAddress : public IPIfaces
{
  public:
    /** @brief Constructor to put object onto bus at a dbus path.
     *  @param[in] bus - Bus to attach to.
     *  @param[in] objRoot - Path to attach at.
     *  @param[in] parent - Parent object.
     *  @param[in] addr - The ip address and prefix.
     *  @param[in] origin - origin of ipaddress(dhcp/static/SLAAC/LinkLocal).
     */
    IPAddress(sdbusplus::bus_t& bus, std::string_view objRoot,
              stdplus::PinnedRef<EthernetInterface> parent, IfAddr addr,
              IP::AddressOrigin origin);

    std::string address(std::string ipAddress) override;
    uint8_t prefixLength(uint8_t) override;
    std::string gateway(std::string gateway) override;
    IP::Protocol type(IP::Protocol type) override;
    IP::AddressOrigin origin(IP::AddressOrigin origin) override;

    /** @brief Delete this d-bus object.
     */
    void delete_() override;

    using IP::address;
    using IP::gateway;
    using IP::origin;
    using IP::prefixLength;
    using IP::type;

    inline const auto& getObjPath() const
    {
        return objPath;
    }

  private:
    /** @brief Parent Object. */
    stdplus::PinnedRef<EthernetInterface> parent;

    /** @brief Dbus object path */
    sdbusplus::message::object_path objPath;

    IPAddress(sdbusplus::bus_t& bus, sdbusplus::message::object_path objPath,
              stdplus::PinnedRef<EthernetInterface> parent, IfAddr addr,
              IP::AddressOrigin origin);
};

} // namespace network
} // namespace phosphor
