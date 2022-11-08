#pragma once
#include "types.hpp"

#include <linux/netlink.h>

#include <cstdint>
#include <optional>
#include <sdbusplus/bus.hpp>
#include <sdbusplus/message/native_types.hpp>
#include <sdbusplus/server/object.hpp>
#include <string>
#include <string_view>
#include <vector>
#include <xyz/openbmc_project/Network/IP/server.hpp>
#include <xyz/openbmc_project/Object/Delete/server.hpp>

namespace phosphor
{
namespace network
{

using IPIfaces = sdbusplus::server::object_t<
    sdbusplus::xyz::openbmc_project::Network::server::IP,
    sdbusplus::xyz::openbmc_project::Object::server::Delete>;

using IP = sdbusplus::xyz::openbmc_project::Network::server::IP;

class EthernetInterface;

/* @class AddressFilter
 */
struct AddressFilter
{
    unsigned interface = 0;
    std::optional<uint8_t> scope;
};

/** @class AddressInfo
 *  @brief Information about a addresses from the kernel
 */
struct AddressInfo
{
    unsigned interface;
    InAddrAny address;
    uint8_t prefix;
    uint8_t scope;
    uint32_t flags;
};

/** @brief Returns a list of the current system neighbor table
 */
std::vector<AddressInfo> getCurrentAddresses(const AddressFilter& filter);

/** @class IPAddress
 *  @brief OpenBMC IPAddress implementation.
 *  @details A concrete implementation for the
 *  xyz.openbmc_project.Network.IPProtocol
 *  xyz.openbmc_project.Network.IP Dbus interfaces.
 */
class IPAddress : public IPIfaces
{
  public:
    IPAddress() = delete;
    IPAddress(const IPAddress&) = delete;
    IPAddress& operator=(const IPAddress&) = delete;
    IPAddress(IPAddress&&) = delete;
    IPAddress& operator=(IPAddress&&) = delete;
    virtual ~IPAddress() = default;

    /** @brief Constructor to put object onto bus at a dbus path.
     *  @param[in] bus - Bus to attach to.
     *  @param[in] objRoot - Path to attach at.
     *  @param[in] parent - Parent object.
     *  @param[in] addr - The ip address and prefix.
     *  @param[in] origin - origin of ipaddress(dhcp/static/SLAAC/LinkLocal).
     */
    IPAddress(sdbusplus::bus_t& bus, std::string_view objRoot,
              EthernetInterface& parent, IfAddr addr, IP::AddressOrigin origin);

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
    EthernetInterface& parent;

    /** @brief Dbus object path */
    sdbusplus::message::object_path objPath;

    IPAddress(sdbusplus::bus_t& bus, sdbusplus::message::object_path objPath,
              EthernetInterface& parent, IfAddr addr, IP::AddressOrigin origin);
};

namespace detail
{

void parseAddress(const AddressFilter& filter, const nlmsghdr& hdr,
                  std::string_view msg, std::vector<AddressInfo>& addresses);

} // namespace detail
} // namespace network
} // namespace phosphor
