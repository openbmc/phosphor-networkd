#pragma once
#include "types.hpp"

#include <linux/netlink.h>

#include <cstdint>
#include <sdbusplus/bus.hpp>
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

using IPIfaces = sdbusplus::server::object::object<
    sdbusplus::xyz::openbmc_project::Network::server::IP,
    sdbusplus::xyz::openbmc_project::Object::server::Delete>;

using IP = sdbusplus::xyz::openbmc_project::Network::server::IP;

class EthernetInterface;

/* @class AddressFilter
 */
struct AddressFilter
{
    unsigned interface;
    std::optional<uint8_t> scope;

    /* @brief Creates an empty filter */
    AddressFilter() : interface(0)
    {
    }
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
     *  @param[in] objPath - Path to attach at.
     *  @param[in] parent - Parent object.
     *  @param[in] type - ipaddress type(v4/v6).
     *  @param[in] ipAddress - ipadress.
     *  @param[in] origin - origin of ipaddress(dhcp/static/SLAAC/LinkLocal).
     *  @param[in] prefixLength - Length of prefix.
     *  @param[in] gateway - gateway address.
     */
    IPAddress(sdbusplus::bus::bus& bus, const char* objPath,
              EthernetInterface& parent, IP::Protocol type,
              const std::string& ipAddress, IP::AddressOrigin origin,
              uint8_t prefixLength, const std::string& gateway);

    /** @brief Delete this d-bus object.
     */
    void delete_() override;

  private:
    /** @brief Parent Object. */
    EthernetInterface& parent;
};

namespace detail
{

void parseAddress(const AddressFilter& filter, const nlmsghdr& hdr,
                  std::string_view msg, std::vector<AddressInfo>& addresses);

} // namespace detail
} // namespace network
} // namespace phosphor
