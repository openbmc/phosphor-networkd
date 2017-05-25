#pragma once

#include "xyz/openbmc_project/Network/IP/server.hpp"
#include "xyz/openbmc_project/Object/Delete/server.hpp"

#include <sdbusplus/bus.hpp>
#include <sdbusplus/server/object.hpp>

#include <string>

namespace phosphor
{
namespace network
{

using IPIfaces =
    sdbusplus::server::object::object<
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
        IPAddress() = delete;
        IPAddress(const IPAddress&) = delete;
        IPAddress& operator=(const IPAddress&) = delete;
        IPAddress(IPAddress&&) = delete;
        IPAddress& operator=(IPAddress &&) = delete;
        virtual ~IPAddress() = default;

        /** @brief Constructor to put object onto bus at a dbus path.
         *  @param[in] bus - Bus to attach to.
         *  @param[in] objPath - Path to attach at.
         *  @param[in] parent - Parent object.
         *  @param[in] type - ipaddress type(v4/v6).
         *  @param[in] ipAddress - ipadress.
         *  @param[in] prefixLength - Length of prefix.
         *  @param[in] gateway - gateway address.
         */
        IPAddress(sdbusplus::bus::bus& bus,
                  const char* objPath,
                  EthernetInterface& parent,
                  IP::Protocol type,
                  const std::string& ipAddress,
                  IP::AddressOrigin origin,
                  uint8_t prefixLength,
                  const std::string& gateway);

        /** @brief Delete this d-bus object.
         */
        void delete_() override;

    private:

        /** @brief Parent Object. */
        EthernetInterface& parent;

};

} // namespace network
} // namespace phosphor
