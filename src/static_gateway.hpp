#pragma once
#include "types.hpp"

#include <sdbusplus/bus.hpp>
#include <sdbusplus/message/native_types.hpp>
#include <sdbusplus/server/object.hpp>
#include <stdplus/pinned.hpp>
#include <xyz/openbmc_project/Network/IP/server.hpp>
#include <xyz/openbmc_project/Network/StaticGateway/server.hpp>
#include <xyz/openbmc_project/Object/Delete/server.hpp>

#include <string_view>

namespace phosphor
{
namespace network
{

using StaticGatewayIntf =
    sdbusplus::xyz::openbmc_project::Network::server::StaticGateway;

using StaticGatewayObj = sdbusplus::server::object_t<
    StaticGatewayIntf, sdbusplus::xyz::openbmc_project::Object::server::Delete>;

using IP = sdbusplus::xyz::openbmc_project::Network::server::IP;

class EthernetInterface;

/** @class StaticGateway
 *  @brief OpenBMC network static gateway implementation.
 *  @details A concrete implementation for the
 *  xyz.openbmc_project.Network.StaticGateway dbus interface.
 */
class StaticGateway : public StaticGatewayObj
{
  public:
    /** @brief Constructor to put object onto bus at a dbus path.
     *  @param[in] bus - Bus to attach to.
     *  @param[in] objRoot - Path to attach at.
     *  @param[in] parent - Parent object.
     *  @param[in] gateway - Gateway address.
     */
    StaticGateway(sdbusplus::bus_t& bus, std::string_view objRoot,
                  stdplus::PinnedRef<EthernetInterface> parent,
                  std::string gateway, IP::Protocol protocolType);

    /** @brief Delete this d-bus object.
     */
    void delete_() override;

    using StaticGatewayObj::gateway;
    std::string gateway(std::string) override;
    using StaticGatewayObj::protocolType;
    IP::Protocol protocolType(IP::Protocol) override;
    inline const auto& getObjPath() const
    {
        return objPath;
    }

  private:
    /** @brief Parent Object. */
    stdplus::PinnedRef<EthernetInterface> parent;

    /** @brief Dbus object path */
    sdbusplus::message::object_path objPath;

    StaticGateway(sdbusplus::bus_t& bus,
                  sdbusplus::message::object_path objPath,
                  stdplus::PinnedRef<EthernetInterface> parent,
                  std::string gateway, IP::Protocol protocolType);
};

} // namespace network
} // namespace phosphor
