#pragma once
#include "types.hpp"

#include <sdbusplus/bus.hpp>
#include <sdbusplus/message/native_types.hpp>
#include <sdbusplus/server/object.hpp>
#include <stdplus/pinned.hpp>
#include <string_view>
#include <xyz/openbmc_project/Network/StaticRoute/server.hpp>
#include <xyz/openbmc_project/Object/Delete/server.hpp>

namespace phosphor
{
namespace network
{

using StaticRouteIntf =
    sdbusplus::xyz::openbmc_project::Network::server::StaticRoute;

using StaticRouteObj = sdbusplus::server::object_t<
    StaticRouteIntf, sdbusplus::xyz::openbmc_project::Object::server::Delete>;

class EthernetInterface;

/** @class StaticRoute
 *  @brief OpenBMC network static route implementation.
 *  @details A concrete implementation for the
 *  xyz.openbmc_project.Network.StaticRoute dbus interface.
 */
class StaticRoute : public StaticRouteObj
{
  public:
    /** @brief Constructor to put object onto bus at a dbus path.
     *  @param[in] bus - Bus to attach to.
     *  @param[in] objRoot - Path to attach at.
     *  @param[in] parent - Parent object.
     *  @param[in] destination - Destination address.
     *  @param[in] gateway - Gateway address.
     *  @param[in] prefixLength - Prefix length.
     */
    StaticRoute(sdbusplus::bus_t& bus, std::string_view objRoot,
                stdplus::PinnedRef<EthernetInterface> parent,
                std::string destination, std::string gateway,
                uint32_t prefixLength);

    /** @brief Delete this d-bus object.
     */
    void delete_() override;

    using StaticRouteObj::destination;
    std::string destination(std::string) override;
    using StaticRouteObj::gateway;
    std::string gateway(std::string) override;
    using StaticRouteObj::prefixLength;
    uint32_t prefixLength(uint32_t) override;

    inline const auto& getObjPath() const
    {
        return objPath;
    }

  private:
    /** @brief Parent Object. */
    stdplus::PinnedRef<EthernetInterface> parent;

    /** @brief Dbus object path */
    sdbusplus::message::object_path objPath;

    StaticRoute(sdbusplus::bus_t& bus, sdbusplus::message::object_path objPath,
                stdplus::PinnedRef<EthernetInterface> parent,
                std::string destination, std::string gateway,
                uint32_t prefixLength);
};

} // namespace network
} // namespace phosphor
