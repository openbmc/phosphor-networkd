#pragma once
#include "types.hpp"

#include <sdbusplus/bus.hpp>
#include <sdbusplus/message/native_types.hpp>
#include <sdbusplus/server/object.hpp>
#include <stdplus/pinned.hpp>
#include <string_view>
#include <xyz/openbmc_project/Network/Neighbor/server.hpp>
#include <xyz/openbmc_project/Object/Delete/server.hpp>

namespace phosphor
{
namespace network
{

using NeighborIntf = sdbusplus::xyz::openbmc_project::Network::server::Neighbor;

using NeighborObj = sdbusplus::server::object_t<
    NeighborIntf, sdbusplus::xyz::openbmc_project::Object::server::Delete>;

class EthernetInterface;

/** @class Neighbor
 *  @brief OpenBMC network neighbor implementation.
 *  @details A concrete implementation for the
 *  xyz.openbmc_project.Network.Neighbor dbus interface.
 */
class Neighbor : public NeighborObj
{
  public:
    /** @brief Constructor to put object onto bus at a dbus path.
     *  @param[in] bus - Bus to attach to.
     *  @param[in] objRoot - Path to attach at.
     *  @param[in] parent - Parent object.
     *  @param[in] addr - IP address.
     *  @param[in] lladdr - Low level MAC address.
     *  @param[in] state - The state of the neighbor entry.
     */
    Neighbor(sdbusplus::bus_t& bus, std::string_view objRoot,
             stdplus::PinnedRef<EthernetInterface> parent, InAddrAny addr,
             ether_addr lladdr, State state);

    /** @brief Delete this d-bus object.
     */
    void delete_() override;

    using NeighborObj::ipAddress;
    std::string ipAddress(std::string) override;
    using NeighborObj::macAddress;
    std::string macAddress(std::string) override;
    using NeighborObj::state;
    State state(State) override;

    inline const auto& getObjPath() const
    {
        return objPath;
    }

  private:
    /** @brief Parent Object. */
    stdplus::PinnedRef<EthernetInterface> parent;

    /** @brief Dbus object path */
    sdbusplus::message::object_path objPath;

    Neighbor(sdbusplus::bus_t& bus, sdbusplus::message::object_path objPath,
             stdplus::PinnedRef<EthernetInterface> parent, InAddrAny addr,
             ether_addr lladdr, State state);
};

} // namespace network
} // namespace phosphor
