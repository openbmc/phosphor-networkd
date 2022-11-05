#pragma once
#include "types.hpp"

#include <linux/netlink.h>
#include <net/ethernet.h>

#include <cstdint>
#include <optional>
#include <sdbusplus/bus.hpp>
#include <sdbusplus/message/native_types.hpp>
#include <sdbusplus/server/object.hpp>
#include <string_view>
#include <vector>
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

/* @class NeighborFilter
 */
struct NeighborFilter
{
    unsigned interface;
    uint16_t state;

    /* @brief Creates an empty filter */
    NeighborFilter() : interface(0), state(~UINT16_C(0))
    {
    }
};

/** @class NeighborInfo
 *  @brief Information about a neighbor from the kernel
 */
struct NeighborInfo
{
    unsigned interface;
    InAddrAny address;
    std::optional<ether_addr> mac;
    uint16_t state;
};

/** @brief Returns a list of the current system neighbor table
 */
std::vector<NeighborInfo> getCurrentNeighbors(const NeighborFilter& filter);

/** @class Neighbor
 *  @brief OpenBMC network neighbor implementation.
 *  @details A concrete implementation for the
 *  xyz.openbmc_project.Network.Neighbor dbus interface.
 */
class Neighbor : public NeighborObj
{
  public:
    using State = NeighborIntf::State;

    Neighbor() = delete;
    Neighbor(const Neighbor&) = delete;
    Neighbor& operator=(const Neighbor&) = delete;
    Neighbor(Neighbor&&) = delete;
    Neighbor& operator=(Neighbor&&) = delete;
    virtual ~Neighbor() = default;

    /** @brief Constructor to put object onto bus at a dbus path.
     *  @param[in] bus - Bus to attach to.
     *  @param[in] objRoot - Path to attach at.
     *  @param[in] parent - Parent object.
     *  @param[in] addr - IP address.
     *  @param[in] lladdr - Low level MAC address.
     *  @param[in] state - The state of the neighbor entry.
     */
    Neighbor(sdbusplus::bus_t& bus, std::string_view objRoot,
             EthernetInterface& parent, InAddrAny addr, ether_addr lladdr,
             State state);

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
    EthernetInterface& parent;

    /** @brief Dbus object path */
    sdbusplus::message::object_path objPath;

    Neighbor(sdbusplus::bus_t& bus, sdbusplus::message::object_path objPath,
             EthernetInterface& parent, InAddrAny addr, ether_addr lladdr,
             State state);
};

namespace detail
{

void parseNeighbor(const NeighborFilter& filter, const nlmsghdr& hdr,
                   std::string_view msg, std::vector<NeighborInfo>& neighbors);

} // namespace detail

} // namespace network
} // namespace phosphor
