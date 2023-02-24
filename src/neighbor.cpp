#include "neighbor.hpp"

#include "ethernet_interface.hpp"
#include "network_manager.hpp"

#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/elog.hpp>
#include <string>
#include <xyz/openbmc_project/Common/error.hpp>

namespace phosphor
{
namespace network
{

static auto makeObjPath(std::string_view root, InAddrAny addr)
{
    auto ret = sdbusplus::message::object_path(std::string(root));
    ret /= std::to_string(addr);
    return ret;
}

Neighbor::Neighbor(sdbusplus::bus_t& bus, std::string_view objRoot,
                   stdplus::PinnedRef<EthernetInterface> parent, InAddrAny addr,
                   ether_addr lladdr, State state) :
    Neighbor(bus, makeObjPath(objRoot, addr), parent, addr, lladdr, state)
{
}

Neighbor::Neighbor(sdbusplus::bus_t& bus,
                   sdbusplus::message::object_path objPath,
                   stdplus::PinnedRef<EthernetInterface> parent, InAddrAny addr,
                   ether_addr lladdr, State state) :
    NeighborObj(bus, objPath.str.c_str(), NeighborObj::action::defer_emit),
    parent(parent), objPath(std::move(objPath))
{
    NeighborObj::ipAddress(std::to_string(addr), true);
    NeighborObj::macAddress(std::to_string(lladdr), true);
    NeighborObj::state(state, true);
    emit_object_added();
}

void Neighbor::delete_()
{
    auto& neighbors = parent.get().staticNeighbors;
    std::unique_ptr<Neighbor> ptr;
    for (auto it = neighbors.begin(); it != neighbors.end(); ++it)
    {
        if (it->second.get() == this)
        {
            ptr = std::move(it->second);
            neighbors.erase(it);
            break;
        }
    }

    parent.get().queueWriteConfig();
    parent.get().manager.get().reloadConfigs();
}

using sdbusplus::xyz::openbmc_project::Common::Error::NotAllowed;
using REASON =
    phosphor::logging::xyz::openbmc_project::Common::NotAllowed::REASON;
using phosphor::logging::elog;

std::string Neighbor::ipAddress(std::string /*ipAddress*/)
{
    elog<NotAllowed>(REASON("Property update is not allowed"));
}

std::string Neighbor::macAddress(std::string /*macAddress*/)
{
    elog<NotAllowed>(REASON("Property update is not allowed"));
}

Neighbor::State Neighbor::state(State /*state*/)
{
    elog<NotAllowed>(REASON("Property update is not allowed"));
}

} // namespace network
} // namespace phosphor
