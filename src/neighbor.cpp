#include "neighbor.hpp"

#include "ethernet_interface.hpp"
#include "network_manager.hpp"

#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/elog.hpp>
#include <xyz/openbmc_project/Common/error.hpp>

#include <string>

namespace phosphor
{
namespace network
{

static auto makeObjPath(std::string_view root, stdplus::InAnyAddr addr)
{
    auto ret = sdbusplus::message::object_path(std::string(root));
    stdplus::ToStrHandle<stdplus::ToStr<stdplus::InAnyAddr>> tsh;
    ret /= tsh(addr);
    return ret;
}

Neighbor::Neighbor(sdbusplus::bus_t& bus, std::string_view objRoot,
                   stdplus::PinnedRef<EthernetInterface> parent,
                   stdplus::InAnyAddr addr, stdplus::EtherAddr lladdr,
                   State state) :
    Neighbor(bus, makeObjPath(objRoot, addr), parent, addr, lladdr, state)
{}

Neighbor::Neighbor(sdbusplus::bus_t& bus,
                   sdbusplus::message::object_path objPath,
                   stdplus::PinnedRef<EthernetInterface> parent,
                   stdplus::InAnyAddr addr, stdplus::EtherAddr lladdr,
                   State state) :
    NeighborObj(bus, objPath.str.c_str(), NeighborObj::action::defer_emit),
    parent(parent), objPath(std::move(objPath))
{
    NeighborObj::ipAddress(stdplus::toStr(addr), true);
    NeighborObj::macAddress(stdplus::toStr(lladdr), true);
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

    parent.get().writeConfigurationFile();
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
