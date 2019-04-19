#include "config.h"

#include "neighbor.hpp"

#include "ethernet_interface.hpp"
#include "netlink.hpp"
#include "util.hpp"

#include <linux/neighbour.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <cstring>
#include <stdexcept>
#include <string_view>
#include <system_error>
#include <vector>

namespace phosphor
{
namespace network
{
namespace detail
{

void parseNeighbor(const nlmsghdr& hdr, std::string_view msg,
                   std::vector<NeighborInfo>& neighbors)
{
    if (hdr.nlmsg_type != RTM_NEWNEIGH)
    {
        throw std::runtime_error("Not a neighbor msg");
    }
    auto ndm = extract<ndmsg>(msg, "Bad neighbor msg");

    NeighborInfo neighbor;
    neighbor.interface.resize(IF_NAMESIZE);
    if (if_indextoname(ndm.ndm_ifindex, neighbor.interface.data()) == nullptr)
    {
        throw std::system_error(errno, std::generic_category(),
                                "if_indextoname");
    }
    neighbor.interface.resize(strlen(neighbor.interface.c_str()));
    neighbor.permanent = ndm.ndm_state & NUD_PERMANENT;
    bool set_addr = false;
    while (!msg.empty())
    {
        auto [hdr, data] = netlink::extractRtAttr(msg);
        if (hdr.rta_type == NDA_LLADDR)
        {
            neighbor.mac = mac_address::fromBuf(data);
        }
        else if (hdr.rta_type == NDA_DST)
        {
            neighbor.address = addrFromBuf(ndm.ndm_family, data);
            set_addr = true;
        }
    }
    if (!set_addr)
    {
        throw std::runtime_error("Missing address");
    }
    neighbors.push_back(std::move(neighbor));
}

} // namespace detail

std::vector<NeighborInfo> getCurrentNeighbors()
{
    std::vector<NeighborInfo> neighbors;
    auto cb = [&neighbors](const nlmsghdr& hdr, std::string_view msg) {
        detail::parseNeighbor(hdr, msg, neighbors);
    };
    netlink::performRequest(NETLINK_ROUTE, RTM_GETNEIGH, NLM_F_DUMP, ndmsg{},
                            cb);
    return neighbors;
}

Neighbor::Neighbor(sdbusplus::bus::bus& bus, const char* objPath,
                   EthernetInterface& parent, const std::string& ipAddress,
                   const std::string& macAddress, State state) :
    NeighborObj(bus, objPath, true),
    parent(parent)
{
    this->iPAddress(ipAddress);
    this->mACAddress(macAddress);
    this->state(state);

    // Emit deferred signal.
    emit_object_added();
}

void Neighbor::delete_()
{
    parent.deleteStaticNeighborObject(iPAddress());
}

} // namespace network
} // namespace phosphor
