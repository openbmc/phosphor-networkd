#include "config.h"

#include "ipaddress.hpp"

#include "ethernet_interface.hpp"
#include "netlink.hpp"
#include "util.hpp"

#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/log.hpp>
#include <stdexcept>
#include <stdplus/raw.hpp>
#include <string>
#include <string_view>
#include <vector>
#include <xyz/openbmc_project/Common/error.hpp>

namespace phosphor
{
namespace network
{

std::vector<AddressInfo> getCurrentAddresses(const AddressFilter& filter)
{
    std::vector<AddressInfo> addresses;
    auto cb = [&filter, &addresses](const nlmsghdr& hdr, std::string_view msg) {
        detail::parseAddress(filter, hdr, msg, addresses);
    };
    ifaddrmsg msg{};
    msg.ifa_index = filter.interface;
    netlink::performRequest(NETLINK_ROUTE, RTM_GETADDR, NLM_F_DUMP, msg, cb);
    return addresses;
}

using namespace phosphor::logging;
using namespace sdbusplus::xyz::openbmc_project::Common::Error;

IPAddress::IPAddress(sdbusplus::bus_t& bus, const char* objPath,
                     EthernetInterface& parent, IP::Protocol type,
                     const std::string& ipaddress, IP::AddressOrigin origin,
                     uint8_t prefixLength, const std::string& gateway) :
    IPIfaces(bus, objPath, IPIfaces::action::defer_emit),
    parent(parent)
{

    IP::address(ipaddress);
    IP::prefixLength(prefixLength);
    IP::gateway(gateway);
    IP::type(type);
    IP::origin(origin);

    // Emit deferred signal.
    emit_object_added();
}

void IPAddress::delete_()
{
    if (origin() != IP::AddressOrigin::Static)
    {
        log<level::ERR>("Tried to delete a non-static address"),
            entry("ADDRESS=%s", address().c_str()),
            entry("PREFIX=%" PRIu8, prefixLength()),
            entry("INTERFACE=%s", parent.interfaceName().c_str());
        elog<InternalFailure>();
    }

    parent.deleteObject(address());
}

namespace detail
{

void parseAddress(const AddressFilter& filter, const nlmsghdr& hdr,
                  std::string_view msg, std::vector<AddressInfo>& addresses)
{
    if (hdr.nlmsg_type != RTM_NEWADDR)
    {
        throw std::runtime_error("Not an address msg");
    }
    auto ifaddr = stdplus::raw::extract<ifaddrmsg>(msg);

    // Filter out addresses we don't care about
    unsigned ifindex = ifaddr.ifa_index;
    if (filter.interface != 0 && filter.interface != ifindex)
    {
        return;
    }
    if (filter.scope && *filter.scope != ifaddr.ifa_scope)
    {
        return;
    }

    // Build the info about the address we found
    AddressInfo address;
    address.interface = ifindex;
    address.prefix = ifaddr.ifa_prefixlen;
    address.flags = ifaddr.ifa_flags;
    address.scope = ifaddr.ifa_scope;
    bool set_addr = false;
    while (!msg.empty())
    {
        auto [hdr, data] = netlink::extractRtAttr(msg);
        if (hdr.rta_type == IFA_ADDRESS)
        {
            address.address = addrFromBuf(ifaddr.ifa_family, data);
            set_addr = true;
        }
        else if (hdr.rta_type == IFA_FLAGS)
        {
            address.flags = stdplus::raw::extract<uint32_t>(data);
        }
    }
    if (!set_addr)
    {
        throw std::runtime_error("Missing address");
    }
    addresses.push_back(std::move(address));
}

} // namespace detail
} // namespace network
} // namespace phosphor
