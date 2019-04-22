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
    std::vector<AddressInfo> info;
    auto cb = [&filter, &info](const nlmsghdr& hdr, std::string_view msg) {
        detail::parseAddress(filter, info, hdr, msg);
    };
    ifaddrmsg msg{};
    msg.ifa_index = filter.interface;
    netlink::performRequest(NETLINK_ROUTE, RTM_GETADDR, NLM_F_DUMP, msg, cb);
    return info;
}

using namespace phosphor::logging;
using namespace sdbusplus::xyz::openbmc_project::Common::Error;

IPAddress::IPAddress(sdbusplus::bus::bus& bus, const char* objPath,
                     EthernetInterface& parent, IP::Protocol type,
                     const std::string& ipaddress, IP::AddressOrigin origin,
                     uint8_t prefixLength, const std::string& gateway) :
    IPIfaces(bus, objPath, true),
    parent(parent)
{
    this->address(ipaddress);
    this->prefixLength(prefixLength);
    this->gateway(gateway);
    this->type(type);
    this->origin(origin);

    // Emit deferred signal.
    emit_object_added();
}

void IPAddress::delete_()
{
    if (IP::AddressOrigin::Static != origin())
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

void parseAddress(const AddressFilter& filter, std::vector<AddressInfo>& ret,
                  const nlmsghdr& hdr, std::string_view msg)
{
    if (hdr.nlmsg_type != RTM_NEWADDR)
    {
        throw std::runtime_error("Not an address msg");
    }
    auto ifaddr = extract<ifaddrmsg>(msg, "Bad address msg");

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
    AddressInfo info;
    info.interface = ifindex;
    info.prefix = ifaddr.ifa_prefixlen;
    info.scope = ifaddr.ifa_scope;
    bool set_addr = false;
    while (!msg.empty())
    {
        auto [hdr, data] = netlink::extractRtAttr(msg);
        if (hdr.rta_type == IFA_ADDRESS)
        {
            info.address = addrFromBuf(ifaddr.ifa_family, data);
            set_addr = true;
        }
    }
    if (!set_addr)
    {
        throw std::runtime_error("Missing address");
    }
    ret.push_back(std::move(info));
}

} // namespace detail
} // namespace network
} // namespace phosphor
