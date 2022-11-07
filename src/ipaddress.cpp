#include "ipaddress.hpp"

#include "ethernet_interface.hpp"
#include "network_manager.hpp"
#include "util.hpp"

#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/log.hpp>
#include <stdexcept>
#include <string>
#include <string_view>
#include <xyz/openbmc_project/Common/error.hpp>

namespace phosphor
{
namespace network
{

using namespace phosphor::logging;
using namespace sdbusplus::xyz::openbmc_project::Common::Error;
using NotAllowed = sdbusplus::xyz::openbmc_project::Common::Error::NotAllowed;
using Reason = xyz::openbmc_project::Common::NotAllowed::REASON;

static auto makeObjPath(std::string_view root, IfAddr addr)
{
    auto ret = sdbusplus::message::object_path(std::string(root));
    ret /= std::to_string(addr);
    return ret;
}

template <typename T>
struct Proto
{
};

template <>
struct Proto<in_addr>
{
    static inline constexpr auto value = IP::Protocol::IPv4;
};

template <>
struct Proto<in6_addr>
{
    static inline constexpr auto value = IP::Protocol::IPv6;
};

IPAddress::IPAddress(sdbusplus::bus_t& bus, std::string_view objRoot,
                     EthernetInterface& parent, IfAddr addr,
                     AddressOrigin origin) :
    IPAddress(bus, makeObjPath(objRoot, addr), parent, addr, origin)
{
}

IPAddress::IPAddress(sdbusplus::bus_t& bus,
                     sdbusplus::message::object_path objPath,
                     EthernetInterface& parent, IfAddr addr,
                     AddressOrigin origin) :
    IPIfaces(bus, objPath.str.c_str(), IPIfaces::action::defer_emit),
    parent(parent), objPath(std::move(objPath))
{
    IP::address(std::to_string(addr.getAddr()));
    IP::prefixLength(addr.getPfx());
    IP::type(std::visit([](auto v) { return Proto<decltype(v)>::value; },
                        addr.getAddr()));
    IP::origin(origin);

    // Emit deferred signal.
    emit_object_added();
}
std::string IPAddress::address(std::string /*ipAddress*/)
{
    elog<NotAllowed>(Reason("Property update is not allowed"));
}
uint8_t IPAddress::prefixLength(uint8_t /*value*/)
{
    elog<NotAllowed>(Reason("Property update is not allowed"));
}
std::string IPAddress::gateway(std::string /*gateway*/)
{
    elog<NotAllowed>(Reason("Property update is not allowed"));
}
IP::Protocol IPAddress::type(IP::Protocol /*type*/)
{
    elog<NotAllowed>(Reason("Property update is not allowed"));
}
IP::AddressOrigin IPAddress::origin(IP::AddressOrigin /*origin*/)
{
    elog<NotAllowed>(Reason("Property update is not allowed"));
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

    std::unique_ptr<IPAddress> ptr;
    for (auto it = parent.addrs.begin(); it != parent.addrs.end(); ++it)
    {
        if (it->second.get() == this)
        {
            ptr = std::move(it->second);
            parent.addrs.erase(it);
            break;
        }
    }

    parent.writeConfigurationFile();
    parent.manager.reloadConfigsNoRefresh();
}

} // namespace network
} // namespace phosphor
