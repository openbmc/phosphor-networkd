#include "hyp_ip_interface.hpp"

#include "types.hpp"

#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/elog.hpp>
#include <phosphor-logging/log.hpp>
#include <xyz/openbmc_project/Common/error.hpp>

class HypIPAddress;

namespace phosphor
{
namespace network
{

using namespace phosphor::logging;
using namespace sdbusplus::xyz::openbmc_project::Common::Error;
using NotAllowed = sdbusplus::xyz::openbmc_project::Common::Error::NotAllowed;
using NotAllowedArgument = xyz::openbmc_project::Common::NotAllowed;
using Reason = xyz::openbmc_project::Common::NotAllowed::REASON;
using Argument = xyz::openbmc_project::Common::InvalidArgument;

template <typename T>
struct Proto
{};

template <>
struct Proto<stdplus::In4Addr>
{
    static inline constexpr auto value = HypIP::Protocol::IPv4;
};

template <>
struct Proto<stdplus::In6Addr>
{
    static inline constexpr auto value = HypIP::Protocol::IPv6;
};

HypIPAddress::HypIPAddress(sdbusplus::bus::bus& bus,
                           sdbusplus::message::object_path objPath,
                           stdplus::PinnedRef<HypEthInterface> parent,
                           stdplus::SubnetAny addr, const std::string& gateway,
                           HypIP::AddressOrigin origin,
                           const std::string& intf) :
    HypIPIfaces(bus, objPath.str.c_str(), HypIPIfaces::action::defer_emit),
    intf(std::move(intf)), parent(parent), objectPath(std::move(objPath))
{
    HypIP::address(stdplus::toStr(addr.getAddr()), true);
    HypIP::prefixLength(addr.getPfx(), true);
    HypIP::type(std::visit([](auto v) { return Proto<decltype(v)>::value; },
                           addr.getAddr()),
                true);
    HypIP::origin(origin, true);
    HypIP::gateway(gateway);

    emit_object_added();
}

std::string HypIPAddress::address(std::string /*ipAddress*/)
{
    elog<NotAllowed>(Reason("Property update is not allowed"));
}

uint8_t HypIPAddress::prefixLength(uint8_t /*value*/)
{
    elog<NotAllowed>(Reason("Property update is not allowed"));
}

std::string HypIPAddress::gateway(std::string /*gateway*/)
{
    elog<NotAllowed>(Reason("Property update is not allowed"));
}

HypIP::Protocol HypIPAddress::type(HypIP::Protocol /*type*/)
{
    elog<NotAllowed>(Reason("Property update is not allowed"));
}

HypIP::AddressOrigin HypIPAddress::origin(HypIP::AddressOrigin /*origin*/)
{
    elog<NotAllowed>(Reason("Property update is not allowed"));
}

} // namespace network
} // namespace phosphor
