#include "hyp_ip_interface.hpp"

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

HypIPAddress::HypIPAddress(sdbusplus::bus::bus& bus, const char* objPath,
                           HypEthInterface& parent, HypIP::Protocol type,
                           const std::string& ipaddress,
                           HypIP::AddressOrigin origin, uint8_t prefixLength,
                           const std::string& gateway,
                           const std::string& intf) :
    HypIPIfaces(bus, objPath, HypIPIfaces::action::defer_emit),
    parent(parent)
{
    HypIP::address(ipaddress);
    HypIP::prefixLength(prefixLength);
    HypIP::gateway(gateway);
    HypIP::type(type);
    HypIP::origin(origin);

    this->objectPath = objPath;
    this->intf = intf;
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
