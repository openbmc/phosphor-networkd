#include "config.h"

#include "ipaddress.hpp"

#include "ethernet_interface.hpp"
#include "util.hpp"

#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/log.hpp>
#include <xyz/openbmc_project/Common/error.hpp>

namespace phosphor
{
namespace network
{

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

} // namespace network
} // namespace phosphor
