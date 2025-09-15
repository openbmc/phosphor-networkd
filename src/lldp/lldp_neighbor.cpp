#include "lldp_neighbor.hpp"

#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/lg2.hpp>
#include <xyz/openbmc_project/Common/error.hpp>

namespace phosphor
{
namespace network
{
namespace lldp
{

using namespace phosphor::logging;
using namespace sdbusplus::xyz::openbmc_project::Common::Error;
using NotAllowed = sdbusplus::xyz::openbmc_project::Common::Error::NotAllowed;
using Reason = xyz::openbmc_project::Common::NotAllowed::REASON;

Neighbor::Neighbor(sdbusplus::bus_t& bus, const std::string& objPath) :
    Neighbor(bus, objPath, "", TLVsIface::IEEE802IdSubtype::NotTransmitted, "",
             TLVsIface::IEEE802IdSubtype::NotTransmitted, "", "", {}, "", "",
             "", 0)
{}

Neighbor::Neighbor(
    sdbusplus::bus_t& bus, const std::string& objPath,
    const std::string& chassisId, TLVsIface::IEEE802IdSubtype chassisIdSubtype,
    const std::string& portId, TLVsIface::IEEE802IdSubtype portIdSubtype,
    const std::string& systemName, const std::string& systemDescription,
    const std::vector<TLVsIface::SystemCapabilities>& systemCapabilities,
    const std::string& managementAddressIPv4,
    const std::string& managementAddressIPv6,
    const std::string& managementAddressMAC, uint16_t managementVlanId) :
    TLVsIface(bus, objPath.c_str(), TLVsIface::action::defer_emit),
    objectPath(objPath)
{
    TLVsIface::chassisId(chassisId);
    TLVsIface::chassisIdSubtype(chassisIdSubtype);
    TLVsIface::portId(portId);
    TLVsIface::portIdSubtype(portIdSubtype);
    TLVsIface::systemName(systemName);
    TLVsIface::systemDescription(systemDescription);
    TLVsIface::systemCapabilities(systemCapabilities);
    TLVsIface::managementAddressIPv4(managementAddressIPv4);
    TLVsIface::managementAddressIPv6(managementAddressIPv6);
    TLVsIface::managementAddressMAC(managementAddressMAC);
    TLVsIface::managementVlanId(managementVlanId);

    emit_object_added();
}

std::string Neighbor::chassisId(std::string)
{
    elog<NotAllowed>(Reason("Property update is not allowed"));
}

TLVsIface::IEEE802IdSubtype Neighbor::chassisIdSubtype(
    TLVsIface::IEEE802IdSubtype)
{
    elog<NotAllowed>(Reason("Property update is not allowed"));
}

std::string Neighbor::portId(std::string)
{
    elog<NotAllowed>(Reason("Property update is not allowed"));
}

TLVsIface::IEEE802IdSubtype Neighbor::portIdSubtype(TLVsIface::IEEE802IdSubtype)
{
    elog<NotAllowed>(Reason("Property update is not allowed"));
}

std::string Neighbor::systemName(std::string)
{
    elog<NotAllowed>(Reason("Property update is not allowed"));
}

std::string Neighbor::systemDescription(std::string)
{
    elog<NotAllowed>(Reason("Property update is not allowed"));
}

std::vector<TLVsIface::SystemCapabilities> Neighbor::systemCapabilities(
    std::vector<TLVsIface::SystemCapabilities>)
{
    elog<NotAllowed>(Reason("Property update is not allowed"));
}

std::string Neighbor::managementAddressIPv4(std::string)
{
    elog<NotAllowed>(Reason("Property update is not allowed"));
}

std::string Neighbor::managementAddressIPv6(std::string)
{
    elog<NotAllowed>(Reason("Property update is not allowed"));
}

std::string Neighbor::managementAddressMAC(std::string)
{
    elog<NotAllowed>(Reason("Property update is not allowed"));
}

uint16_t Neighbor::managementVlanId(uint16_t)
{
    elog<NotAllowed>(Reason("Property update is not allowed"));
}

} // namespace lldp
} // namespace network
} // namespace phosphor
