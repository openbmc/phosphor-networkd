#include "lldp_tlvs.hpp"

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

TLVs::TLVs(sdbusplus::bus_t& bus, const std::string& objPath) :
    TLVsIface(bus, objPath.c_str(), TLVsIface::action::defer_emit)
{
    // Set defaults per YAML
    TLVsIface::chassisId("");
    TLVsIface::chassisIdSubtype(TLVsIface::IEEE802IdSubtype::NotTransmitted);
    TLVsIface::portId("");
    TLVsIface::portIdSubtype(TLVsIface::IEEE802IdSubtype::NotTransmitted);
    TLVsIface::systemName("");
    TLVsIface::systemDescription("");
    TLVsIface::systemCapabilities(std::vector<TLVsIface::SystemCapabilities>());
    TLVsIface::managementAddressIPv4("");
    TLVsIface::managementAddressIPv6("");
    TLVsIface::managementAddressMAC("");
    TLVsIface::managementVlanId(0);

    emit_object_added();
}

TLVs::TLVs(
    sdbusplus::bus_t& bus, const std::string& objPath,
    const std::string& chassisIdIn,
    TLVsIface::IEEE802IdSubtype chassisIdSubTypeIn, const std::string& portIdIn,
    TLVsIface::IEEE802IdSubtype portIdSubtypeIn,
    const std::string& systemNameIn, const std::string& systemDescriptionIn,
    std::vector<TLVsIface::SystemCapabilities> systemCapabilitiesIn,
    const std::string& managementAddressIPv4In,
    const std::string& managementAddressIPv6In,
    const std::string& managementAddressMACIn, uint16_t managementVlanIdIn,
    LLDPExchangeType exchangeTypeIn) :
    TLVsIface(bus, objPath.c_str(), TLVsIface::action::defer_emit)
{
    TLVsIface::chassisId(chassisIdIn);
    TLVsIface::chassisIdSubtype(chassisIdSubTypeIn);
    TLVsIface::portId(portIdIn);
    TLVsIface::portIdSubtype(portIdSubtypeIn);
    TLVsIface::systemName(systemNameIn);
    TLVsIface::systemDescription(systemDescriptionIn);
    TLVsIface::systemCapabilities(systemCapabilitiesIn);
    TLVsIface::managementAddressIPv4(managementAddressIPv4In);
    TLVsIface::managementAddressIPv6(managementAddressIPv6In);
    TLVsIface::managementAddressMAC(managementAddressMACIn);
    TLVsIface::managementVlanId(managementVlanIdIn);
    TLVsIface::exchangeType(exchangeTypeIn);

    emit_object_added();
}

void TLVs::resetToDefaults()
{
    TLVsIface::chassisId("");
    TLVsIface::chassisIdSubtype(TLVsIface::IEEE802IdSubtype::NotTransmitted);
    TLVsIface::portId("");
    TLVsIface::portIdSubtype(TLVsIface::IEEE802IdSubtype::NotTransmitted);
    TLVsIface::systemName("");
    TLVsIface::systemDescription("");
    TLVsIface::systemCapabilities(std::vector<TLVsIface::SystemCapabilities>());
    TLVsIface::managementAddressIPv4("");
    TLVsIface::managementAddressIPv6("");
    TLVsIface::managementAddressMAC("");
    TLVsIface::managementVlanId(0);
}

void TLVs::setChassisId(const std::string& v)
{
    TLVsIface::chassisId(v);
}

void TLVs::setChassisIdSubtype(TLVsIface::IEEE802IdSubtype v)
{
    TLVsIface::chassisIdSubtype(v);
}

void TLVs::setPortId(const std::string& v)
{
    TLVsIface::portId(v);
}

void TLVs::setPortIdSubtype(TLVsIface::IEEE802IdSubtype v)
{
    TLVsIface::portIdSubtype(v);
}

void TLVs::setSystemName(const std::string& v)
{
    TLVsIface::systemName(v);
}

void TLVs::setSystemDescription(const std::string& v)
{
    TLVsIface::systemDescription(v);
}

void TLVs::setSystemCapabilities(std::vector<TLVsIface::SystemCapabilities> v)
{
    TLVsIface::systemCapabilities(v);
}

void TLVs::setManagementAddressIPv4(const std::string& v)
{
    TLVsIface::managementAddressIPv4(v);
}

void TLVs::setManagementAddressIPv6(const std::string& v)
{
    TLVsIface::managementAddressIPv6(v);
}

void TLVs::setManagementAddressMAC(const std::string& v)
{
    TLVsIface::managementAddressMAC(v);
}

void TLVs::setManagementVlanId(uint16_t v)
{
    TLVsIface::managementVlanId(v);
}

void TLVs::setExchangeType(TLVsIface::LLDPExchangeType type)
{
    TLVsIface::exchangeType(type);
}

std::string TLVs::chassisId(std::string)
{
    elog<NotAllowed>(Reason("Property update is not allowed"));
}

TLVsIface::IEEE802IdSubtype TLVs::chassisIdSubtype(TLVsIface::IEEE802IdSubtype)
{
    elog<NotAllowed>(Reason("Property update is not allowed"));
}

std::string TLVs::portId(std::string)
{
    elog<NotAllowed>(Reason("Property update is not allowed"));
}

TLVsIface::IEEE802IdSubtype TLVs::portIdSubtype(TLVsIface::IEEE802IdSubtype)
{
    elog<NotAllowed>(Reason("Property update is not allowed"));
}

std::string TLVs::systemName(std::string)
{
    elog<NotAllowed>(Reason("Property update is not allowed"));
}

std::string TLVs::systemDescription(std::string)
{
    elog<NotAllowed>(Reason("Property update is not allowed"));
}

std::vector<TLVsIface::SystemCapabilities> TLVs::systemCapabilities(
    std::vector<TLVsIface::SystemCapabilities>)
{
    elog<NotAllowed>(Reason("Property update is not allowed"));
}

std::string TLVs::managementAddressIPv4(std::string)
{
    elog<NotAllowed>(Reason("Property update is not allowed"));
}

std::string TLVs::managementAddressIPv6(std::string)
{
    elog<NotAllowed>(Reason("Property update is not allowed"));
}

std::string TLVs::managementAddressMAC(std::string)
{
    elog<NotAllowed>(Reason("Property update is not allowed"));
}

uint16_t TLVs::managementVlanId(uint16_t)
{
    elog<NotAllowed>(Reason("Property update is not allowed"));
}

TLVsIface::LLDPExchangeType TLVs::exchangeType(TLVsIface::LLDPExchangeType)
{
    elog<NotAllowed>(Reason("Property update is not allowed"));
}

} // namespace lldp
} // namespace network
} // namespace phosphor
