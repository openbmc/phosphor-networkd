#pragma once

#include <sdbusplus/server/object.hpp>
#include <xyz/openbmc_project/Network/LLDP/TLVs/server.hpp>

#include <string>
#include <vector>

namespace phosphor
{
namespace network
{
namespace lldp
{

using TLVsIface = sdbusplus::server::object_t<
    sdbusplus::xyz::openbmc_project::Network::LLDP::server::TLVs>;

class TLVs : public TLVsIface
{
  public:
    TLVs() = delete;
    TLVs(const TLVs&) = delete;
    TLVs& operator=(const TLVs&) = delete;

    TLVs(sdbusplus::bus_t& bus, const std::string& objPath);
    ~TLVs() = default;

    void setChassisId(const std::string& v);
    void setPortId(const std::string& v);
    void setSystemName(const std::string& v);
    void setSystemDescription(const std::string& v);
    void setManagementAddressIPv4(const std::string& v);
    void setManagementAddressIPv6(const std::string& v);

    std::string chassisId(std::string) override;
    TLVsIface::IEEE802IdSubtype chassisIdSubtype(
        TLVsIface::IEEE802IdSubtype) override;
    std::string portId(std::string) override;
    TLVsIface::IEEE802IdSubtype portIdSubtype(
        TLVsIface::IEEE802IdSubtype) override;
    std::string systemName(std::string) override;
    std::string systemDescription(std::string) override;
    std::vector<TLVsIface::SystemCapabilities> systemCapabilities(
        std::vector<TLVsIface::SystemCapabilities>) override;
    std::string managementAddressIPv4(std::string) override;
    std::string managementAddressIPv6(std::string) override;
    std::string managementAddressMAC(std::string) override;
    uint16_t managementVlanId(uint16_t) override;

    void resetToDefaults();
};
} // namespace lldp
} // namespace network
} // namespace phosphor
