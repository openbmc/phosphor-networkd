#pragma once
#include "xyz/openbmc_project/Network/LLDP/TLVs/server.hpp"

#include <sdbusplus/bus.hpp>

namespace phosphor
{
namespace network
{
namespace lldp
{

using TLVsIface = sdbusplus::server::object_t<
    sdbusplus::xyz::openbmc_project::Network::LLDP::server::TLVs>;

class Neighbor : public TLVsIface
{
  public:
    Neighbor() = delete;
    Neighbor(const Neighbor&) = delete;
    Neighbor& operator=(const Neighbor&) = delete;
    Neighbor(Neighbor&&) = delete;
    Neighbor& operator=(Neighbor&&) = delete;
    virtual ~Neighbor() = default;

    Neighbor(sdbusplus::bus_t& bus, const std::string& objPath);

    Neighbor(
        sdbusplus::bus_t& bus, const std::string& objPath,
        const std::string& chassisId,
        TLVsIface::IEEE802IdSubtype chassisIdSubtype, const std::string& portId,
        TLVsIface::IEEE802IdSubtype portIdSubtype,
        const std::string& systemName, const std::string& systemDescription,
        const std::vector<TLVsIface::SystemCapabilities>& systemCapabilities,
        const std::string& managementAddressIPv4,
        const std::string& managementAddressIPv6,
        const std::string& managementAddressMAC, uint16_t managementVlanId);

    using TLVsIface::chassisId;
    using TLVsIface::chassisIdSubtype;
    using TLVsIface::managementAddressIPv4;
    using TLVsIface::managementAddressIPv6;
    using TLVsIface::managementAddressMAC;
    using TLVsIface::managementVlanId;
    using TLVsIface::portId;
    using TLVsIface::portIdSubtype;
    using TLVsIface::systemCapabilities;
    using TLVsIface::systemDescription;
    using TLVsIface::systemName;

    /** @brief Return dbus object path */
    std::string getObjectPath() const
    {
        return objectPath;
    }

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

  private:
    std::string objectPath;
};

} // namespace lldp
} // namespace network
} // namespace phosphor
