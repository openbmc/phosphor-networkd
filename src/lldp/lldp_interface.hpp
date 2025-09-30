#pragma once

#include "lldp_tlvs.hpp"

#include <sdbusplus/server/object.hpp>
#include <xyz/openbmc_project/Network/LLDP/Settings/server.hpp>

#include <string>

namespace phosphor
{
namespace network
{
namespace lldp
{

class LLDPManager;

using SettingsIface = sdbusplus::server::object_t<
    sdbusplus::xyz::openbmc_project::Network::LLDP::server::Settings>;

class Interface : public SettingsIface
{
  public:
    Interface() = delete;
    Interface(const Interface&) = delete;
    Interface& operator=(const Interface&) = delete;

    Interface(sdbusplus::bus_t& bus, LLDPManager& manager,
              const std::string& objPath, const std::string& ifname);

    ~Interface() = default;

    bool enableLLDP(bool value) override;
    using SettingsIface::enableLLDP;

  private:
    LLDPManager& manager;
    sdbusplus::bus_t& bus;
    std::string objPath;
    std::string ifname;

    // Pointers to transmit and receive objects
    std::unique_ptr<TLVs> transmit;
    std::unique_ptr<TLVs> receive;

    std::string buildLLDPStatusCommand(bool enable) const;
    void updateInterfaceLLDPConfig(bool enable);

    void updateTransmitObjProperties();
};
} // namespace lldp
} // namespace network
} // namespace phosphor
