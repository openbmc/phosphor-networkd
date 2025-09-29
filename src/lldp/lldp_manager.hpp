#pragma once

#include "lldp_interface.hpp"
#include "lldp_utils.hpp"

#include <sdbusplus/bus.hpp>
#include <sdeventplus/event.hpp>
#include <sdeventplus/utility/timer.hpp>

#include <map>
#include <string>
#include <unordered_map>
#include <vector>

namespace phosphor
{
namespace network
{
namespace lldp
{
class Interface;

using TimerType = sdeventplus::utility::Timer<sdeventplus::ClockId::Monotonic>;

class LLDPManager
{
  public:
    LLDPManager(sdbusplus::bus_t& bus, sdeventplus::Event& event);

    static constexpr std::string_view objPath =
        "/xyz/openbmc_project/network/lldp";

    std::vector<std::string> getInterfaces();
    void reloadLLDPService();
    void loadInterfaceConfigs(const std::string& dirPath);
    bool isLLDPEnabledForInterface(const std::string& ifname) const;
    void handleLLDPEnableChange(const std::string& iface, bool enable);

  protected:
    void createIntfDbusObjects();

    sdbusplus::bus_t& bus;
    sdeventplus::Event& event;
    std::unique_ptr<TimerType> createIntfTimer;

    std::unordered_map<std::string, std::unique_ptr<Interface>> ifaces;
    phosphor::lldp_utils::ConfigList configs;
};

} // namespace lldp
} // namespace network
} // namespace phosphor
